from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.db.models.signals import m2m_changed
from django.db.models.signals import post_save,pre_save
from django.dispatch import receiver
from core.models import Job,Chat,Profile,Response,Message
from django.core.exceptions import ValidationError
from wallet.models import WalletTransaction
from decimal import Decimal

@receiver(pre_save, sender=Job)
def cache_old_job_values(sender, instance, **kwargs):
    if instance.pk:
        try:
            old_instance = Job.objects.get(pk=instance.pk)
            instance._old_selected_freelancer = old_instance.selected_freelancer
            instance._old_payment_verified = old_instance.payment_verified
        except Job.DoesNotExist:
            instance._old_selected_freelancer = None
            instance._old_payment_verified = False
    else:
        instance._old_selected_freelancer = None
        instance._old_payment_verified = False


@receiver(post_save, sender=Job)
def update_response_status_on_job_change(sender, instance, **kwargs):
    responses = instance.responses.all()
    for response in responses:
        response.save()


@receiver(m2m_changed, sender=Job.reviewed_responses.through)
def validate_and_update_reviewed_responses(sender, instance, action, pk_set, **kwargs):
    """
    Ensure only Responses linked to this Job are added to reviewed_responses.
    Automatically set status to 'under_review' for valid entries.
    """
    if action == 'pre_add':
        invalid_response_ids = Response.objects.filter(
            pk__in=pk_set).exclude(job=instance).values_list('id', flat=True)
        if invalid_response_ids:
            raise ValidationError(
                f"Responses {list(invalid_response_ids)} do not belong to job '{instance.title}'.")

    if action == 'post_add':
        valid_responses = Response.objects.filter(pk__in=pk_set, job=instance)
        for response in valid_responses:
            if response.status not in ['accepted', 'rejected']:
                response.status = 'under_review'
                response.marked_for_review = True
                response.save()


@receiver(pre_save, sender=Job)
def store_old_job_values(sender, instance, **kwargs):
    """Store old values before saving to detect changes in post_save."""
    if instance.pk:
        try:
            old_instance = Job.objects.get(pk=instance.pk)
            instance._old_selected_freelancer = old_instance.selected_freelancer
            instance._old_payment_verified = old_instance.payment_verified
        except Job.DoesNotExist:
            instance._old_selected_freelancer = None
            instance._old_payment_verified = False
    else:
        instance._old_selected_freelancer = None
        instance._old_payment_verified = False


@receiver(post_save, sender=Job)
def manage_chat_on_job_update(sender, instance, created, **kwargs):
    job = instance
    old_freelancer = getattr(job, "_old_selected_freelancer", None)
    old_payment = getattr(job, "_old_payment_verified", False)
    new_freelancer = job.selected_freelancer
    new_payment = job.payment_verified

    # --- If a new freelancer is assigned ---
    if new_freelancer:
        try:
            freelancer_profile = Profile.objects.get(user=new_freelancer)
        except Profile.DoesNotExist:
            return

        # Create or get chat
        chat, chat_created = Chat.objects.get_or_create(
            job=job,
            client=job.client,
            freelancer=freelancer_profile,
            defaults={'active': new_payment},
        )

        # Deactivate old freelancer chat if changed
        if old_freelancer and old_freelancer != new_freelancer:
            try:
                old_profile = Profile.objects.get(user=old_freelancer)
                Chat.objects.filter(
                    job=job, freelancer=old_profile).update(active=False)
            except Profile.DoesNotExist:
                pass

        # Activate chat if payment verified
        if new_payment and not chat.active:
            chat.active = True
            chat.save()

        # Create the first chat message automatically
        if not old_freelancer or old_freelancer != new_freelancer:
            send_initial_chat_message(job, job.client, freelancer_profile)

    # --- If freelancer removed, deactivate chats ---
    elif old_freelancer and not new_freelancer:
        try:
            old_profile = Profile.objects.get(user=old_freelancer)
            Chat.objects.filter(
                job=job, freelancer=old_profile).update(active=False)
        except Profile.DoesNotExist:
            pass


def send_initial_chat_message(job, client_profile, freelancer_profile):
    """
    Auto-create a welcome message from the client once a freelancer is accepted.
    """
    chat, _ = Chat.objects.get_or_create(
        job=job,
        client=client_profile,
        freelancer=freelancer_profile,
        defaults={'active': True},
    )

    # Get latest platform fee rate
    latest_tx = WalletTransaction.objects.order_by('-timestamp').first()
    fee_rate = latest_tx.rate if latest_tx else Decimal('10.00')

    gross = job.price or Decimal('0.00')
    fee = (fee_rate / Decimal('100')) * gross
    net_amount = gross - fee

    # Compose a friendly message
    message_text = (
        f"👋 Hi {freelancer_profile.user.first_name or freelancer_profile.user.username},\n\n"
        f"I’m {client_profile.user.first_name or client_profile.user.username}, "
        f"and I’ve just accepted you for the job **'{job.title}'**.\n\n"
        f"Project rate (after platform fee): Kes {net_amount:.2f}\n"
        f"📅 Expected deadline: {job.deadline_date.strftime('%b %d, %Y') if job.deadline_date else 'Not specified'}\n\n"
        f"Welcome aboard! Feel free to ask any questions or share your ideas here — "
        f"we’re excited to get started.\n\n"
        f"— {client_profile.user.first_name or client_profile.user.username}"
    )

    # Save as a message in the chat
    Message.objects.create(
        chat=chat,
        sender=client_profile.user,
        content=message_text
    )
