import os
import mimetypes
import cloudinary
from cloudinary.utils import cloudinary_url
from django.conf import settings
from django.db.models import Sum
from django.utils import timezone
from payment.models import Payment
from datetime import datetime, time
from rest_framework import serializers
from api.core.utils import validate_file
from payments.models import PaypalPayments
from django.contrib.auth import get_user_model
from drf_spectacular.utils import OpenApiExample
from accounts.models import Profile, Skill, FreelancerProfile
from api.accounts.serializers import ProfileMiniSerializer, SkillSerializer
from core.models import Job, JobCategory, Response, Chat, Message, MessageAttachment, Review, JobBookmark, Notification,ResponseAttachment



User = get_user_model()


class NestedResponseSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()

    class Meta:
        model = Response
        fields = ['user','id', 'submitted_at', 'extra_data', 'cv', 'cover_letter', 'portfolio']

    def get_user(self, obj):
        try:
            profile = obj.user.profile 
            freelancer_profile = profile.freelancer_profile
            return {
                'id': obj.user.id,
                'first_name': obj.user.first_name,
                'last_name': obj.user.last_name,
                'username': obj.user.username,
                'portfolio': freelancer_profile.portfolio_link if freelancer_profile.portfolio_link else None,
                'profile_pic': profile.profile_pic.url if profile.profile_pic else None,
                'email_verified': True if obj.user.is_active else False,
                'date_joined': obj.user.date_joined
            }
        except (Profile.DoesNotExist, FreelancerProfile.DoesNotExist):
            return obj.user.username if obj.user else None


class JobCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = JobCategory
        fields = ['id', 'name']
        extra_kwargs = {
            'name': {'help_text': 'Unique category name (e.g., web_dev, ai_training)'}
        }



class JobSerializer(serializers.ModelSerializer):
    client = serializers.SerializerMethodField()
    selected_freelancer = serializers.SerializerMethodField()
    
    category = serializers.CharField(write_only=True)
    category_display = serializers.SerializerMethodField(read_only=True)
    
    skills_required = serializers.ListField(child=serializers.CharField(),write_only=True)
    skills_required_display = SkillSerializer(many=True, read_only=True, source='skills_required')
    
    client_rating = serializers.SerializerMethodField()
    client_review_count = serializers.SerializerMethodField()
    #client_recent_reviews = serializers.SerializerMethodField()
    
    application_count = serializers.SerializerMethodField(read_only=True)
    bookmarked = serializers.BooleanField(read_only=True)
    has_applied = serializers.BooleanField(read_only=True)


    class Meta:
        model = Job
        fields = [
            'client','id','status','title', 'category', 'category_display', 'description', 'price',
            'posted_date', 'deadline_date',
            'max_freelancers', 'required_freelancers', 'skills_required', 'skills_required_display',
            'preferred_freelancer_level', 'slug',
            'selected_freelancer', 'payment_verified', 'client_rating', 'client_review_count','application_count',
            'bookmarked', 'has_applied',
            
        ]
        read_only_fields = ['posted_date', 'payment_verified','required_freelancers']
        
        
    def validate_skills_required(self, value):
        skill_objs = []
        for name in value:
            name = name.strip().lower()
            skill, created = Skill.objects.get_or_create(name=name)
            skill_objs.append(skill)
        return skill_objs

    def validate_category(self, value):
        value = value.strip().lower()
        category, created = JobCategory.objects.get_or_create(name=value)
        return category

    def create(self, validated_data):
        category = validated_data.pop('category')
        skills = validated_data.pop('skills_required', [])
        job = Job.objects.create(**validated_data, category=category)
        job.skills_required.set(skills)
        return job

    def update(self, instance, validated_data):
        category = validated_data.pop('category', None)
        skills = validated_data.pop('skills_required', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if category:
            instance.category = category
        instance.save()
        if skills is not None:
            instance.skills_required.set(skills)
        return instance
    
    def get_application_count(self, obj):
        if hasattr(obj, "application_count"):
            return obj.application_count
        return obj.responses.count()

    def get_bookmarked(self, obj):
        user = self.context['request'].user
        if not user.is_authenticated:
            return False
        return JobBookmark.objects.filter(user=user, job__slug=obj.slug).exists()

    def get_has_applied(self, obj):
        user = self.context['request'].user
        if not user.is_authenticated:
            return False
        return Response.objects.filter(user=user, job__slug=obj.slug).exists()
    
    def get_category_display(self, obj):
        return obj.category.name if obj.category else None
    
    def get_client_rating(self, obj):
        return round(Review.average_rating_for(obj.client.user), 2)

    def get_client_review_count(self, obj):
        return Review.review_count_for(obj.client.user)

    def get_client_recent_reviews(self, obj):
        recent = Review.recent_reviews_for(obj.client.user, limit=3)
        return ReviewSerializer(recent, many=True).data

    def get_client(self, obj):
        profile = obj.client.user.profile
        user = obj.client.user

        if obj.client:
            # From PaypalPayments (only verified & completed)
            paypal_total = PaypalPayments.objects.filter(
                user=user,
                verified=True,
                status='completed'
            ).aggregate(total=Sum('amount'))['total'] or 0

            # From Payment (only verified)
            payment_total = Payment.objects.filter(
                user=user,
                verified=True
            ).aggregate(total=Sum('amount'))['total'] or 0

            total_paid = round(paypal_total + payment_total, 2)

            hired_count = Job.objects.filter(
                client__user=user,
                selected_freelancer__isnull=False
            ).values('selected_freelancer').distinct().count()

            return {
                'id': user.id,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'username': user.username,
                'location': profile.location,
                'profile_pic': profile.profile_pic.url if profile.profile_pic else None,
                'email_verified': user.is_active,
                'date_joined': user.date_joined,
                'client_rating': round(Review.average_rating_for(user), 2),
                'total_amount_paid': total_paid,
                'total_freelancers_hired': hired_count
            }
        return None
        

    def get_selected_freelancer(self, obj):
        if not obj.selected_freelancer:
            return None
    
        user = obj.selected_freelancer
        rating = round(Review.average_rating_for(user), 2)
        recent_reviews = Review.recent_reviews_for(user)
        return {
            'id': user.id,
            'username': user.username,
            'rating': rating,
            'recent_reviews': ReviewSerializer(recent_reviews, many=True).data
        }
    
    def get_responses(self, obj):
        user = self.context['request'].user
        if not user.is_authenticated:
            return []

        if user == obj.client.user:
            # Client sees all responses
            responses = obj.responses.all()
        else:
            # Freelancer sees only their response
            responses = obj.responses.filter(user=user)

        return NestedResponseSerializer(responses, many=True).data
            

class ApplyResponseSerializer(serializers.ModelSerializer):
    cv_url = serializers.SerializerMethodField(read_only=True)
    cover_letter_url = serializers.SerializerMethodField(read_only=True)
    portfolio_url = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Response
        fields = [
            'extra_data', 'cv', 'cover_letter', 'portfolio',
            'cv_url', 'cover_letter_url', 'portfolio_url'
        ]
        extra_kwargs = {
            'cv': {'required': False, 'allow_null': True},
            'cover_letter': {'required': False, 'allow_null': True},
            'portfolio': {'required': False, 'allow_null': True}
        }

    def get_cv_url(self, obj):
        if obj.cv:
            url, _ = cloudinary_url(obj.cv.public_id, resource_type="raw")
            return url
        return None

    def get_cover_letter_url(self, obj):
        if obj.cover_letter:
            url, _ = cloudinary_url(
                obj.cover_letter.public_id, resource_type="raw")
            return url
        return None

    def get_portfolio_url(self, obj):
        if obj.portfolio:
            # If portfolio is image → deliver as image, else → raw
            resource_type = "image"
            ext = obj.portfolio.public_id.split('.')[-1].lower()
            if ext not in ["jpg", "jpeg", "png"]:
                resource_type = "raw"
            url, _ = cloudinary_url(
                obj.portfolio.public_id, resource_type=resource_type)
            return url
        return None

    def validate_cv(self, value):
        if value is None or value == '':
            return None
        validate_file(value, ['.pdf', '.doc', '.docx'])
        return value

    def validate_cover_letter(self, value):
        if value is None or value == '':
            return None
        validate_file(value, ['.pdf', '.doc', '.docx'])
        return value

    def validate_portfolio(self, value):
        if value is None or value == '':
            return None
        validate_file(value, ['.pdf', '.doc', '.docx',
                      '.jpg', '.jpeg', '.png'])
        return value


class ResponseListSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()
    cv_url = serializers.SerializerMethodField()
    cover_letter_url = serializers.SerializerMethodField()
    portfolio_url = serializers.SerializerMethodField()

    class Meta:
        model = Response
        fields = [
            'user', 'id', 'extra_data', 'submitted_at',
            'cv_url', 'cover_letter_url', 'portfolio_url',
            'slug', 'status', 'marked_for_review'
        ]

    def get_user(self, obj):
        profile = getattr(obj.user, 'profile', None)
        return {
            'username': obj.user.username,
            'first_name': obj.user.first_name,
            'last_name': obj.user.last_name,
            'email': obj.user.email,
            'bio': profile.bio if profile else '',
            'location': profile.location if profile else '',
            'profile_pic': profile.profile_pic.url if profile and profile.profile_pic else None,
        }

    def get_cv_url(self, obj):
        return obj.cv.url if obj.cv else None

    def get_cover_letter_url(self, obj):
        return obj.cover_letter.url if obj.cover_letter else None

    def get_portfolio_url(self, obj):
        return obj.portfolio.url if obj.portfolio else None

    def validate_cv(self, value):
        if value is None or value == '':
            return None
        validate_file(value, ['.pdf', '.doc', '.docx'])
        return value

    def validate_cover_letter(self, value):
        if value is None or value == '':
            return None
        validate_file(value, ['.pdf', '.doc', '.docx'])
        return value

    def validate_portfolio(self, value):
        if value is None or value == '':
            return None
        validate_file(value, ['.pdf', '.doc', '.docx',
                        '.jpg', '.jpeg', '.png'])
        return value


class ResponseReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Response
        fields = ['marked_for_review']
        read_only_fields = [] 

    def update(self, instance, validated_data):
        marked_for_review = validated_data.get(
            'marked_for_review', instance.marked_for_review)
        if marked_for_review:
            instance.mark_for_review()
        else:
            instance.unmark_review()
        return instance
    

class FreelancerBriefSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username']


class JobResponseBriefSerializer(serializers.ModelSerializer):
    user = FreelancerBriefSerializer()

    class Meta:
        model = Response
        fields = ['id', 'user', 'submitted_at']


class JobWithResponsesSerializer(serializers.ModelSerializer):
    responses = JobResponseBriefSerializer(many=True)

    class Meta:
        model = Job
        fields = ['id', 'title', 'description', 'responses']

    
    
class ReviewSerializer(serializers.ModelSerializer):
    reviewer = serializers.SlugRelatedField(
        read_only=True,
        slug_field='username'
    )
    recipient = serializers.SlugRelatedField(
        queryset=User.objects.all(),
        slug_field='username'
    )

    class Meta:
        model = Review
        fields = ['id', 'reviewer', 'recipient', 'rating',
                    'comment', 'created_at', 'updated_at']
        read_only_fields = ['reviewer', 'created_at', 'updated_at']


class JobSearchSerializer(serializers.ModelSerializer):
    client = serializers.SerializerMethodField()
    category = JobCategorySerializer(read_only=True)
    skills_required = serializers.ListField(
        child=serializers.CharField(), write_only=True)
    skills_required_display = SkillSerializer(
        many=True, read_only=True, source='skills_required')
    selected_freelancer = serializers.SerializerMethodField()

    class Meta:
        model = Job
        fields = [
            'client',
            'id', 'title', 'slug', 'category', 'description',
            'price', 'posted_date', 'deadline_date', 'status',
            'selected_freelancer', 'skills_required', 'skills_required_display', 'payment_verified',
            
        ]
        
    def get_client(self, obj):
        client = getattr(obj, 'client', None)
        if not client or not hasattr(client, 'user'):
            return None

        user = client.user
        profile = getattr(user, 'profile', None)
        if not profile:
            return None

        paypal_total = PaypalPayments.objects.filter(
            user=user, verified=True, status='completed'
        ).aggregate(total=Sum('amount'))['total'] or 0

        payment_total = Payment.objects.filter(
            user=user, verified=True
        ).aggregate(total=Sum('amount'))['total'] or 0

        total_paid = round(paypal_total + payment_total, 2)

        hired_count = Job.objects.filter(
            client__user=user, selected_freelancer__isnull=False
        ).values('selected_freelancer').distinct().count()

        return {
            'id': user.id,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'username': user.username,
            'location': profile.location,
            'profile_pic': profile.profile_pic.url if profile.profile_pic else None,
            'email_verified': user.is_active,
            'date_joined': user.date_joined,
            'client_rating': round(Review.average_rating_for(user), 2),
            'total_amount_paid': total_paid,
            'total_freelancers_hired': hired_count
        }
    
    def get_selected_freelancer(self, obj):
        """
        Return the username instead of ID for the selected freelancer.
        """
        if not obj.selected_freelancer:
            return None
        return obj.selected_freelancer.username

    def get_urgency(self, obj):
        if obj.deadline_date:
            return (obj.deadline_date - timezone.now()).days <= 2
        return False

    def get_bookmarked(self, obj):
        bookmarked_ids = self.context.get('bookmarked_ids', set())
        return obj.id in bookmarked_ids

    def get_has_applied(self, obj):
        applied_ids = self.context.get('applied_ids', set())
        return obj.id in applied_ids

    def get_has_applied_and_bookmarked(self, obj):
        bookmarked_ids = self.context.get('bookmarked_ids', set())
        applied_ids = self.context.get('applied_ids', set())
        return obj.id in bookmarked_ids and obj.id in applied_ids


class BookmarkedJobSerializer(serializers.ModelSerializer):
    slug = serializers.CharField(source='job.slug', read_only=True)
    job = JobSearchSerializer(read_only=True)
    has_applied = serializers.SerializerMethodField()
    bookmarked = serializers.SerializerMethodField()

    class Meta:
        model = JobBookmark
        fields = [
            'id',
            'slug',
            'job',
            'created_at',
            'bookmarked',
            'has_applied',
        ]

    def get_bookmarked(self, obj):
        return True

    def get_has_applied(self, obj):
        user = self.context.get('request').user
        if not user.is_authenticated:
            return False
        return obj.job.responses.filter(user=user).exists()


class MessageAttachmentSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField(read_only=True)
    thumbnail_url = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = MessageAttachment
        fields = [
            'id', 'message', 'file', 'filename', 'uploaded_at',
            'file_size', 'content_type', 'thumbnail',
            'file_url', 'thumbnail_url'
        ]
        read_only_fields = [
            'filename', 'uploaded_at', 'file_size', 'content_type',
            'file_url', 'thumbnail_url'
        ]

    def get_file_url(self, obj):
        return obj.file.url if obj.file else None

    def get_thumbnail_url(self, obj):
        if obj.thumbnail:
            return obj.thumbnail.url
        # Fallback: if file is an image, use the file itself as preview
        if obj.content_type and obj.content_type.startswith('image/'):
            return obj.file.url
        return None

    def validate_file(self, value):
        if value is None or value == '':
            return None
        return value

    def validate_thumbnail(self, value):
        if value is None or value == '':
            return None
        return value


class MessageSerializer(serializers.ModelSerializer):
    attachments = MessageAttachmentSerializer(many=True, read_only=True)
    new_attachments = serializers.ListField(
        child=serializers.FileField(
            max_length=100000,
            allow_empty_file=False,
            use_url=False
        ),
        write_only=True,
        required=False
    )
    sender = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = Message
        fields = [
            'id', 'chat', 'sender', 'content', 'is_read',
            'timestamp', 'is_deleted',
            'attachments', 'new_attachments'
        ]
        read_only_fields = ['chat', 'sender', 'is_deleted', 'timestamp']

    def create(self, validated_data):
        attachments_data = validated_data.pop('new_attachments', [])
        message = Message.objects.create(**validated_data)

        for file in attachments_data:
            MessageAttachment.objects.create(
                message=message,
                file=file,
                # Extract filename without path
                filename=file.name.split('/')[-1],
                file_size=file.size if hasattr(file, 'size') else 0,
                content_type=file.content_type if hasattr(
                    file, 'content_type') else 'application/octet-stream'
            )

        return message


class ChatSerializer(serializers.ModelSerializer):
    messages = MessageSerializer(many=True, read_only=True)
    client = serializers.StringRelatedField()
    freelancer = serializers.StringRelatedField()

    class Meta:
        model = Chat
        fields = ['id', 'chat_uuid', 'job', 'client', 'freelancer',
                    'created_at', 'slug', 'active', 'messages']


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'user', 'message', 'created_at', 'is_read', 'chat']
        

class ResponseAttachmentSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = ResponseAttachment
        fields = [
            'id', 'response', 'file', 'filename', 'file_size',
            'content_type', 'uploaded_at', 'file_url'
        ]
        read_only_fields = [
            'filename', 'file_size', 'content_type', 'uploaded_at', 'file_url'
        ]

    def get_file_url(self, obj):
        return obj.file.url if obj.file else None

    def validate_file(self, value):
        if value is None or value == '':
            return None
        return value
