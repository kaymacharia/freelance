from rest_framework import serializers
from django.contrib.auth import get_user_model
from google.oauth2 import id_token
from google.auth.transport import requests
from django.conf import settings
from accounts.models import Profile

User = get_user_model()


class GoogleAuthSerializer(serializers.Serializer):
    id_token = serializers.CharField(write_only=True)
    user_type = serializers.ChoiceField(
        choices=[('freelancer', 'Freelancer'), ('client', 'Client')],
        required=False
    )

    def validate(self, attrs):
        token = attrs.get("id_token")
        user_type = attrs.get("user_type")

        # --- Local testing bypass ---
        if settings.DEBUG and token == "test":
            email = "testuser@example.com"
            name = "Test User"
        else:
            # --- Verify token with Google ---
            try:
                id_info = id_token.verify_oauth2_token(
                    token, requests.Request(), settings.GOOGLE_CLIENT_ID
                )
                email = id_info.get("email")
                name = id_info.get("name", "")
            except Exception:
                raise serializers.ValidationError(
                    {"error": "Invalid or expired Google token."}
                )

        if not email:
            raise serializers.ValidationError(
                {"error": "Google account missing email."})

        # --- Normalize email ---
        email = email.strip().lower()

        # --- Try to find existing user ---
        user = User.objects.filter(email__iexact=email).first()

        if user:
            created = False
        else:
            # --- If user doesn't exist and no user_type provided ---
            if not user_type:
                raise serializers.ValidationError(
                    {"error": "User not found. Please sign up first using Google signup."}
                )

            # --- Otherwise create new user ---
            first_name, *last_name_parts = name.split(" ", 1)
            last_name = last_name_parts[0] if last_name_parts else ""

            user = User.objects.create(
                email=email,
                username=email.split("@")[0],
                first_name=first_name,
                last_name=last_name,
                is_active=True,
            )
            created = True

        # --- Ensure profile exists ---
        profile, _ = Profile.objects.get_or_create(
            user=user,
            defaults={"user_type": user_type or "freelancer"},
        )

        # --- Update user_type if explicitly passed and changed ---
        if user_type and profile.user_type != user_type:
            profile.user_type = user_type
            profile.save(update_fields=["user_type"])

        attrs["user"] = user
        attrs["created"] = created
        return attrs
