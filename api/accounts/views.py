from .serializers import ClientProfileWriteSerializer, ClientProfileReadSerializer
from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import timedelta, datetime
from rest_framework.exceptions import ValidationError, NotFound,PermissionDenied
from rest_framework.decorators import action
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView
from rest_framework import viewsets, status, permissions,generics,filters,mixins
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken,TokenError
from rest_framework.parsers import MultiPartParser, FormParser,JSONParser
from rest_framework.permissions import AllowAny,IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
from rest_framework_simplejwt.settings import api_settings as jwt_settings

from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiExample, OpenApiParameter, extend_schema_view

from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from django.core.mail import EmailMultiAlternatives
from django.contrib.sites.shortcuts import get_current_site
from django.utils.html import format_html
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.http import FileResponse, Http404
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import password_validation
from django.utils.encoding import force_bytes
from django.shortcuts import get_object_or_404,redirect
from django.conf import settings
from urllib.parse import urlencode

from accounts.models import Profile, FreelancerProfile, ClientProfile, Skill, Language,PortfolioProject
from api.accounts.filters import FreelancerProfileFilter,ClientProfileFilter
from core.models import Job, Response as CoreResponse, Chat, Message, MessageAttachment, Review
from .permissions import IsOwnerOrAdmin,IsClient, IsFreelancer, IsJobOwner,CanReview,IsFreelancerOrAdminOrClientReadOnly,IsClientOrAdminFreelancerReadOnly,IsOwnerOrReadOnly
from .google_auth import GoogleAuthSerializer
from .serializers import (
    UserSerializer, RegisterSerializer, LoginSerializer,LogoutSerializer,AuthUserSerializer,
    PasswordChangeSerializer, PasswordResetRequestSerializer,ResendVerificationSerializer,VerifyEmailSerializer,
    PasswordResetConfirmSerializer, ProfileSerializer, SkillSerializer,FreelancerProfileReadSerializer,
    LanguageSerializer,FreelancerListSerializer,FreelancerProfileWriteSerializer,ProfileWriteSerializer,
    ClientProfileWriteSerializer, ClientProfileReadSerializer,ClientListSerializer,PortfolioProjectReadSerializer,PortfolioProjectSerializer
)

import logging
from datetime import timedelta
#from api.tasks import send_verification_email

logger = logging.getLogger(__name__)

User = get_user_model()



class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]
    
    @extend_schema(
        summary="List all users (admin only)",
        responses={
            200: UserSerializer(many=True),
            403: OpenApiResponse(description="Admin access required.")
        }
    )
    def list(self, request, *args, **kwargs):
        if not request.user.is_staff:
            return Response({"error": "Admin access required."}, status=status.HTTP_403_FORBIDDEN)
        return super().list(request, *args, **kwargs)

    @extend_schema(
        summary="Retrieve a user",
        responses={200: UserSerializer}
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    @extend_schema(
        summary="Update a user",
        request=UserSerializer,
        responses={200: UserSerializer}
    )
    def update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)

    @extend_schema(
        summary="Delete a user",
        responses={204: OpenApiResponse(
            description="User deleted successfully.")}
    )
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary="Register a new user",
        request=RegisterSerializer,
        responses={
            201: OpenApiResponse(description="User created, verification email sent."),
            400: OpenApiResponse(description="Validation error")
        }
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            def build_verify_email_url(uid, token):
                base_url = settings.BACKEND_URL.rstrip("/")
                print(base_url)
                query_params = urlencode({"uid": uid, "token": token})
                return f"{base_url}/auth/verify-email/?{query_params}"

            current_site = build_verify_email_url(uid, token)
            verification_url = f'{current_site}'

            subject = 'Verify Your Email Address'
            message_text = f'Hi {user.username},\n\nPlease click the link to verify your email: {verification_url}'
            message_html = format_html(
                '<div style="font-family: Arial, sans-serif; text-align: center;">'
                f'<h2>Welcome, {user.username}!</h2>'
                '<p>Please click the button below to verify your email address:</p>'
                f'<a href="{verification_url}" style="display: inline-block; background-color: #28a745; color: white; text-decoration: none; padding: 10px 20px; border-radius: 5px; font-size: 16px;">'
                'Verify Email</a><p>If you didn\'t sign up, ignore this email.</p>'
                '</div>'
            )
            email = EmailMultiAlternatives(
                subject, message_text, 'info@nilltechsolutions.com', [user.email])
            email.attach_alternative(message_html, "text/html")
            email.send()

            return Response({"message": "User created, verification email sent. Please check you eamil inbox or spam"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class VerifyEmailView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary="Verify Email (GET)",
        description="Verify user email using token and uid from the email link. Returns JWT tokens on success.",
        parameters=[
            {
                "name": "uid",
                "in": "query",
                "required": True,
                "description": "Base64 encoded user ID from verification link",
                "schema": {"type": "string"}
            },
            {
                "name": "token",
                "in": "query",
                "required": True,
                "description": "Verification token from verification link",
                "schema": {"type": "string"}
            }
        ],
        responses={
            200: OpenApiResponse(description="Email verified successfully"),
            400: OpenApiResponse(description="Invalid or expired token"),
        }
    )    
    def get(self, request):
        serializer = VerifyEmailSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        data = serializer.save()
        redirect_url = f"{settings.FRONTEND_URL}/auth/login"

        
        return redirect(redirect_url)

    @extend_schema(
        summary="Verify Email (POST)",
        description="Verify user email using token and uid in the request body. Returns JWT tokens on success.",
        request=VerifyEmailSerializer,
        responses={
            200: OpenApiResponse(description="Email verified successfully"),
            400: OpenApiResponse(description="Invalid or expired token"),
        },
        examples=[
            OpenApiExample(
                "Verification Example",
                value={
                    "uid": "MTQ",
                    "token": "cuklrq-6aae3489aff22c004276561564bedbe8"
                },
                request_only=True
            )
        ]
    )
    def post(self, request):
        serializer = VerifyEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.save()
        redirect_url = f"{settings.FRONTEND_URL}/auth/login"

        return redirect(redirect_url)


class ResendVerificationView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary="Resend verification email",
        description="Resend the email verification link. Requires the email field.",
        request=ResendVerificationSerializer,
        responses={
            200: OpenApiResponse(description="Verification email resent."),
            400: OpenApiResponse(description="User not found or already verified.")
        }
    )
    def post(self, request):
        serializer = ResendVerificationSerializer(data=request.data)
        if not serializer.is_valid():
            logger.warning(
                "Resend verification failed due to invalid data: %s", serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        logger.info("Resend verification requested for email: %s", email)

        # Look up user
        try:
            user = User.objects.get(email__iexact=email)
            logger.debug("User found for email %s with id %s", email, user.id)
        except User.DoesNotExist:
            logger.warning(
                "Resend verification attempted for non-existent email: %s", email)
            return Response({"error": "No user with this email found."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if already active
        if user.is_active:
            logger.info(
                "Resend verification attempted for already verified user: %s", email)
            return Response({"error": "Account is already verified."}, status=status.HTTP_400_BAD_REQUEST)

        # Create UID and token
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        logger.debug("Generated verification token for user %s", user.id)

        # Build verification URL
        base_url = settings.BACKEND_URL.rstrip("/")
        query_params = urlencode({"uid": uid, "token": token})
        verification_url = f"{base_url}/auth/verify-email/?{query_params}"
        logger.debug("Verification URL generated for user %s: %s",
                     user.id, verification_url)

        # Email content
        subject = "Verify Your Email Address"
        message_text = (
            f"Hi {user.username},\n\n"
            f"Please click the link to verify your email: {verification_url}\n\n"
            "This link will expire in 24 hours."
        )
        message_html = format_html(
            '<div style="font-family: Arial, sans-serif; text-align: center;">'
            f'<h2>Hi {user.username},</h2>'
            '<p>Please click the button below to verify your email address:</p>'
            f'<a href="{verification_url}" style="display: inline-block; background-color: #007bff; '
            'color: white; text-decoration: none; padding: 10px 20px; border-radius: 5px; '
            'font-size: 16px;">Verify Email</a>'
            '<p>This link will expire in 24 hours.</p>'
            '</div>'
        )

        try:
            # Send email
            email_message = EmailMultiAlternatives(
                subject,
                message_text,
                settings.DEFAULT_FROM_EMAIL,
                [user.email]
            )
            email_message.attach_alternative(message_html, "text/html")
            email_message.send()
            logger.info("Verification email resent successfully to %s", email)
        except Exception as e:
            logger.error("Failed to send verification email to %s: %s",
                         email, str(e), exc_info=True)
            return Response({"error": "Failed to send verification email."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": "Verification email resent."}, status=status.HTTP_200_OK)


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary="User Login",
        description="Authenticate user and return JWT tokens. Use `remember_me=true` for 30-day session.",
        request=LoginSerializer,
        responses={
            200: OpenApiResponse(description="Login successful. JWT tokens and user info returned."),
            400: OpenApiResponse(description="Invalid credentials.")
        }
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            remember_me = serializer.validated_data.get('remember_me', False)

            refresh = RefreshToken.for_user(user)

            # Token lifetimes
            if remember_me:
                refresh.set_exp(lifetime=timedelta(days=30))
                access_lifetime = timedelta(days=7)
            else:
                access_lifetime = timedelta(minutes=5)  # default

            refresh.access_token.set_exp(lifetime=access_lifetime)

            access_token = refresh.access_token
            
            # Get user_type from related profile
            user_type = getattr(user.profile, 'user_type', None)
            email_verified = getattr(user, 'is_active',None)

            # Create response
            res = Response({
                "message": "Login successful.",
                "user": AuthUserSerializer(user).data,
                "user_type":user_type,
                "email_verified":email_verified,
                "access": str(access_token),
                "refresh": str(refresh),
                "access_expires": datetime.fromtimestamp(access_token['exp']).isoformat(),
                "refresh_expires": datetime.fromtimestamp(refresh['exp']).isoformat()
            }, status=status.HTTP_200_OK)
            

            # Set cookies 
            res.set_cookie(
                key="access_token",
                value=str(access_token),
                expires=access_token['exp'],
                httponly=True,
                secure=True,
                samesite='Lax'
            )
            res.set_cookie(
                key="refresh_token",
                value=str(refresh),
                expires=refresh['exp'],
                httponly=True,
                secure=True,
                samesite='Lax'
            )

            return res

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="User Logout",
        description="Blacklist the refresh token to log out the user.",
        request=LogoutSerializer,
        responses={
            205: OpenApiResponse(description="Logged out successfully."),
            400: OpenApiResponse(description="Invalid or expired refresh token.")
        }
    )
    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        if serializer.is_valid():
            refresh_token = serializer.validated_data['refresh']
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
                return Response({"message": "Logged out successfully."}, status=status.HTTP_205_RESET_CONTENT)
            except TokenError:
                return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GoogleAuthView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary="Google Sign Up / Login",
        description=(
            "Authenticate a user using a Google ID token. "
            "If the user exists → log in and issue JWT tokens. "
            "If not, and a user_type is provided → create a new user and issue tokens. "
            "Otherwise, return a 400 error prompting signup."
        ),
        request=GoogleAuthSerializer,
        responses={
            200: OpenApiResponse(description="Google login successful."),
            201: OpenApiResponse(description="Google signup successful."),
            400: OpenApiResponse(description="User not found or invalid Google token."),
        }
    )
    def post(self, request):
        serializer = GoogleAuthSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        created = serializer.validated_data["created"]

        # --- Issue JWT tokens ---
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        # --- Build response payload ---
        response_data = {
            "message": "Google signup successful." if created else "Google login successful.",
            "is_new": created,
            "user": AuthUserSerializer(user, context={"request": request}).data,
            'user_type': user.profile.user_type,
            "access": str(access),
            "refresh": str(refresh),
        }

        return Response(
            response_data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK
        )


class PasswordChangeView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Change Password",
        description="Authenticated user can change their password.",
        request=PasswordChangeSerializer,
        responses={
            200: OpenApiResponse(description="Password updated."),
            400: OpenApiResponse(description="Invalid input.")
        }
    )
    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data)
        if serializer.is_valid():
            request.user.set_password(
                serializer.validated_data['new_password1'])
            request.user.save()
            return Response({"message": "Password updated successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary="Request Password Reset",
        description="Sends a password reset email if the email is registered.",
        request=PasswordResetRequestSerializer,
        responses={
            200: OpenApiResponse(description="Password reset email sent."),
            400: OpenApiResponse(description="Invalid email.")
        }
    )
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = User.objects.get(
                    email=serializer.validated_data['email'],
                    is_active=True
                )

                # Create uid + token
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)

                # Build reset URL for frontend
                base_url = settings.FRONTEND_URL.rstrip("/")
                query_params = urlencode({"uid": uid, "token": token})
                reset_url = f"{base_url}/auth/password-reset-confirm/?{query_params}"

                # Email content
                subject = "Reset Your Password"
                message_text = (
                    f"Hi {user.username},\n\n"
                    f"Please click the link to reset your password: {reset_url}"
                )
                message_html = format_html(
                    '<div style="font-family: Arial, sans-serif; text-align: center;">'
                    f'<h2>Hi {user.username},</h2>'
                    '<p>Please click the button below to reset your password:</p>'
                    f'<a href="{reset_url}" style="display: inline-block; background-color: #dc3545; '
                    'color: white; text-decoration: none; padding: 10px 20px; border-radius: 5px; '
                    'font-size: 16px;">Reset Password</a>'
                    '<p>If you didn\'t request this, ignore this email.</p>'
                    '</div>'
                )

                email = EmailMultiAlternatives(
                    subject,
                    message_text,
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email]
                )
                email.attach_alternative(message_html, "text/html")
                email.send()

            except User.DoesNotExist:
                pass  

            return Response({"message": "Password reset email sent."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary="Confirm Password Reset",
        description="Reset password using UID and token from email link.",
        request=PasswordChangeSerializer,
        responses={
            200: OpenApiResponse(description="Password reset successful."),
            400: OpenApiResponse(description="Invalid or expired token.")
        }
    )
    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data)
        if serializer.is_valid():
            uidb64 = serializer.validated_data['uid']
            token = serializer.validated_data['token']

            try:
                uid = force_str(urlsafe_base64_decode(uidb64))
                user = User.objects.get(pk=uid)
            except (TypeError, ValueError, User.DoesNotExist):
                return Response({"error": "Invalid reset link."}, status=status.HTTP_400_BAD_REQUEST)

            # is token is valid
            if not default_token_generator.check_token(user, token):
                return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

            # Re-run password validation 
            serializer.context['user'] = user
            # raises error if invalid
            serializer.validate(serializer.validated_data)

            # Set new password
            user.set_password(serializer.validated_data['new_password1'])
            user.save()

            return Response({"message": "Password reset successful."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

@extend_schema(
    methods=['GET', 'PUT', 'PATCH', 'DELETE'],
    summary="Retrieve or modify the authenticated user's profile",
    description="GET retrieves profile, PUT/PATCH updates, DELETE removes the profile.",
    request={
        "multipart/form-data": {
            "type": "object",
            "properties": {
                "phone": {"type": "string", "description": "User phone number"},
                "location": {"type": "string", "description": "User location"},
                "bio": {"type": "string", "description": "User bio"},
                "profile_pic": {
                    "type": "string",
                    "format": "binary",
                    "description": "Profile picture file"
                },
                "pay_id": {
                    "type": "string",
                    "enum": ["M-Pesa", "Binance"],
                    "description": "Payment method"
                },
                "pay_id_no": {"type": "string", "description": "Payment identifier"},
                "id_card": {"type": "string", "description": "National ID or verification document"},
                "user_type": {
                    "type": "string",
                    "enum": ["freelancer", "client"],
                    "description": "Type of user"
                }
            },
            "required": []
        },
        "application/json": {
            "type": "object",
            "properties": {
                "phone": {"type": "string"},
                "location": {"type": "string"},
                "bio": {"type": "string"},
                "profile_pic": {"type": "string", "format": "base64"},
                "pay_id": {"type": "string", "enum": ["M-Pesa", "Binance"]},
                "pay_id_no": {"type": "string"},
                "id_card": {"type": "string"},
                "user_type": {"type": "string", "enum": ["freelancer", "client"]}
            },
            "required": []
        }
    },
    responses={
        200: OpenApiResponse(description="Profile retrieved or updated successfully"),
        204: OpenApiResponse(description="Profile deleted successfully"),
        400: OpenApiResponse(description="Validation error"),
        403: OpenApiResponse(description="Permission denied")
    },
    examples=[
        OpenApiExample(
            "Sample JSON PUT",
            summary="Example of JSON body for updating profile",
            value={
                "phone": "254712345678",
                "location": "Nairobi, Kenya",
                "bio": "Updated bio",
                "profile_pic": "<base64-string>",
                "pay_id": "M-Pesa",
                "pay_id_no": "12345678",
                "id_card": "876857",
                "user_type": "client"
            },
            request_only=True,
            response_only=False
        ),
        OpenApiExample(
            "Sample multipart/form-data",
            summary="Example of multipart/form-data body",
            value={
                "phone": "254712345678",
                "location": "Nairobi, Kenya",
                "bio": "Updated bio",
                "profile_pic": "<file upload>",
                "pay_id": "M-Pesa",
                "pay_id_no": "12345678",
                "id_card": "876857",
                "user_type": "client"
            },
            request_only=True,
            response_only=False
        )
    ]
)

class ProfileViewSet(viewsets.GenericViewSet):
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Profile.objects.filter(user=self.request.user)

    @action(detail=False, methods=['get', 'put', 'patch', 'delete'], url_path='me')
    def me(self, request):
        profile = request.user.profile

        if request.method == 'GET':
            serializer = self.get_serializer(profile)
            return Response(serializer.data)

        elif request.method in ['PUT', 'PATCH']:
            serializer = self.get_serializer(
                profile, data=request.data, partial=(request.method == 'PATCH'), context={'request': request}
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)

        elif request.method == 'DELETE':
            profile.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)


class SkillViewSet(viewsets.ModelViewSet):
    queryset = Skill.objects.all()
    serializer_class = SkillSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    @extend_schema(summary="List skills", responses=SkillSerializer(many=True))
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @extend_schema(summary="Create a skill", request=SkillSerializer, responses=SkillSerializer)
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    @extend_schema(summary="Retrieve a skill", responses=SkillSerializer)
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    @extend_schema(summary="Update a skill", request=SkillSerializer, responses=SkillSerializer)
    def update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)

    @extend_schema(summary="Delete a skill", responses={204: OpenApiResponse(description="Deleted")})
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class LanguageViewSet(viewsets.ModelViewSet):
    queryset = Language.objects.all()
    serializer_class = LanguageSerializer
    permission_classes = [permissions.IsAdminUser]

    @extend_schema(summary="List languages", responses=LanguageSerializer(many=True))
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @extend_schema(summary="Create a language", request=LanguageSerializer, responses=LanguageSerializer)
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    @extend_schema(summary="Retrieve a language", responses=LanguageSerializer)
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    @extend_schema(summary="Update a language", request=LanguageSerializer, responses=LanguageSerializer)
    def update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)

    @extend_schema(summary="Delete a language", responses={204: OpenApiResponse(description="Deleted")})
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@extend_schema(
    summary="List available freelancers",
    description="Returns a filtered and searchable list of visible freelancer profiles.",
    responses={200: FreelancerListSerializer(many=True)},
)
class ListFreelancersView(generics.ListAPIView):
    queryset = FreelancerProfile.objects.select_related('profile__user').prefetch_related('languages', 'skills')
    serializer_class = FreelancerListSerializer
    permission_classes = [permissions.IsAuthenticated]

    #  Enable search, filtering, and ordering
    filter_backends = [filters.SearchFilter,filters.OrderingFilter, DjangoFilterBackend]
    
    filterset_class = FreelancerProfileFilter

    search_fields = [
        'profile__user__email',
        'profile__location',
        'languages__name',
        'skills__name',
    ]

    ordering_fields = [
        'profile__user__email', 'experience_years', 'profile__location','hourly_rate'
    ]

    filterset_fields = [
        'languages__name',
        'skills__name',
        'profile__location',
        'experience_years', 
        'hourly_rate',                   
        'availability',
        'profile__user__first_name',    
        'profile__user__last_name',
        'is_visible',                   
    ]


@extend_schema(
    summary="List client profiles",
    description="Search and filter client profiles based on company, industry, budget, and other criteria.",
    responses={200: ClientListSerializer(many=True)},
)
class ClientProfileListView(generics.ListAPIView):
    queryset = ClientProfile.objects.select_related(
        'profile__user').prefetch_related('languages')
    serializer_class = ClientListSerializer
    permission_classes = [permissions.AllowAny]

    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = {
        'industry': ['exact', 'in'],
        'languages__name': ['exact', 'in'],
        'preferred_freelancer_level': ['exact', 'in'],
        'project_budget': ['exact', 'gte', 'lte'],
        'is_verified': ['exact'],
        'profile__location': ['exact', 'icontains'],
        'profile__user__email': ['exact', 'icontains'],
    }
    filterset_class = ClientProfileFilter
    search_fields = ['company_name',
                        'profile__user__first_name', 'profile__user__last_name']
    ordering_fields = ['company_name', 'project_budget']


@extend_schema(
    summary="Create, update, retrieve or delete client profile",
    request={
        "application/json": {
            "type": "object",
            "properties": {
                # User fields
                "first_name": {"type": "string"},
                "last_name": {"type": "string"},
                "username":{"type":"string"},
                "email": {"type": "string", "format": "email"},
                "phone": {"type": "string"},
                "location": {"type": "string"},
                "bio": {"type": "string"},
                "pay_id": {"type": "string", "enum": ["M-Pesa", "Binance"]},
                "pay_id_no": {"type": "string"},
                "id_card": {"type": "string"},
                "company_name": {"type": "string"},
                "company_website": {"type": "string"},
                "industry": {"type": "string"},
                "project_budget": {"type": "number"},
                "preferred_freelancer_level": {
                    "type": "string",
                    "enum": ["entry", "intermediate", "expert"]
                },
                "languages": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of language names (e.g. 'english', 'french')"
                }
            },
            "required": ["phone", "company_name"]
        },
        "multipart/form-data": {
            "type": "object",
            "properties": {
                "phone": {"type": "string"},
                "location": {"type": "string"},
                "bio": {"type": "string"},
                "pay_id": {"type": "string", "enum": ["M-Pesa", "Binance"]},
                "pay_id_no": {"type": "string"},
                "id_card": {"type": "string"},
                "profile_picture": {
                    "type": "string",
                    "format": "binary",
                    "description": "Optional profile picture"
                },
                "company_name": {"type": "string"},
                "company_website": {"type": "string"},
                "industry": {"type": "string"},
                "project_budget": {"type": "number"},
                "preferred_freelancer_level": {
                    "type": "string",
                    "enum": ["entry", "intermediate", "expert"]
                },
                "languages": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of language names (e.g. 'english', 'french')"
                }
            },
            "required": ["phone", "company_name"]
        }
    },
    responses={
        201: OpenApiResponse(description="Client profile created successfully."),
        200: OpenApiResponse(description="Client profile retrieved/updated successfully."),
        400: OpenApiResponse(description="Validation error."),
        403: OpenApiResponse(description="Permission denied."),
        204: OpenApiResponse(description="Client profile deleted.")
    }
)

class ClientWriteViewSet(viewsets.ModelViewSet):
    serializer_class = ClientProfileWriteSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    lookup_field = 'slug'

    def get_queryset(self):
        return ClientProfile.objects.filter(profile__user=self.request.user)

    def get_object(self):
        identifier = self.kwargs.get('slug') or 'me'
        if identifier == 'me':
            obj = get_object_or_404(
                ClientProfile, profile__user=self.request.user)
        else:
            obj = get_object_or_404(ClientProfile, slug=identifier)

        if obj.profile.user != self.request.user:
            raise PermissionDenied(
                "You do not have permission to access this profile.")
        return obj

    def get_serializer_class(self):
        if self.action in ['list', 'retrieve']:
            return ClientProfileReadSerializer
        return ClientProfileWriteSerializer

    def create(self, request, *args, **kwargs):
        if ClientProfile.objects.filter(profile__user=request.user).exists():
            return Response({
                "message": "Client profile already exists.",
                "data": None,
                "http_code": status.HTTP_400_BAD_REQUEST
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(
            data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        client = serializer.save()
        read_serializer = ClientProfileReadSerializer(
            client, context={'request': request})
        return Response({
            "message": "Client profile created successfully.",
            "data": read_serializer.data,
            "http_code": status.HTTP_201_CREATED
        }, status=status.HTTP_201_CREATED)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = ClientProfileReadSerializer(
            instance, context={'request': request})
        return Response({
            "message": "Client profile retrieved successfully.",
            "data": serializer.data,
            "http_code": status.HTTP_200_OK
        }, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        partial = request.method == 'PATCH'
        serializer = self.get_serializer(
            instance, data=request.data, partial=partial, context={
                'request': request}
        )
        serializer.is_valid(raise_exception=True)
        client = serializer.save()
        read_serializer = ClientProfileReadSerializer(
            client, context={'request': request})
        return Response({
            "message": "Client profile updated successfully.",
            "data": read_serializer.data,
            "http_code": status.HTTP_200_OK
        }, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response({
            "message": "Client profile deleted successfully.",
            "data": None,
            "http_code": status.HTTP_204_NO_CONTENT
        }, status=status.HTTP_204_NO_CONTENT)

@extend_schema(
    summary="Retrieve public freelancer profile",
    description="Get a visible freelancer profile by username or 'me' if authenticated.",
    responses={200: FreelancerProfileReadSerializer}
)
class FreelancerReadOnlyViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = FreelancerProfileReadSerializer
    permission_classes = [permissions.AllowAny]
    lookup_field = 'username'

    def get_queryset(self):
        return FreelancerProfile.objects.filter(is_visible=True)

    def get_object(self):
        identifier = self.kwargs.get('username')

        if identifier == 'me':
            if not self.request.user.is_authenticated:
                raise PermissionDenied(
                    "Authentication required to access your profile.")
            return get_object_or_404(FreelancerProfile, profile__user=self.request.user)

        user = get_object_or_404(User, username=identifier)
        return get_object_or_404(FreelancerProfile, profile__user=user)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response({
            "message": "Freelancer profile retrieved successfully.",
            "data": serializer.data,
            "http_code": status.HTTP_200_OK
        }, status=status.HTTP_200_OK)
        

@extend_schema(
    summary="Create, update, retrieve or delete freelancer profile",
    request={
        "multipart/form-data": {
            "type": "object",
            "properties": {
                # User fields
                "first_name": {"type": "string"},
                "last_name": {"type": "string"},
                "email": {"type": "string", "format": "email"},

                # Profile fields
                "phone": {"type": "string"},
                "location": {"type": "string"},
                "bio": {"type": "string"},
                "profile_picture": {
                    "type": "string",
                    "format": "binary",
                    "description": "Profile picture"
                },

                # FreelancerProfile fields
                "experience_years": {
                    "type": "integer",
                    "description": "Years of professional experience"
                },
                "hourly_rate": {
                    "type": "number",
                    "format": "float",
                    "description": "Freelancer's hourly rate"
                },
                "availability": {
                    "type": "string",
                    "enum": ["full_time", "part_time", "weekends", "custom", "not_available"],
                    "description": "Current availability"
                },
                "skills": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of skill names"
                },
                "languages": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of language names"
                },
                "is_visible": {
                    "type": "boolean",
                    "description": "Whether profile is publicly visible"
                },
                "portfolio_link": {
                    "type": "string",
                    "format": "uri",
                    "description": "Portfolio URL"
                }
            },
            "required": ["phone", "experience_years", "hourly_rate"]
        }
    },
    responses={
        201: OpenApiResponse(description="Freelancer profile created successfully."),
        200: OpenApiResponse(description="Freelancer profile updated successfully."),
        400: OpenApiResponse(description="Validation error."),
        403: OpenApiResponse(description="Permission denied."),
        204: OpenApiResponse(description="Freelancer profile deleted.")
    }
)


class FreelancerWriteViewSet(viewsets.ModelViewSet):
    serializer_class = FreelancerProfileWriteSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrReadOnly]
    lookup_field = 'slug'

    def get_queryset(self):
        return FreelancerProfile.objects.filter(profile__user=self.request.user)

    def get_object(self):
        identifier = self.kwargs.get(
            'freelance_profile_slug') or self.kwargs.get('slug')
        logger.debug(f"Fetching object with identifier: {identifier}")

        if identifier == 'me':
            obj = get_object_or_404(
                FreelancerProfile, profile__user=self.request.user)
        else:
            obj = get_object_or_404(FreelancerProfile, slug=identifier)

        if obj.profile.user != self.request.user:
            logger.warning(
                f"Permission denied for user {self.request.user} on profile {obj.slug}")
            raise PermissionDenied(
                "You do not have permission to access this profile.")

        return obj

    def create(self, request, *args, **kwargs):
        logger.debug(
            f"Creating freelancer profile for user: {request.user.username}")
        if FreelancerProfile.objects.filter(profile__user=request.user).exists():
            logger.warning(
                f"Profile already exists for user: {request.user.username}")
            return Response({
                "message": "Freelancer profile already exists.",
                "data": None,
                "http_code": status.HTTP_400_BAD_REQUEST
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(
            data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        freelancer = serializer.save()

        read_serializer = FreelancerProfileReadSerializer(freelancer)
        logger.info(
            f"Freelancer profile created for user: {request.user.username}")
        return Response({
            "message": "Freelancer profile created successfully.",
            "data": read_serializer.data,
            "http_code": status.HTTP_201_CREATED
        }, status=status.HTTP_201_CREATED)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = FreelancerProfileReadSerializer(instance)
        logger.debug(f"Retrieved profile: {instance.slug}")
        return Response({
            "message": "Freelancer profile retrieved successfully.",
            "data": serializer.data,
            "http_code": status.HTTP_200_OK
        }, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(
            instance,
            data=request.data,
            context={'request': request},
            partial=(request.method == 'PATCH')
        )
        serializer.is_valid(raise_exception=True)
        freelancer = serializer.save()
        read_serializer = FreelancerProfileReadSerializer(freelancer)
        logger.info(f"Updated profile: {freelancer.slug}")
        return Response({
            "message": "Freelancer profile updated successfully.",
            "data": read_serializer.data,
            "http_code": status.HTTP_200_OK
        }, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        logger.info(f"Deleted profile: {instance.slug}")
        return Response({
            "message": "Freelancer profile deleted successfully.",
            "data": None,
            "http_code": status.HTTP_204_NO_CONTENT
        }, status=status.HTTP_204_NO_CONTENT)
        

@extend_schema(
    tags=["Portfolio Projects"],
    summary="List Portfolio Projects",
    description="Retrieve all portfolio projects belonging to the authenticated user.",
    responses={200: PortfolioProjectSerializer(many=True)},
)
@extend_schema(
    methods=["POST"],
    summary="Create Portfolio Project",
    description="Create a new portfolio project for the authenticated user. The user is automatically set from the authentication context.",
    request=PortfolioProjectSerializer,
    responses={201: PortfolioProjectSerializer},
)
class PortfolioProjectViewSet(viewsets.ModelViewSet):
    serializer_class = PortfolioProjectSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "slug"

    def get_queryset(self):
        return PortfolioProject.objects.filter(user=self.request.user)

    @extend_schema(
        summary="Retrieve Portfolio Project",
        description="Retrieve a specific portfolio project by slug.",
        responses={200: PortfolioProjectSerializer},
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    @extend_schema(
        summary="Update Portfolio Project",
        description="Update a specific portfolio project by slug. Partial updates are supported.",
        request=PortfolioProjectSerializer,
        responses={200: PortfolioProjectSerializer},
    )
    def update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)

    @extend_schema(
        summary="Partial Update Portfolio Project",
        description="Partially update a specific portfolio project by slug.",
        request=PortfolioProjectSerializer,
        responses={200: PortfolioProjectSerializer},
    )
    def partial_update(self, request, *args, **kwargs):
        return super().partial_update(request, *args, **kwargs)

    @extend_schema(
        summary="Delete Portfolio Project",
        description="Delete a specific portfolio project by slug.",
        responses={204: OpenApiResponse(description="No content")},
    )
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)
