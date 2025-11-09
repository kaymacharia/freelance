

from datetime import timedelta
import os
from dotenv import load_dotenv
from pathlib import Path
from django.contrib.messages import constants as messages
import ssl
import socket
import dj_database_url
from decouple import config
import cloudinary
# from api.spectacular_settings import ENUM_NAME_OVERRIDES

load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-g)!b+mp+adw_fc1r-$fq2gd1os(6-!6e=fbpsd6!j0)7b-kek0'

DEBUG = True #os.getenv('DEBUG', 'False') == 'True'

ALLOWED_HOSTS = [
    'localhost',
    'localhost:3000',
    '127.0.0.1',
    'web-production-b953.up.railway.app',
    'nilltechsolutions.com',
    'freelance-w8gc.onrender.com',
    'www.nilltechsolutions.com',
    'www.freelance-w8gc.onrender.com',
]


FRONTEND_URL = 'http://127.0.0.1:3000' #os.getenv('FRONTEND_URL')
BACKEND_URL = '127.0.0.1:8000' #os.getenv('BACKEND_URL')
DOMAIN = '127.0.0.1:8000'  #os.getenv('DOMAIN')

LOGIN_REDIRECT_URL = "core:index"
LOGOUT_REDIRECT_URL = "core:index1"
LOGIN_URL = '/'

# Application definition

INSTALLED_APPS = [
    "daphne",
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # api
    'api',

    # custom
    'core',
    'accounts',
    'academy',
    'invoicemgmt',
    'payment',
    'payments',
    'wallet',

    # pypi
    'paypal.standard.ipn',
    'channels',
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'drf_spectacular',
    'tz_detect',
    'corsheaders',

    'cloudinary_storage',
    'cloudinary',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'tz_detect.middleware.TimezoneMiddleware',
]


ROOT_URLCONF = 'freelance.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.request',

            ],
        },
    },
]

WSGI_APPLICATION = 'freelance.wsgi.application'
ASGI_APPLICATION = 'freelance.asgi.application'


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / "db.sqlite3",
    }
}

# Use PostgreSQL in productioos.getenv('DATABASE_URL')n (Railway)
DATABASE_URL = os.getenv('DATABASE_URL')
if DATABASE_URL:
    DATABASES['default'] = dj_database_url.config(
        default=DATABASE_URL,
        conn_max_age=600,
        conn_health_checks=True,
    )


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


MESSAGE_TAGS = {
    messages.DEBUG: 'alert-info',
    messages.INFO: 'alert-info',
    messages.SUCCESS: 'alert-success',
    messages.WARNING: 'alert-warning',
    messages.ERROR: 'alert-danger',
}


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Africa/Nairobi'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = 'static/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static')
]
STATIC_ROOT = os.path.join(BASE_DIR, 'assets')

MEDIA_URL = '/media/'
# MEDIA_ROOT = os.path.join(BASE_DIR, 'media/')


STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
DEFAULT_FILE_STORAGE = 'cloudinary_storage.storage.MediaCloudinaryStorage'

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


PAYSTACK_SECRET_KEY = 'sk_test_fe4eb40364e4a71a3b387c7a334861ed7977538f'

PAYSTACK_PUBLIC_KEY = 'pk_test_6255b092a137c0d37a6e9e8168012bf73eaec6d3'


# PayPal configuration

PAYPAL_RECEIVER_EMAIL = "niltestbusiness@business.example.com"
PAYPAL_TEST = True  # when live change to False

PAYPAL_CLIENT_ID = "AVyJLECov8YpYvif_IRguvgjh5vGBspN6Aqhg5mYoDRNhVQITTnnzSryjk8PSubZJ5KqUXp7UqDTAo9Q"
PAYPAL_SECRET = "EEYypYfyXGky0fxaw48xMMARgkfqYfAYP9pBP6-HcCpZO8CGs_YmdqxS3koL4dEilYh9p5s9YPNuxm0g"
PAYPAL_MODE = "sandbox"  # or "live"

PAYPAL_URL = (
    "https://api-m.sandbox.paypal.com"
    if PAYPAL_TEST
    else "https://api-m.paypal.com"
)

PAYPAL_OAUTH_URL = f"{PAYPAL_URL}/v1/oauth2/token"
PAYPAL_ORDERS_URL = f"{PAYPAL_URL}/v2/checkout/orders"
PAYPAL_VERIFY_URL = "https://api.paystack.co/transaction/verify"

'''
REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/1")


if os.environ.get('REDIS_URL'):
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": os.environ.get('REDIS_URL'),
            "OPTIONS": {
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
            }
        }
    }
    # For Celery
    CELERY_BROKER_URL = os.environ.get('REDIS_URL')
    CELERY_RESULT_BACKEND = os.environ.get('REDIS_URL')
else:
    # Local development settings
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": REDIS_URL,
            "OPTIONS": {
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
            }
        }
    }
    # For Celery
    CELERY_BROKER_URL = REDIS_URL
    CELERY_RESULT_BACKEND = REDIS_URL
    CELERY_ACCEPT_CONTENT = ["json"]
    CELERY_TASK_SERIALIZER = "json"
    CELERY_RESULT_SERIALIZER = "json"
    '''


# Email Settings
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.zoho.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_USE_SSL = False
EMAIL_HOST_USER = "info@nilltechsolutions.com"
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', '352LfAv8unud')
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER


CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer"
    }
}

# for attachment files
# DEFAULT_FILE_STORAGE = 'django.core.files.storage.FileSystemStorage'

# for heroku csrf_token
# CSRF Settings
CSRF_TRUSTED_ORIGINS = [
    'http://localhost:8000',
    'http://127.0.0.1:8000',
    'https://www.freelance-w8gc.onrender.com',
    'https://freelance-w8gc.onrender.com',
    "https://www.nilltech-frontend.onrender.com",
    "https://nilltech-frontend.onrender.com",
    'https://www.nilltechsolutions.com',
    'https://nilltechsolutions.com'

]

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_SECRET = os.getenv('GOOGLE_SECRET')

# Secure cookies and redirects
#SECURE_SSL_REDIRECT = not DEBUG
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG

#SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

TZ_DETECT_COUNTRIES = ('CN', 'US', 'IN', 'JP', 'BR',
                    'RU', 'DE', 'FR', 'GB', 'KE',)


REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.UserRateThrottle',
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.ScopedRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'user': '30/minute',
        'anon': '10/minute',
        'search': '10/minute',
    },
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 10,
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}


SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'BLACKLIST_ENABLED': True,
    'AUTH_HEADER_TYPES': ('Bearer',),
}

CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "https://nilltechsolutions.com",
    "https://www.nilltechsolutions.com",
    "https://nilltech-frontend.onrender.com",
    "https://www.nilltech-frontend.onrender.com",
    "https://freelance-w8gc.onrender.com",
    "http://www.freelance-w8gc.onrender.com",
]

CORS_ALLOW_CREDENTIALS = True


CORS_ALLOW_HEADERS = [
    "accept",
    "accept-encoding",
    "authorization",
    "content-type",
    "origin",
    "dnt",
    "user-agent",
    "x-csrftoken",
    "x-requested-with",
]

CSRF_TRUSTED_ORIGINS = [
    "https://nilltechsolutions.com",
    "https://freelance-w8gc.onrender.com",
    "https://nilltech-frontend.onrender.com",
]

SESSION_COOKIE_SAMESITE = "None"
SESSION_COOKIE_SECURE = True

CSRF_COOKIE_SAMESITE = "None"
CSRF_COOKIE_SECURE = True


SPECTACULAR_SETTINGS = {
    'TITLE': 'Freelancer Platform API',
    'DESCRIPTION': 'API for managing and testing freelancer-client platform.',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': True,
    'SECURITY': [
        {
            'BearerAuth': {
                'type': 'http',
                'scheme': 'bearer',
                'bearerFormat': 'JWT',
            }
        }
    ],
    # 'ENUM_NAME_OVERRIDES': ENUM_NAME_OVERRIDES,
}

'''
CLOUDINARY_STORAGE = {
    'CLOUD_NAME': os.getenv('CLOUDINARY_CLOUD_NAME'),
    'API_KEY': os.getenv('CLOUDINARY_API_KEY'),
    'API_SECRET': os.getenv('CLOUDINARY_API_SECRET'),
    'FOLDER': 'freelance',
}

cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET'),
    secure=True
)'''


CLOUDINARY_STORAGE = {
    'CLOUD_NAME': 'dfg91rvuz',
    'API_KEY': '769588735978123',
    'API_SECRET': 'lHmFwTKYGgpWqilcjBRJMpGgj4I',
    'FOLDER': 'freelance',
}

cloudinary.config(
    cloud_name='dfg91rvuz',
    api_key='769588735978123',
    api_secret='lHmFwTKYGgpWqilcjBRJMpGgj4I',
    secure=True
)


CLOUDINARY_FOLDERS = {
    'TRAINING': 'freelance/pdf_documents',
    'PROFILE': 'freelance/profile_pic',
    'RESPONSE_CV': 'freelance/response_attachments/cvs',
    'RESPONSE_COVER_LETTER': 'freelance/response_attachments/cover_letters',
    'RESPONSE_PORTFOLIO': 'freelance/response_attachments/portfolios',
    'RESPONSE_THUMBNAIL': 'freelance/response_attachments/thumbnails',
    'MESSAGE_ATTACHMENT': 'freelance/chat_attachments',
    'MESSAGE_THUMBNAIL': 'freelance/chat_attachments/thumbnails',
    'RESPONSE_ATTACHMENT': 'freelance/response_attachments',
}


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': 'debug.log',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        '': {
            'handlers': ['file', 'console'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}
