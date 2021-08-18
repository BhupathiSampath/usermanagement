"""
Django settings for user_portal project.

Generated by 'django-admin startproject' using Django 2.2.24.

For more information on this file, see
https://docs.djangoproject.com/en/2.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.2/ref/settings/
"""

import os
from re import DEBUG
from decouple import config
from dotenv import load_dotenv

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv()

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv("SECRET_KEY")
# with open(os.path.join(BASE_DIR, 'secret_key.txt')) as f:
#     SECRET_KEY = f.read().strip()
# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv("DEBUG", bool)
# DEBUG = False

ALLOWED_HOSTS = ['*']
AUTH_USER_MODEL = "users.Account"

# Application definition

INSTALLED_APPS = [
    'users',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'corsheaders'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

X_FRAME_OPTIONS = 'DENY'

ROOT_URLCONF = 'user_portal.urls'

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
            ],
        },
    },
]

WSGI_APPLICATION = 'user_portal.wsgi.application'


# Database
# https://docs.djangoproject.com/en/2.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}



# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators

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


# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/

LANGUAGE_CODE = os.getenv('LANGUAGE_CODE')

TIME_ZONE = os.getenv('TIME_ZONE')

USE_I18N = os.getenv('USE_I18N', bool)

USE_L10N = os.getenv('USE_L10N', bool)

USE_TZ = os.getenv('USE_TZ', bool)


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.2/howto/static-files/

STATIC_URL = '/static/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR,'static')
]
STATIC_ROOT = os.path.join(BASE_DIR,'assets')

# HTTPS Settings
SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', bool)
CSRF_COOKIE_SECURE = os.getenv('CSRF_COOKIE_SECURE', bool)
SECURE_SSL_SECURE = os.getenv('SECURE_SSL_SECURE', bool)

# HSTS Settings

SECURE_HSTS_SECONDS = os.getenv('SECURE_HSTS_SECONDS')
SECURE_HSTS_PRELOAD = os.getenv('SECURE_HSTS_PRELOAD', bool)
SECURE_HSTS_INCLUDE_SUBDOMAINS = os.getenv('SECURE_HSTS_INCLUDE_SUBDOMAINS', bool)

SECURE_CONTENT_TYPE_NOSNIFF = os.getenv('SECURE_CONTENT_TYPE_NOSNIFF', bool)
SECURE_BROWSER_XSS_FILTER = os.getenv('SECURE_BROWSER_XSS_FILTER', bool)
SECURE_SSL_REDIRECT = False

# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_CREDENTIALS = True



REST_FRAMEWORK = {
     'DEFAULT_PERMISSION_CLASSES': [
         'rest_framework.permissions.IsAuthenticated',
         'rest_framework.permissions.IsAdminUser',
         ],
    'DEFAULT_AUTHENTICATION_CLASSES': (
    # 'rest_framework_jwt.authentication.JSONWebTokenAuthentication',
    'users.auth.JSONWebTokenAuthentication',
    # 'rest_framework.authentication.BasicAuthentication',
     )
}

from datetime import timedelta
JWT_AUTH = {
  'JWT_ENCODE_HANDLER':
  'rest_framework_jwt.utils.jwt_encode_handler',
  'JWT_DECODE_HANDLER':
  'rest_framework_jwt.utils.jwt_decode_handler',
  'JWT_PAYLOAD_HANDLER':
  'rest_framework_jwt.utils.jwt_payload_handler',
  'JWT_PAYLOAD_GET_USER_ID_HANDLER':
  'rest_framework_jwt.utils.jwt_get_user_id_from_payload_handler',
  'JWT_RESPONSE_PAYLOAD_HANDLER':
  'rest_framework_jwt.utils.jwt_response_payload_handler',
 
  'JWT_SECRET_KEY': 'SECRET_KEY',
  'JWT_GET_USER_SECRET_KEY': None,
  'JWT_PUBLIC_KEY': None,
  'JWT_PRIVATE_KEY': None,
  'JWT_ALGORITHM': 'HS256',
  'JWT_VERIFY': True,
  'JWT_VERIFY_EXPIRATION': True,
  'JWT_LEEWAY': 0,
  'JWT_EXPIRATION_DELTA': timedelta(days=30),
#   'JWT_EXPIRATION_DELTA': timedelta(minutes=0.5),
  'JWT_AUDIENCE': None,
  'JWT_ISSUER': None,
  'JWT_ALLOW_REFRESH': True,
  'JWT_REFRESH_EXPIRATION_DELTA': timedelta(days=30),
#   'JWT_EXPIRATION_DELTA': timedelta(minutes=0.5),
  'JWT_AUTH_HEADER_PREFIX': '',
  'JWT_AUTH_COOKIE': os.getenv('JWT_AUTH_COOKIE'),
}

