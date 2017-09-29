from tutorial.settings.base import *

# Override base.py settings here
SECRET_KEY = '-apk16j_5ch-wi2nu9#*+vi&00pe)eyoe29!_x0mq@l2-!y3vk'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

try:
    from tutorial.settings.local import *
except:
    pass
