
import sys


LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'loggers': {
        'vk': {
            'level': 'INFO',
            'handlers': ['vk-stdout'],
            'propagate': False,
            },
        },
    'handlers': {
        'vk-stdout': {
            'class': 'logging.StreamHandler',
            'stream': sys.stdout,
            'formatter': 'vk-verbose',
        },
    },
    'formatters': {
        'vk-verbose': {
            'format': '%(asctime)s %(name) -5s %(module)s:%(lineno)d %(levelname)s: %(message)s',
        },
    },
}

# Test settings
USER_LOGIN = ''         # user email or phone number
USER_PASSWORD = ''      # user password
APP_ID = ''             # aka API/Client ID
