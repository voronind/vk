
import sys


LOGGING_CONFIG = {
    'version': 1,
    'loggers': {
        'vk': {
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
            'format': '%(asctime)s %(name) -14s %(levelname)s: %(message)s',
        },
    },
}
