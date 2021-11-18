import logging
from typing import Iterable

logger = logging.getLogger('vk')

STRING_LIKE_TYPES = (str, bytes, bytearray)


try:
    import simplejson as json
except ImportError:
    import json


def json_iter_parse(response_text):
    decoder = json.JSONDecoder(strict=False)
    idx = 0
    while idx < len(response_text):
        obj, idx = decoder.raw_decode(response_text, idx)
        yield obj


def stringify(value):
    if isinstance(value, Iterable) and not isinstance(value, STRING_LIKE_TYPES):
        return ','.join(map(str, value))
    return value


def stringify_values(dictionary):
    return {key: stringify(value) for key, value in dictionary.items()}


# class LoggingSession(requests.Session):
#     def request(self, method, url, **kwargs):
#         logger.debug('Request: %s %s, params=%r, data=%r', method, url, kwargs.get('params'), kwargs.get('data'))
#         response = super(LoggingSession, self).request(method, url, **kwargs)
#         logger.debug('Response: %s %s', response.status_code, response.url)
#         return response


def censor_access_token(access_token):
    if isinstance(access_token, str) and len(access_token) >= 12:
        return '{}***{}'.format(access_token[:4], access_token[-4:])
    elif access_token:
        return '***'
    else:
        return access_token
