from typing import Iterable

STRING_LIKE_TYPES = (str, bytes, bytearray)


def stringify(value):
    if isinstance(value, Iterable) and not isinstance(value, STRING_LIKE_TYPES):
        return ','.join(map(str, value))
    return value


def stringify_values(dictionary):
    return {key: stringify(value) for key, value in dictionary.items()}


def censor_access_token(access_token):
    if isinstance(access_token, str) and len(access_token) >= 12:
        return '{}***{}'.format(access_token[:4], access_token[-4:])
    return '***'
