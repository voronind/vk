
from collections import Iterable


STRING_TYPES = (str, bytes, bytearray)


try:
    # Python 2
    from urlparse import urlparse, parse_qsl
except ImportError:
    # Python 3
    from urllib.parse import urlparse, parse_qsl

try:
    import simplejson as json
except ImportError:
    import json

try:
    # Python 2
    raw_input = raw_input
except NameError:
    # Python 3
    raw_input = input


def json_iter_parse(response_text):
    decoder = json.JSONDecoder(strict=False)
    idx = 0
    while idx < len(response_text):
        obj, idx = decoder.raw_decode(response_text, idx)
        yield obj


def stringify_values(method_kwargs):
    stringified_method_kwargs = {}
    for key, value in method_kwargs.items():
        if not isinstance(value, STRING_TYPES) and isinstance(value, Iterable):
            value = ','.join(map(str, value))
        stringified_method_kwargs[key] = value
    return stringified_method_kwargs

# Useless handy shit
class HandyList(list):

    @property
    def first(self):
        if self:
            return self[0]
        else:
            return None

    def __getitem__(self, item):
        obj = list.__getitem__(self, item)

        if type(obj) == dict:
            return HandyDict(obj)

        return obj


class HandyDict(dict):

    def __getattr__(self, item):
        return self[item]


def make_handy(obj):

    if type(obj) == list:
        return HandyList(obj)

    elif type(obj) == dict:
        return HandyDict(obj)

    return obj
