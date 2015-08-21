
from collections import Iterable


STRING_TYPES = (str, bytes, bytearray)


try:
    # Python 2
    from urllib import urlencode
    from urlparse import urlparse, parse
except ImportError:
    # Python 3
    from urllib.parse import urlparse, parse_qsl, urlencode


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
