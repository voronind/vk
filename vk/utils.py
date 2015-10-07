
import re
import logging
from collections import Iterable

import requests


logger = logging.getLogger('vk')


try:
    # Python 2
    str_type = unicode
except NameError:
    # Python 3
    str_type = str

STRING_TYPES = (str_type, bytes, bytearray)

try:
    # Python 2
    from urllib import urlencode
    from urlparse import urlparse, parse_qsl
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


def stringify_values(dictionary):
    stringified_values_dict = {}
    for key, value in dictionary.items():
        if isinstance(value, Iterable) and not isinstance(value, STRING_TYPES):
            value = u','.join(map(str_type, value))
        stringified_values_dict[key] = value
    return stringified_values_dict


def get_url_query(url):
    parsed_url = urlparse(url)
    url_query = parse_qsl(parsed_url.fragment)
    # login_response_url_query can have multiple key
    url_query = dict(url_query)
    return url_query


def get_form_action(html):
    form_action = re.findall(r'<form(?= ).* action="(.+)"', html)
    if form_action:
        return form_action[0]


class LoggingSession(requests.Session):
    def request(self, method, url, **kwargs):
        logger.debug('Request: %s %s, params=%r, data=%r', method, url, kwargs.get('params'), kwargs.get('data'))
        response = super(LoggingSession, self).request(method, url, **kwargs)
        logger.debug('Response: %s %s', response.status_code, response.url)
        return response
