# coding=utf8

import time
import random
import warnings

from hashlib import md5

try:
    from urlparse import urlparse, parse_qsl  # Python 2
except ImportError:
    from urllib.parse import urlparse, parse_qsl  # Python 3

try:
    import simplejson as json
except ImportError:
    import json

import requests


def encode_for_signature(obj):
    if isinstance(obj, (dict, list, tuple)):
        obj = json.dumps(obj, ensure_ascii=False)
    return obj


def json_iter_parse(response_text):
    decoder = json.JSONDecoder(strict=False)
    idx = 0
    while idx < len(response_text):
        obj, idx = decoder.raw_decode(response_text, idx)
        yield obj


class APISession(object):
    def __init__(self, app_id, user_email=None, user_password=None, access_token=None, app_secret=None,
                 scope='friends,photos,audio,video,wall', timeout=1):

        if (not user_email or not user_password) and not access_token and not app_secret:
            raise ValueError('Arguments user_email and user_password, or token, or app_secret are required')

        self.app_id = app_id
        self.api_secret = app_secret

        self.user_email = user_email
        self.user_password = user_password

        self.access_token = access_token
        self.scope = scope or ''

        self._timeout = timeout

        self.session = requests.Session()
        self.session.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        if not access_token and user_email and user_password:
            self.get_access_token()

    def get_access_token(self):

        session = requests.Session()

        # Login
        login_data = {
            'act': 'login',
            'utf8': '1',
            'email': self.user_email,
            'pass': self.user_password,
        }
        session.post('https://login.vk.com', login_data)

        if 'remixsid' not in session.cookies:
            raise VkAuthorizationError('Bad password or Captcha or Phone number is needed')

        # OAuth2
        oauth_data = {
            'response_type': 'token',
            'client_id': self.app_id,
            'scope': self.scope,
            'display': 'mobile',
        }
        response = session.post('https://oauth.vk.com/authorize', oauth_data)
        parsed_url = urlparse(response.url)
        token_dict = dict(parse_qsl(parsed_url.fragment))
        if 'access_token' in token_dict:
            self.access_token = token_dict['access_token']
            self.expires_in = token_dict['expires_in']
        else:
            raise VkAuthorizationError('OAuth2 authorization error')

    def __getattr__(self, name):
        return APIMethod(self, name)

    def __call__(self, method, timeout=None, **kwargs):
        response = self._request(method, timeout=timeout, **kwargs)
        response.raise_for_status()

        # there are may be 2 dicts in 1 json
        # for example: {'error': ...}{'response': ...}
        errors = []
        for data in json_iter_parse(response.text):
            if 'error' in data:
                errors.append(data['error'])

            if 'response' in data:
                for error in errors:
                    warnings.warn(str(error))

                return data['response']

        raise VkAPIError(errors[0])

    def _request(self, method, timeout=None, **kwargs):

        if self.access_token:
            params = {
                'access_token': self.access_token,
                'timestamp': int(time.time()),
                }
            params.update(kwargs)
            url = 'https://api.vk.com/method/' + method
        else:
            params = {
                'api_id': str(self.app_id),
                'method': method,
                'format': 'JSON',
                'v': '5.0',
                'random': random.randint(0, 2 ** 30),
                'timestamp': int(time.time()),
            }
            params.update(kwargs)
            params['sig'] = self._signature(params)
            url = 'http://api.vk.com/api.php'

        return self.session.post(url, params, timeout=timeout or self._timeout)

    def _signature(self, params):
        params = {key: encode_for_signature(value) for key, value in params.items()}
        params_str = ''.join('{}={}'.format(key, value) for key, value in sorted(params.items()))
        params_str += self.api_secret
        return md5(params_str.encode('utf8')).hexdigest()


class APIMethod(object):
    __slots__ = ['_api_session', '_name']

    def __init__(self, api_session, name):
        self._api_session = api_session
        self._name = name

    def __getattr__(self, name):
        return APIMethod(self._api_session, self._name + '.' + name)

    def __call__(self, **params):
        return self._api_session(self._name, **params)


class VkError(Exception):
    pass


class VkAuthorizationError(VkError):
    pass


class VkAPIError(VkError):
    __slots__ = ['error']

    def __init__(self, error):
        self.error = error
        super(Exception, self).__init__()

    def __str__(self):
        return "{error_code}. {error_msg}. params = {request_params}".format(**self.error)


API = APISession
