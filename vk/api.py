# coding=utf8

import re
import time
import warnings

from vk.utils import make_handy

try:
    from urlparse import urlparse, parse_qsl  # Python 2
except ImportError:
    from urllib.parse import urlparse, parse_qsl  # Python 3

try:
    import simplejson as json
except ImportError:
    import json

import requests

# vk.com API Errors
INTERNAL_SERVER_ERROR = 10  # Invalid access token
CAPTCHA_IS_NEEDED = 14


def json_iter_parse(response_text):
    decoder = json.JSONDecoder(strict=False)
    idx = 0
    while idx < len(response_text):
        obj, idx = decoder.raw_decode(response_text, idx)
        yield obj   


class APISession(object):
    def __init__(self, app_id=None, user_login=None, user_password=None, access_token=None, user_email=None,
                 scope='offline', timeout=1, api_version='5.20'):

        user_login = user_login or user_email

        if (not user_login or not user_password) and not access_token:
            raise ValueError('Arguments user_login and user_password, or access_token are required')

        if user_email:  # deprecated at April 11, 2014
            warnings.simplefilter('once')
            warnings.warn("Use 'user_login' instead of deprecated 'user_email'", DeprecationWarning, stacklevel=2)

        self.app_id = app_id

        self.user_login = user_login
        self.user_password = user_password

        self.access_token = access_token
        self.scope = scope or ''
        
        self.api_version = api_version

        self._default_timeout = timeout

        self.session = requests.Session()
        self.session.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        if not access_token and user_login and user_password:
            self.get_access_token()

    def get_access_token(self):

        session = requests.Session()

        # Login
        login_data = {
            'act': 'login',
            'utf8': '1',
            'email': self.user_login,
            'pass': self.user_password,
        }

        response = session.post('https://login.vk.com', login_data)

        if 'remixsid' in session.cookies:
            pass
        elif 'sid=' in response.url:
            raise VkAuthorizationError('Authorization error (captcha)')
        elif 'security_check' in response.url:
            raise VkAuthorizationError('Authorization error (phone number is needed)')
        else:
            raise VkAuthorizationError('Authorization error (bad password)')

        # OAuth2
        oauth_data = {
            'response_type': 'token',
            'client_id': self.app_id,
            'scope': self.scope,
            'display': 'mobile',
        }
        response = session.post('https://oauth.vk.com/authorize', oauth_data)

        if 'access_token' not in response.url:
            form_action = re.findall(u'<form method="post" action="(.+?)">', response.text)
            if form_action:
                response = session.get(form_action[0])
            else:
                try:
                    json_data = response.json()
                except ValueError:  # not json in response
                    error_message = 'OAuth2 grant access error'
                else:
                    error_message = 'VK error: [{0}] {1}'.format(
                        json_data['error'],
                        json_data['error_description']
                    )
                session.close()
                raise VkAuthorizationError(error_message)

        session.close()

        parsed_url = urlparse(response.url)
        token_dict = dict(parse_qsl(parsed_url.fragment))
        if 'access_token' in token_dict:
            self.access_token = token_dict['access_token']
            self.expires_in = token_dict['expires_in']
        else:
            raise VkAuthorizationError('OAuth2 authorization error')

    def __getattr__(self, method_name):
        return APIMethod(self, method_name)

    def __call__(self, method_name, **method_kwargs):
        response = self.method_request(method_name, **method_kwargs)
        response.raise_for_status()

        # there are may be 2 dicts in 1 json
        # for example: {'error': ...}{'response': ...}
        errors = []
        error_codes = []
        for data in json_iter_parse(response.text):
            if 'error' in data:
                error_data = data['error']
                if error_data['error_code'] == CAPTCHA_IS_NEEDED:
                    return self.captcha_is_needed(error_data, method_name, **method_kwargs)

                error_codes.append(error_data['error_code'])
                errors.append(error_data)

            if 'response' in data:
                for error in errors:
                    warnings.warn(str(error))

                # return make_handy(data['response'])
                return data['response']
            
        if INTERNAL_SERVER_ERROR in error_codes:  # invalid access token
            self.get_access_token()
            return self(method_name, **method_kwargs)
        else:
            raise VkAPIMethodError(errors[0])

    def method_request(self, method_name, timeout=None, **method_kwargs):
        if self.access_token:
            params = {
                'access_token': self.access_token,
                'timestamp': int(time.time()),
                'v': self.api_version,
            }
            params.update(method_kwargs)
            url = 'https://api.vk.com/method/' + method_name

        return self.session.post(url, params, timeout=timeout or self._default_timeout)

    def captcha_is_needed(self, error_data, method_name, **method_kwargs):
        """
        Default behavior on CAPTCHA is to raise exception
        Reload this in child
        """
        raise VkAPIMethodError(error_data)


class APIMethod(object):
    __slots__ = ['_api_session', '_method_name']

    def __init__(self, api_session, method_name):
        self._api_session = api_session
        self._method_name = method_name

    def __getattr__(self, method_name):
        return APIMethod(self._api_session, self._method_name + '.' + method_name)

    def __call__(self, **method_kwargs):
        return self._api_session(self._method_name, **method_kwargs)


class VkError(Exception):
    pass


class VkAuthorizationError(VkError):
    pass


class VkAPIMethodError(VkError):
    __slots__ = ['error']

    def __init__(self, error):
        self.error = error
        super(Exception, self).__init__()

    def __str__(self):
        return "{error_code}. {error_msg}. params = {request_params}".format(**self.error)
