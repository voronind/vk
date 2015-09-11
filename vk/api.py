# coding=utf8

import time
import logging
import logging.config
import warnings

import requests

from vk.logs import LOGGING_CONFIG
from vk.utils import stringify_values, json_iter_parse, LoggingSession
from vk.exceptions import VkAuthError, VkAPIMethodError, CAPTCHA_IS_NEEDED, AUTHORIZATION_FAILED
from vk.mixins import AuthMixin, InteractiveMixin


VERSION = '2.0a3'


logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger('vk')


class API(object):
    API_URL = 'https://api.vk.com/method/'

    def __init__(self, access_token=None, scope='offline', default_timeout=10, api_version='5.28'):

        logger.debug('API.__init__(access_token=%(access_token)r, scope=%(scope)r, default_timeout=%(default_timeout)r, api_version=%(api_version)r)',
            dict(access_token=access_token, scope=scope, default_timeout=default_timeout, api_version=api_version))

        self.scope = scope
        self.api_version = api_version

        self.default_timeout = default_timeout
        self.access_token = access_token
        self.access_token_is_needed = False

        # self.requests_session = requests.Session()
        self.requests_session = LoggingSession()
        self.requests_session.headers['Accept'] = 'application/json'
        self.requests_session.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    @property
    def access_token(self):
        logger.debug('Check that we need new access token')
        if self.access_token_is_needed:
            logger.debug('We need new access token. Try to get it.')
            self.access_token, self._access_token_expires_in = self.get_access_token()
            logger.info('Got new access token')
        logger.debug('access_token = %r, expires in %s', self.censored_access_token, self._access_token_expires_in)
        return self._access_token

    @access_token.setter
    def access_token(self, value):
        self._access_token = value
        self._access_token_expires_in = None
        self.access_token_is_needed = not self._access_token

    @property
    def censored_access_token(self):
        if self._access_token:
            return '{}***{}'.format(self._access_token[:4], self._access_token[-4:])

    def get_user_login(self):
        logger.debug('Do nothing to get user login')

    def get_access_token(self):
        """
        Dummy method
        """
        logger.debug('API.get_access_token()')
        return self._access_token, self._access_token_expires_in

    def __getattr__(self, method_name):
        return APIMethod(self, method_name)

    # def __call__new(self, method_name, **method_kwargs):
    #     method = MethodRequest(method_name, method_kwargs)
    #     method_response = self.make_request(method)
    #     return

    def __call__(self, method_name, **method_kwargs):

        # self.check_access_token()
        logger.debug('Prepare API Method request')
        # todo Create MethodObject that keeps params to recall API method more easily

        response = self.method_request(method_name, **method_kwargs)
        response.raise_for_status()

        # there are may be 2 dicts in one JSON
        # for example: {'error': ...}{'response': ...}
        errors = []
        error_codes = []
        for data in json_iter_parse(response.text):
            if 'error' in data:
                error_data = data['error']
                if error_data['error_code'] == CAPTCHA_IS_NEEDED:
                    return self.on_captcha_is_needed(error_data, method_name, **method_kwargs)

                error_codes.append(error_data['error_code'])
                errors.append(error_data)

            if 'response' in data:
                for error in errors:
                    logger.warning(str(error))

                return data['response']
            
        if AUTHORIZATION_FAILED in error_codes:  # invalid access token
            logger.info('Authorization failed. Access token will be dropped')
            self.access_token = None
            return self(method_name, **method_kwargs)
        else:
            raise VkAPIMethodError(errors[0])

    def method_request(self, method_name, timeout=None, **method_kwargs):
        params = {
            'timestamp': int(time.time()),
            'v': self.api_version,
        }
        if self.access_token:
            params['access_token'] = self.access_token

        method_kwargs = stringify_values(method_kwargs)
        params.update(method_kwargs)
        url = self.API_URL + method_name
        response = self.requests_session.post(url, params, timeout=timeout or self.default_timeout)
        return response

    def on_captcha_is_needed(self, error_data, method_name, **method_kwargs):
        """
        Default behavior on CAPTCHA is to raise exception
        Reload this in child
        """
        raise VkAPIMethodError(error_data)
    
    def auth_code_is_needed(self, content, session):
        """
        Default behavior on 2-AUTH CODE is to raise exception
        Reload this in child
        """           
        raise VkAuthError('Authorization error (2-factor code is needed)')
    
    def auth_captcha_is_needed(self, content, session):
        """
        Default behavior on CAPTCHA is to raise exception
        Reload this in child
        """              
        raise VkAuthError('Authorization error (captcha)')
    
    def phone_number_is_needed(self, content, session):
        """
        Default behavior on PHONE NUMBER is to raise exception
        Reload this in child
        """
        logger.error('Authorization error (phone number is needed)')
        raise VkAuthError('Authorization error (phone number is needed)')


class APIMethod(object):
    __slots__ = ['_api_session', '_method_name']

    def __init__(self, api_session, method_name):
        self._api_session = api_session
        self._method_name = method_name

    def __getattr__(self, method_name):
        logger.debug('Create API Method')
        return APIMethod(self._api_session, self._method_name + '.' + method_name)

    def __call__(self, **method_kwargs):
        return self._api_session(self._method_name, **method_kwargs)


class AuthAPI(AuthMixin, API):
    pass


class InteractiveAPI(InteractiveMixin, API):
    pass


class InteractiveAuthAPI(InteractiveMixin, AuthAPI):
    pass
