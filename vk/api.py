# coding=utf8

import time
import logging
import logging.config
import warnings

import requests

from vk.logs import LOGGING_CONFIG
from vk.utils import stringify_values, json_iter_parse
from vk.exceptions import VkAuthorizationError, VkAPIMethodError, CAPTCHA_IS_NEEDED, AUTHORIZATION_FAILED
from vk.mixins import OAuthMixin


logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger('vk')


class APISession(object):

    def __init__(self, access_token=None, scope='offline', default_timeout=10, api_version='5.28'):

        logger.debug('API.__init__(...)')

        self.scope = scope
        self.api_version = api_version

        self.default_timeout = default_timeout
        self.access_token = access_token

        self.session = requests.Session()
        self.session.headers['Accept'] = 'application/json'
        self.session.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    def drop_access_token(self):
        logger.info('Access token was dropped')
        self.access_token = None

    def check_access_token(self):
        logger.debug('Check that we have access token')
        if self.access_token:
            logger.debug('access_token=%r', self.access_token)
        else:
            logger.debug('No access token')
            self.get_access_token()

    def get_access_token(self):
        """
        Overrideable
        """
        logger.debug('Do nothing for getting access token')
        pass

    def __getattr__(self, method_name):
        return APIMethod(self, method_name)

    def __call__(self, method_name, **method_kwargs):

        self.check_access_token()

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

                return data['response']
            
        if AUTHORIZATION_FAILED in error_codes:  # invalid access token
            logger.info('Authorization failed. Access token will be dropped')
            self.drop_access_token()
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
        url = 'https://api.vk.com/method/' + method_name

        logger.info('Make request %s, %s', url, params)
        response = self.session.post(url, params, timeout=timeout or self.default_timeout)
        return response

    def captcha_is_needed(self, error_data, method_name, **method_kwargs):
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
        raise VkAuthorizationError('Authorization error (2-factor code is needed)')
    
    def auth_captcha_is_needed(self, content, session):
        """
        Default behavior on CAPTCHA is to raise exception
        Reload this in child
        """              
        raise VkAuthorizationError('Authorization error (captcha)')
    
    def phone_number_is_needed(self, content, session):
        """
        Default behavior on PHONE NUMBER is to raise exception
        Reload this in child
        """
        raise VkAuthorizationError('Authorization error (phone number is needed)')
    

class APIMethod(object):
    __slots__ = ['_api_session', '_method_name']

    def __init__(self, api_session, method_name):
        self._api_session = api_session
        self._method_name = method_name

    def __getattr__(self, method_name):
        return APIMethod(self._api_session, self._method_name + '.' + method_name)

    def __call__(self, **method_kwargs):
        return self._api_session(self._method_name, **method_kwargs)


class OAuthAPI(OAuthMixin, APISession):
    pass


API = APISession
