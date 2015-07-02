# coding=utf8

import re
import time
import logging
import logging.config
import warnings
from collections import Iterable
from vk.exceptions import VkAuthorizationError, VkAPIMethodError

import requests

from vk.logs import LOGGING_CONFIG
from vk.utils import stringify_values, json_iter_parse


version = '2.0-alpha'


# vk.com API Errors
AUTHORIZATION_FAILED = 5  # Invalid access token
CAPTCHA_IS_NEEDED = 14


logging.config.dictConfig(LOGGING_CONFIG)



class APISession(object):
    # def __init__(self, **kwargs):
    # def __init__(self, app_id=None, user_login=None, user_password=None, access_token=None,
    #              scope='offline', timeout=1, api_version='5.28'):

    def __init__(self, log_level='INFO',
                 access_token=None, scope='offline', timeout=1, api_version='5.28', **kwargs):

        # self.app_id = app_id
        # self.user_login = user_login
        # self.user_password = user_password

        self.scope = scope
        self.api_version = api_version

        self.default_timeout = timeout
        self.access_token = access_token

        # if not access_token and (user_login or user_password):
        #     self.get_access_token()
        # else:
        #     self.access_token = access_token

        super(APISession, self).__init__(**kwargs)

        self.logger = logging.getLogger('vk')
        self.logger.setLevel(log_level)

        self.session = requests.Session()
        self.session.headers['Accept'] = 'application/json'
        self.session.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    def drop_access_token(self):
        self.logger.info('Access token was dropped')
        self.access_token = None

    def check_access_token(self):
        self.logger.info('Check that we have access token')
        if not self.access_token:
            self.logger.info('No access token. Try to get one')
            self.get_access_token()

    def get_access_token(self):
        """
        Overrideable
        """
        self.logger.info('Do nothing for getting access token')
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
            self.logger.info('Authorization failed. Access token will be dropped')
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

        self.logger.info('Make request %s, %s', url, params)
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


from vk.mixins import OAuthMixin

class OAuthAPI(OAuthMixin, APISession):
# class OAuthAPI(APISession, OAuthMixin):
    pass

    # def __init__(self, **kwargs):
    #     super(APISession, self).__init__(kwargs)

