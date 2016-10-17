from __future__ import absolute_import

import logging

import requests

from .exceptions import VkAuthError, VkAPIError
from .utils import raw_input, get_url_query, get_form_action, stringify_values, json_iter_parse

logger = logging.getLogger('vk')


class Session(object):
    LOGIN_URL = 'https://m.vk.com'
    AUTHORIZE_URL = 'https://oauth.vk.com/authorize'

    API_URL = 'https://api.vk.com/method/'

    CAPTCHA_URI = 'https://m.vk.com/captcha.php'

    def __init__(self, user_login='', user_password='', app_id='', scope='offline', access_token='', timeout=10,
                 **method_default_args):

        self.user_login = user_login
        self.user_password = user_password
        self.app_id = app_id
        self.scope = scope

        self.access_token = access_token
        self.timeout = timeout
        self.method_default_args = method_default_args

        self.auth_session = requests.Session()
        # self.requests_session = LoggingSession()
        self.requests_session = requests.Session()
        self.requests_session.headers['Accept'] = 'application/json'
        self.requests_session.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    def get_access_token(self):
        self.login()

    def get_user_login(self):
        return self.user_login

    def get_user_password(self):
        return self.user_password

    def get_app_id(self):
        return self.app_id

    def login(self, user_login='', user_password='', app_id='', scope='offline'):
        user_login = user_login or self.get_user_login()
        user_password = user_password or self.get_user_password()
        app_id = app_id or self.app_id
        scope = scope or self.scope

        # self.auth_session = auth_session = LoggingSession()
        # auth_session = LoggingSession()
        auth_session = self.auth_session = requests.Session()

        response = auth_session.get(self.LOGIN_URL)
        login_form_action = get_form_action(response.text)
        if not login_form_action:
            raise VkAuthError('VK changed login flow')

        login_form_data = {
            'email': user_login,
            'pass': user_password,
        }
        response = auth_session.post(login_form_action, login_form_data)
        logger.debug('Cookies: %s', auth_session.cookies)

        if 'remixsid' in auth_session.cookies or 'remixsid6' in auth_session.cookies:
            self.access_token = self.oauth2_authorization()
            return

        response_url_query = get_url_query(response.url)
        if 'sid' in response_url_query:
            self.auth_captcha_is_needed(response, login_form_data)

        elif response_url_query.get('act') == 'authcheck':
            self.auth_check_is_needed(response.text)

        elif 'security_check' in response_url_query:
            self.phone_number_is_needed(response.text)

        else:
            message = 'Authorization error (incorrect password)'
            logger.error(message)
            raise VkAuthError(message)

    def oauth2_authorization(self):
        """
        OAuth2
        """
        auth_data = {
            'client_id': self.get_app_id(),
            'display': 'mobile',
            'response_type': 'token',
            'scope': self.scope,
            'v': '5.28',
        }
        response = self.auth_session.post(self.AUTHORIZE_URL, auth_data)
        response_url_query = get_url_query(response.url)
        # raise ZeroDivisionError
        if 'access_token' not in response_url_query:
            # Permissions is needed
            logger.info('Getting permissions')
            form_action = get_form_action(response.text)
            logger.debug('Response form action: %s', form_action)
            response = self.auth_session.get(form_action)
            response_url_query = get_url_query(response.url)

        if 'access_token' in response_url_query:
            self.auth_session = None
            return response_url_query['access_token']

        try:
            result = response.json()
        except ValueError:  # not JSON in response
            raise VkAuthError('OAuth2 grant access error')
        else:
            message = 'VK error: [{}] {}'.format(result['error'], result['error_description'])
            raise VkAuthError(message)

    def make_request(self, request, captcha_response=None):

        logger.debug('Prepare API Method request')

        response = self.send_api_request(request, captcha_response=captcha_response)
        # todo Replace with something less exceptional
        response.raise_for_status()

        # there are may be 2 dicts in one JSON
        # for example: "{'error': ...}{'response': ...}"
        for response_or_error in json_iter_parse(response.text):
            if 'response' in response_or_error:
                # todo Can we have error and response simultaneously
                # for error in errors:
                #     logger.warning(str(error))

                return response_or_error['response']

            elif 'error' in response_or_error:
                error_data = response_or_error['error']
                error = VkAPIError(error_data)

                if error.is_captcha_needed():
                    captcha_key = self.get_captcha_key(error.captcha_img)
                    if not captcha_key:
                        raise error

                    captcha_response = {
                        'sid': error.captcha_sid,
                        'key': captcha_key,
                    }
                    return self.make_request(request, captcha_response=captcha_response)

                elif error.is_access_token_incorrect():
                    logger.info('Authorization failed. Access token will be dropped')
                    self.access_token = self.get_access_token()
                    return self.make_request(request)

                else:
                    raise error

    def send_api_request(self, request, captcha_response=None):
        assert 'v' in self.method_default_args or 'v' in request._method_args, 'vk.com API version is required'

        url = self.API_URL + request._method_name
        method_args = self.method_default_args.copy()
        method_args.update(stringify_values(request._method_args))
        if self.access_token:
            method_args['access_token'] = self.access_token
        if captcha_response:
            method_args['captcha_sid'] = captcha_response['sid']
            method_args['captcha_key'] = captcha_response['key']
        response = self.requests_session.post(url, method_args, timeout=self.timeout)
        return response

    def get_captcha_key(self, captcha_image_url):
        """
        Default behavior on CAPTCHA is to raise exception
        Reload this in child
        """
        return None

    def auth_code_is_needed(self, content, session):
        """
        Default behavior on 2-AUTH CODE is to raise exception
        Reload this in child
        """
        raise VkAuthError('Authorization error (2-factor code is needed)')

    def auth_check_is_needed(self, html):
        logger.info('User enabled 2 factors authorization. Auth check code is needed')
        auth_check_form_action = get_form_action(html)
        auth_check_code = self.get_auth_check_code()
        auth_check_data = {'code': auth_check_code, '_ajax': '1', 'remember': '1'}
        self.auth_session.post(auth_check_form_action, data=auth_check_data)

    def auth_captcha_is_needed(self, response, login_form_data):
        logger.info('Captcha is needed')

        response_url_dict = get_url_query(response.url)

        # form_url = re.findall(r'<form method="post" action="(.+)" novalidate>', response.text)
        captcha_form_action = get_form_action(response.text)
        logger.debug('form_url %s', captcha_form_action)
        if not captcha_form_action:
            raise VkAuthError('Cannot find form url')

        # todo Are we sure that `response_url_dict` doesn't contain CAPTCHA image url?
        captcha_url = '%s?s=%s&sid=%s' % (self.CAPTCHA_URI, response_url_dict['s'], response_url_dict['sid'])
        # logger.debug('Captcha url %s', captcha_url)

        login_form_data['captcha_sid'] = response_url_dict['sid']
        login_form_data['captcha_key'] = self.get_captcha_key(captcha_url)

        response = self.auth_session.post(captcha_form_action, login_form_data)

    def phone_number_is_needed(self, content, session):
        """
        Default behavior on PHONE NUMBER is to raise exception
        Reload this in child
        """
        logger.error('Authorization error (phone number is needed)')
        raise VkAuthError('Authorization error (phone number is needed)')

    def get_auth_check_code(self):
        raise VkAuthError('Auth check code is needed')


class InteractiveSession(Session):

    def get_user_login(self):
        user_login = raw_input('VK user login: ')
        return user_login.strip()

    def get_user_password(self):
        import getpass

        user_password = getpass.getpass('VK user password: ')
        return user_password

    def get_access_token(self):
        logger.debug('InteractiveMixin.get_access_token()')
        access_token = super(InteractiveSession, self).get_access_token()
        if not access_token:
            access_token = raw_input('VK API access token: ')
        return access_token

    def get_captcha_key(self, captcha_image_url):
        """
        Read CAPTCHA key from shell
        """
        print('Open CAPTCHA image url: ', captcha_image_url)
        captcha_key = raw_input('Enter CAPTCHA key: ')
        return captcha_key

    def get_auth_check_code(self):
        """
        Read Auth code from shell
        """
        auth_check_code = raw_input('Auth check code: ')
        return auth_check_code.strip()
