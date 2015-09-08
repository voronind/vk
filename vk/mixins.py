# coding=utf8

import re
import logging

import requests

from vk.exceptions import VkAuthError
from vk.utils import urlparse, parse_qsl, raw_input, parse_url_query


logger = logging.getLogger('vk')


class AuthMixin(object):
    LOGIN_URL = 'https://m.vk.com'
    REDIRECT_URI = 'https://oauth.vk.com/blank.html'
    AUTHORISE_URI = 'https://oauth.vk.com/authorize'
    CAPTCHA_URI = 'https://m.vk.com/captcha.php'

    def __init__(self, app_id=None, user_login='', user_password='', **kwargs):
        logger.debug('AuthMixin.__init__(app_id=%(app_id)r, user_login=%(user_login)r, user_password=%(user_password)r, **kwargs=%(kwargs)s)',
            dict(app_id=app_id, user_login=user_login, user_password=user_password, kwargs=kwargs))

        super(AuthMixin, self).__init__(**kwargs)

        self.app_id = app_id
        self.user_login = user_login
        self.user_password = user_password

    @property
    def user_login(self):
        if not self._user_login:
            self._user_login = self.get_user_login()
        return self._user_login

    @user_login.setter
    def user_login(self, value):
        self._user_login = value

    def get_user_login(self):
        return self._user_login

    @property
    def user_password(self):
        if not self._user_password:
            self._user_password = self.get_user_password()
        return self._user_password

    @user_password.setter
    def user_password(self, value):
        self._user_password = value

    def get_user_password(self):
        return self._user_password
    
    def get_access_token(self):
        """
        Get access token using app id and user login and password.
        """
        logger.info('AuthMixin.get_access_token()')

        self.auth_session = requests.Session()

        self.login()
        token_dict = self.oauth2_authorization()
        del self.auth_session

        if 'access_token' in token_dict:
            return token_dict['access_token'], token_dict['expires_in']
        else:
            raise VkAuthError('OAuth2 authorization error')

    def get_login_form_action(self):
        logger.debug('GET %s', self.LOGIN_URL)
        login_response = self.auth_session.get(self.LOGIN_URL)
        logger.debug('%s - %s', self.LOGIN_URL, login_response.status_code)

        login_form_action = re.findall(r'<form ?.* action="(.+)"', login_response.text)
        if not login_form_action:
            raise VkAuthError('VK changed login flow')
        return login_form_action[0]

    def get_login_response(self, login_form_action, login_form_data):
        logger.debug('POST %s, data: %s', login_form_action, login_form_data)
        login_response = self.auth_session.post(login_form_action, login_form_data)
        logger.debug('%s - %s', login_form_action, login_response.status_code)
        return login_response

    def login(self):
        """
        Login
        """

        login_form_action = self.get_login_form_action()
        login_form_data = {
            'email': self.user_login,
            'pass': self.user_password,
        }
        login_response = self.get_login_response(login_form_action, login_form_data)

        logger.debug('Cookies %s', self.auth_session.cookies)
        logger.info('Login response url %s', login_response.url)

        login_response_url_query = parse_url_query(login_response.url)

        if 'remixsid' in self.auth_session.cookies or 'remixsid6' in self.auth_session.cookies:
            pass
        elif 'sid' in login_response_url_query:
            self.auth_captcha_is_needed(login_response, login_form_data)
        elif login_response_url_query.get('act') == 'authcheck':
            self.auth_code_is_needed(login_response.text)
        elif 'security_check' in login_response_url_query:
            self.phone_number_is_needed(login_response.text)
        else:
            raise VkAuthError('Authorization error (incorrect password)')

    def oauth2_authorization(self):
        """
        OAuth2
        """
        auth_session = self.auth_session

        oauth_data = {
            'response_type': 'token',
            'client_id': self.app_id,
            'scope': self.scope,
            'display': 'mobile',
        }
        logger.debug('POST %s data %s', self.AUTHORISE_URI, oauth_data)
        response = auth_session.post(self.AUTHORISE_URI, oauth_data)
        logger.debug('%s - %s', self.AUTHORISE_URI, response.status_code)
        logger.info('OAuth URL: %s %s', response.request.url, oauth_data)

        if 'access_token' not in response.url:
            logger.info('Geting permissions')
            form_action = re.findall(r'<form method="post" action="(.+?)">', response.text)
            logger.debug('form_action %s', form_action)
            if form_action:
                response = auth_session.get(form_action[0])
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
                auth_session.close()
                raise VkAuthError(error_message)
            logger.info('Permissions obtained')

        auth_session.close()

        parsed_url = urlparse(response.url)
        logger.debug('Parsed URL: %s', parsed_url)

        token_dict = dict(parse_qsl(parsed_url.fragment))
        return token_dict

    def auth_code_is_needed(self, text, session):
        logger.info('You use 2 factors authorization. Enter auth code please')
        auth_hash = re.findall(r'action="/login\?act=authcheck_code&hash=([0-9a-z_]+)"', text)
        logger.debug('auth_hash %s', auth_hash)
        if not auth_hash:
            raise VkAuthError('Cannot find hash, maybe vk.com changed login flow')

        auth_hash = auth_hash[0][1]
        logger.debug('hash %s', auth_hash)
        code_data = {
            'code': self.get_auth_check_code(),
            '_ajax': '1',
            'remember': '1'
        }
        params = {
            'act': 'authcheck_code',
            'hash': auth_hash,
        }
        # todo Calc login_url from form
        login_url = self.LOGIN_URL
        logger.debug('POST %s %s data %s', login_url, params, code_data)
        response = session.post(login_url, params=params, data=code_data)
        logger.debug('%s - %s', login_url, response.status_code)

    def auth_captcha_is_needed(self, response, login_form_data, session):
        logger.info('Captcha is needed')

        logger.debug('Response url %s', response.url)
        parsed_url = urlparse(response.url)
        response_url_dict = dict(parse_qsl(parsed_url.query))

        logger.debug('response_url_dict %s', response_url_dict)

        form_url = re.findall(r'<form method="post" action="(.+)" novalidate>', response.text)
        logger.debug('form_url %s', form_url)
        if not form_url:
            raise VkAuthError('Cannot find form url')

        captcha_url = '%s?s=%s&sid=%s' % (self.CAPTCHA_URI, response_url_dict['s'], response_url_dict['sid'])
        logger.debug('Captcha url %s', captcha_url)

        login_form_data['captcha_sid'] = response_url_dict['sid']
        login_form_data['captcha_key'] = self.on_captcha_is_needed(captcha_url)

        logger.debug('POST %s data %s', form_url[0], login_form_data)
        response = session.post(form_url[0], login_form_data)
        logger.debug('%s - %s', form_url[0], response.status_code)

        logger.debug('Cookies %s', session.cookies)
        if 'remixsid' not in session.cookies and 'remixsid6' not in session.cookies:
            raise VkAuthError('Authorization error (Bad password or captcha key)')

    def phone_number_is_needed(self, text, auth_session):
        raise VkAuthError('Phone number is needed')


class InteractiveMixin(object):
    def get_user_login(self):
        user_login = raw_input('VK user login: ')
        return user_login.strip()

    def get_user_password(self):
        import getpass
        user_password = getpass.getpass('VK user password: ')
        return user_password

    def get_access_token(self):
        logger.debug('InteractiveMixin.get_access_token()')
        access_token, access_token_expires_in = super(InteractiveMixin, self).get_access_token()
        if not access_token:
            access_token = raw_input('VK API access token: ')
            access_token_expires_in = None
        return access_token, access_token_expires_in

    def on_captcha_is_needed(self, url):
        """
        Read CAPTCHA key from shell
        """
        print('Open captcha url:', url)
        captcha_key = raw_input('Enter captcha key: ')
        return captcha_key

    def get_auth_check_code(self):
        """
        Read Auth code from shell
        """
        auth_check_code = raw_input('Auth check code: ')
        return auth_check_code
