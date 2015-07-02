import logging
import re

import requests
from vk.exceptions import VkAuthorizationError

from vk.utils import urlparse, parse_qsl

try:
    input = raw_input  # Python 2
except NameError:
    pass


class OAuthMixin(object):
    # LOGIN_URL = 'https://login.vk.com'
    # LOGIN_URL = 'https://vk.com/login'
    LOGIN_URL = 'https://login.vk.com/?act=login'
    MOBILE_LOGIN_URL = 'https://m.vk.com'
    REDIRECT_URI = 'https://oauth.vk.com/blank.html'

    def __init__(self, **kwargs):
        self.app_id = kwargs.pop('app_id', None)
        self.user_login = kwargs.pop('user_login', None)
        self.user_password = kwargs.pop('user_password', None)

        super(OAuthMixin, self).__init__()
        self.logger = logging.getLogger('vk')

    def get_access_token(self):
        """
        Get access token using user_login and user_password
        """
        self.logger.info('Try to get access token via OAuth')
        self.logger.info('%s', self.user_login)

        if self.user_login and not self.user_password:
            # Need user password
            pass

        if not self.user_login and self.user_password:
            # Need user login
            pass

        auth_session = requests.Session()

        login_form_response = auth_session.get(self.MOBILE_LOGIN_URL)

        login_form_action = re.findall(r'<form ?.* action="(.+)"', login_form_response.text)
        if not login_form_action:
            raise VkAuthorizationError('vk.com changed login flow')

        # Login
        login_form_data = {
            'email': self.user_login,
            'pass': self.user_password,
        }

        response = auth_session.post(login_form_action[0], login_form_data)

        self.logger.info('Cookies %s', auth_session.cookies)
        self.logger.info('Login response url %s', response.url)

        with open('debug-login.html', 'wb') as debug_html: debug_html.write(response.content)

        if 'remixsid' in auth_session.cookies or 'remixsid6' in auth_session.cookies:
            pass
        elif 'sid=' in response.url:
            self.auth_captcha_is_needed(response.content, auth_session)
        elif 'act=authcheck' in response.url:
            self.auth_code_is_needed(response.content, auth_session)
        elif 'security_check' in response.url:
            self.phone_number_is_needed(response.content, auth_session)
        else:
            raise VkAuthorizationError('Authorization error (bad password)')

        # OAuth2
        oauth_data = {
            'response_type': 'token',
            'client_id': self.app_id,
            'scope': self.scope,
            'display': 'mobile',
        }
        response = auth_session.post('https://oauth.vk.com/authorize', oauth_data)
        self.logger.info('OAuth URL: %s %s', response.request.url, oauth_data)

        if 'access_token' not in response.url:
        # if 'code' not in response.url:
            form_action = re.findall(u'<form method="post" action="(.+?)">', response.text)
            if form_action:
                response = auth_session.get(form_action[0])
            else:
                try:
                    json_data = response.json()
                except ValueError:  # not json in response
                    # self.logger.error('HTML: %s', response.content)
                    with open('debug-oauth.html', 'wb') as debug_html: debug_html.write(response.content)
                    error_message = 'OAuth2 grant access error'
                else:
                    error_message = 'VK error: [{0}] {1}'.format(
                        json_data['error'],
                        json_data['error_description']
                    )
                auth_session.close()
                raise VkAuthorizationError(error_message)

        auth_session.close()

        parsed_url = urlparse(response.url)
        self.logger.info('Parsed URL: %s', parsed_url)

        token_dict = dict(parse_qsl(parsed_url.fragment))
        if 'access_token' in token_dict:
            self.access_token = token_dict['access_token']
            self.access_token_expires_in = token_dict['expires_in']
        else:
            raise VkAuthorizationError('OAuth2 authorization error')


class EnterCaptchaMixin(object):

    def captcha_is_needed(self, error_data, method_name, **method_kwargs):
        captcha_sid = error_data.get('captcha_sid')
        captcha_img = error_data.get('captcha_img')

        print('Captcha URL: {}'.format(captcha_img))
        captcha_key = input('Enter captcha text: ')

        method_kwargs['captcha_sid'] = captcha_sid
        method_kwargs['captcha_key'] = captcha_key
        return self(method_name, **method_kwargs)
    
    def auth_code_is_needed(self, content, session):
        curhash = re.findall("'/al_login\.php'. \{act: 'a_authcheck_sms', hash: '(.+?)'", content)
        code_data = {
            'act': 'a_authcheck_code',
            'hash': curhash[0],
            'code': self.get_auth_code()
        } 
        response = session.post(u"https://vk.com/al_login.php", code_data)
    
        def get_auth_code(self):
            return input("get 2-auth code: ")
