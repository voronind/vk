import logging

import requests

from .exceptions import VkAuthError, VkAPIError
from .api import API
from .utils import raw_input, get_url_query, get_form_action, json_iter_parse

logger = logging.getLogger('vk')


class APISession:
    METHOD_COMMON_PARAMS = {'v', 'lang', 'https', 'test_mode'}

    API_URL = 'https://api.vk.com/method/'
    CAPTCHA_URL = 'https://m.vk.com/captcha.php'

    def __new__(cls, *args, **kwargs):
        method_common_params = {key: kwargs.pop(key) for key in tuple(kwargs) if key in cls.METHOD_COMMON_PARAMS}

        session = object.__new__(cls)
        session.__init__(*args, **kwargs)

        return API(session, method_common_params)

    def __init__(self, timeout=10):
        self.access_token = None
        self.timeout = timeout

        self.requests_session = requests.Session()
        self.requests_session.headers['Accept'] = 'application/json'
        self.requests_session.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    def get_access_token(self):
        raise NotImplementedError

    def send(self, request):

        logger.debug('Prepare API Method request')

        method_url = self.API_URL + request.method
        request.method_params['access_token'] = self.access_token
        response = self.requests_session.post(method_url, request.method_params, timeout=self.timeout)

        # todo Replace with something less exceptional
        response.raise_for_status()

        # TODO: there are may be 2 dicts in one JSON
        # for example: "{'error': ...}{'response': ...}"
        for response_or_error in json_iter_parse(response.text):
            request.response = response_or_error

            if 'response' in response_or_error:
                # todo Can we have error and response simultaneously
                # for error in errors:
                #     logger.warning(str(error))
                return response_or_error['response']

            elif 'error' in response_or_error:
                api_error = VkAPIError(request.response['error'])
                request.api_error = api_error
                return self.handle_api_error(request)

    def handle_api_error(self, request):
        logger.error('Handle API error: %s', request.api_error)

        api_error_handler_name = 'on_api_error_' + str(request.api_error.code)
        api_error_handler = getattr(self, api_error_handler_name, self.on_api_error)

        return api_error_handler(request)

    def on_api_error_14(self, request):
        """
        14. Captcha needed
        """
        request.method_params['captcha_key'] = self.get_captcha_key(request)
        request.method_params['captcha_sid'] = request.api_error.captcha_sid

        return self.send(request)

    def on_api_error_15(self, request):
        """
        15. Access denied
            - due to scope
        """
        logger.error('Authorization failed. Access token will be dropped')
        self.access_token = self.get_access_token()
        return self.send(request)

    def on_api_error(self, request):
        logger.error('API error: %s', request.api_error)
        raise request.api_error

    def get_captcha_key(self, request):
        """
        Default behavior on CAPTCHA is to raise exception
        Reload this in child
        """
        # request.api_error.captcha_img
        raise request.api_error


class ServiceAPI(APISession):
    def __init__(self, service_token, **kwargs):
        super().__init__(**kwargs)
        self.access_token = service_token


class CommunityAPI(APISession):
    pass


class UserAPI(APISession):
    LOGIN_URL = 'https://m.vk.com'
    AUTHORIZE_URL = 'https://oauth.vk.com/authorize'

    def __init__(self, user_login='', user_password='', app_id='', scope=0x8ffffff, **kwargs):
        super().__init__(**kwargs)

        self.user_login = user_login
        self.user_password = user_password
        self.app_id = app_id
        self.scope = scope

        self.access_token = self.get_access_token()

    def get_credentials(self):
        return {
            'user_login': self.get_user_login(),
            'user_password': self.get_user_password(),
            'app_id': self.get_app_id(),
            'scope': self.get_scope(),
        }

    def get_access_token(self):
        credentials = self.get_credentials()
        auth_session = requests.Session()
        return self.login(auth_session, credentials['user_login'], credentials['user_password'])

    def get_user_login(self):
        return self.user_login

    def get_user_password(self):
        return self.user_password

    def get_app_id(self):
        return self.app_id

    def get_scope(self):
        return self.scope

    def login(self, auth_session, user_login, user_password):

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
            return self.oauth2_authorization(auth_session)

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

    def oauth2_authorization(self, auth_session):
        """
        OAuth2
        """
        auth_data = {
            'client_id': self.get_app_id(),
            'display': 'mobile',
            'response_type': 'token',
            'scope': self.scope,
            'v': '5.80',
        }
        response = auth_session.post(self.AUTHORIZE_URL, auth_data)
        response_url_query = get_url_query(response.url)
        # raise ZeroDivisionError
        if 'access_token' not in response_url_query:
            # Permissions is needed
            logger.info('Getting permissions')
            form_action = get_form_action(response.text)
            logger.debug('Response form action: %s', form_action)
            response = auth_session.get(form_action)
            response_url_query = get_url_query(response.url)

        if 'access_token' in response_url_query:
            return response_url_query['access_token']

        try:
            result = response.json()
        except ValueError:  # not JSON in response
            raise VkAuthError('OAuth2 grant access error')
        else:
            message = 'VK error: [{}] {}'.format(result['error'], result['error_description'])
            raise VkAuthError(message)


class InteractiveMixin:

    def get_user_login(self):
        user_login = raw_input('VK user login: ')
        return user_login.strip()

    def get_user_password(self):
        import getpass

        user_password = getpass.getpass('VK user password: ')
        return user_password

    def get_access_token(self):
        logger.debug('InteractiveMixin.get_access_token()')
        access_token = super().get_access_token()
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
