import getpass
import logging
import urllib
from json import loads
from re import findall

import requests

from .api import APINamespace
from .exceptions import VkAPIError, VkAuthError
from .utils import stringify

logger = logging.getLogger(__name__)


class APIBase:
    METHOD_COMMON_PARAMS = {'v', 'lang', 'https', 'test_mode'}

    API_URL = 'https://api.vk.com/method/'
    CAPTCHA_URL = 'https://m.vk.com/captcha.php'

    def __new__(cls, *args, **kwargs):
        method_common_params = {
            key: kwargs.pop(key)
            for key in tuple(kwargs) if key in cls.METHOD_COMMON_PARAMS
        }

        api = object.__new__(cls)
        api.__init__(*args, **kwargs)

        return APINamespace(api, method_common_params)

    def __init__(self, timeout=10):
        self.timeout = timeout

        self.session = requests.Session()
        self.session.headers['Accept'] = 'application/json'
        self.session.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    def send(self, request):

        logger.debug('Prepare API Method request')

        self.prepare_request(request)

        method_url = self.API_URL + request.method
        response = self.session.post(method_url, request.method_params, timeout=self.timeout)

        # todo Replace with something less exceptional
        response.raise_for_status()

        response_or_error = loads(response.text)
        request.response = response_or_error

        if 'response' in response_or_error:

            for error_data in response_or_error.get('execute_errors', ()):
                api_error = VkAPIError(error_data)
                logger.warning('Execute "%s" error: %s', api_error.method, api_error)

            return response_or_error['response']

        elif 'error' in response_or_error:
            request.api_error = VkAPIError(request.response['error'])
            return self.handle_api_error(request)

    def prepare_request(self, request):  # noqa: U100
        pass

    def handle_api_error(self, request):
        logger.error('Handle API error: %s', request.api_error)

        api_error_handler_name = 'on_api_error_' + str(request.api_error.code)
        api_error_handler = getattr(self, api_error_handler_name, self.on_api_error)

        return api_error_handler(request)

    def on_api_error(self, request):
        raise request.api_error


class API(APIBase):
    """The simplest VK API implementation. Can process `any API method <https://dev.vk.com/method>`__
    that can be called from the server

    Args:
        access_token (str): Access token for API requests obtained by any means
            (see :ref:`documentation <Getting access>`)
        **kwargs (any): Additional parameters, which will be passed to each request.
            The most useful is `v` - API version and `lang` - language of responses
            (see :ref:`documentation <Making API request>`)

    Example:
        .. code-block:: python

            >>> import vk
            >>> api = vk.API(access_token='...', v='5.131')
            >>> print(api.users.get(user_ids=1))
            [{'id': 1, 'first_name': 'Павел', 'last_name': 'Дуров', ... }]
    """

    def __init__(self, access_token, **kwargs):
        super().__init__(**kwargs)
        self.access_token = access_token

    def get_captcha_key(self, request):
        """
        Default behavior on CAPTCHA is to raise exception
        Reload this in child
        """
        # request.api_error.captcha_img
        raise request.api_error

    def on_api_error_14(self, request):
        """
        14. Captcha needed
        """
        request.method_params['captcha_key'] = self.get_captcha_key(request)
        request.method_params['captcha_sid'] = request.api_error.captcha_sid

        return self.send(request)

    def prepare_request(self, request):
        request.method_params.setdefault('access_token', self.access_token)


class UserAPI(API):
    """Subclass of :class:`vk.session.API`. It differs only in that it can get access token
    using app id and user credentials (Implicit flow authorization).

    Args:
        user_login (Optional[str]): User login, optional when using :class:`InteractiveMixin`
        user_password (Optional[str]): User password, optional when using :class:`InteractiveMixin`
        app_id (Optional[int]): App ID
        scope (Union[str, int, None]): Access rights you need. Can be passed comma-separated
            list of scopes, or bitmask sum all of them (see `official documentation
            <https://dev.vk.com/reference/access-rights>`__). Defaults to 'offline'
        **kwargs (any): Additional parameters, which will be passed to each request.
            The most useful is `v` - API version and `lang` - language of responses
            (see :ref:`documentation <Making API request>`)

    Example:
        .. code-block:: python

            >>> import vk
            >>> api = vk.UserAPI(
            ...     user_login='...',
            ...     user_password='...',
            ...     app_id=123456,
            ...     scopes='offline,wall'
            ... )
            >>> print(api.users.get(user_ids=1))
            [{'id': 1, 'first_name': 'Павел', 'last_name': 'Дуров', ... }]
    """
    LOGIN_URL = 'https://m.vk.com'
    AUTHORIZE_URL = 'https://oauth.vk.com/authorize'

    def __init__(self, user_login=None, user_password=None, app_id=None, scope='offline', **kwargs):
        self.user_login = user_login
        self.user_password = user_password
        self.app_id = app_id
        self.scope = scope

        super().__init__(self.get_access_token(), **kwargs)

    @staticmethod
    def get_form_action(response):
        form_action = findall(r'<form(?= ).* action="(.+)"', response.text)
        if form_action:
            return form_action[0]
        else:
            raise VkAuthError('No form on page {}'.format(response.url))

    def get_response_url_queries(self, response):
        if not response.ok:
            if response.status_code == 401:
                raise VkAuthError(response.json()['error_description'])
            else:
                response.raise_for_status()

        return self.get_url_queries(response.url)

    @staticmethod
    def get_url_queries(url):
        parsed_url = urllib.parse.urlparse(url)
        url_queries = urllib.parse.parse_qsl(parsed_url.fragment)
        # We lose repeating keys values
        return dict(url_queries)

    def get_access_token(self):
        auth_session = requests.Session()

        if self.login(auth_session):
            return self.authorize(auth_session)

    def get_login_form_data(self):
        return {
            'email': self.user_login,
            'pass': self.user_password,
        }

    def login(self, auth_session):
        # Get login page
        login_page_response = auth_session.get(self.LOGIN_URL)
        # Get login form action. It must contains ip_h and lg_h values
        login_action = self.get_form_action(login_page_response)
        # Login using user credentials
        login_response = auth_session.post(login_action, self.get_login_form_data())

        if 'remixsid' in auth_session.cookies or 'remixsid6' in auth_session.cookies:
            return True

        url_queries = self.get_url_queries(login_response.url)
        if 'sid' in url_queries:
            self.auth_captcha_is_needed(login_response)

        elif url_queries.get('act') == 'authcheck':
            self.auth_check_is_needed(login_response.text)

        elif 'security_check' in url_queries:
            self.phone_number_is_needed(login_response.text)

        else:
            raise VkAuthError('Login error (e.g. incorrect password)')

    def get_auth_params(self):
        return {
            'client_id': self.app_id,
            'scope': self.scope,
            'display': 'mobile',
            'response_type': 'token',
        }

    def authorize(self, auth_session):
        """
        OAuth2
        """
        # Ask access
        ask_access_response = auth_session.post(self.AUTHORIZE_URL, self.get_auth_params())
        url_queries = self.get_response_url_queries(ask_access_response)

        if 'access_token' not in url_queries:
            # Grant access
            grant_access_action = self.get_form_action(ask_access_response)
            grant_access_response = auth_session.post(grant_access_action)
            url_queries = self.get_response_url_queries(grant_access_response)

        return self.process_auth_url_queries(url_queries)

    def process_auth_url_queries(self, url_queries):
        self.expires_in = url_queries.get('expires_in')
        self.user_id = url_queries.get('user_id')
        return url_queries.get('access_token')

    def on_api_error_15(self, request):
        """
        15. Access denied
            - due to scope
        """
        logger.error('Authorization failed. Access token will be dropped')

        del request.method_params['access_token']
        self.access_token = self.get_access_token()

        return self.send(request)


class CommunityAPI(UserAPI):
    """TODO"""

    def __init__(self, *args, **kwargs):
        self.group_ids = kwargs.pop('group_ids', None)
        self.default_group_id = None

        self.access_tokens = {}

        super().__init__(*args, **kwargs)

    def get_auth_params(self):
        auth_params = super().get_auth_params()
        auth_params['group_ids'] = stringify(self.group_ids)
        return auth_params

    def process_auth_url_queries(self, url_queries):
        super().process_auth_url_queries(url_queries)

        self.access_tokens = {}
        for key, value in url_queries.items():
            # access_token_GROUP-ID: ACCESS-TOKEN
            if key.startswith('access_token_'):
                group_id = int(key[len('access_token_'):])
                self.access_tokens[group_id] = value

        self.default_group_id = self.group_ids[0]

    def prepare_request(self, request):
        group_id = request.method_params.get('group_id', self.default_group_id)
        request.method_params.setdefault('access_token', self.access_tokens[group_id])


class InteractiveMixin:

    def __setattr__(self, name, value):
        if name in dir(self.__class__) and not value:
            return

        object.__setattr__(self, name, value)

    @property
    def user_login(self):
        if not hasattr(self, '_cached_user_login'):
            self._cached_user_login = input('VK user login: ')
        return self._cached_user_login

    @property
    def user_password(self):
        if not hasattr(self, '_cached_user_password'):
            self._cached_user_password = getpass.getpass('VK user password: ')
        return self._cached_user_password

    @property
    def access_token(self):
        if not hasattr(self, '_cached_access_token'):
            self._cached_access_token = input('VK API access token: ')
        return self._cached_access_token

    def get_captcha_key(self, captcha_image_url):
        """
        Read CAPTCHA key from shell
        """
        print('Open CAPTCHA image url: ', captcha_image_url)
        return input('Enter CAPTCHA key: ')

    def get_auth_check_code(self):
        """
        Read Auth code from shell
        """
        return input('Auth check code: ')
