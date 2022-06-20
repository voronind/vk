import getpass
import logging
import urllib
from json import loads
from re import findall

import requests

from .api import APINamespace
from .exceptions import ErrorCodes, VkAPIError, VkAuthError
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

    def __init__(self, timeout=10, proxy=None):
        self.timeout = timeout

        self.session = requests.Session()
        self.session.proxies = {'http': proxy, 'https': proxy}
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
        """Default API error handler that handles all errros and raises them. You can add a
        handler for a specific error by redefining it in your class and appending the error
        code to the method name. In this case, the redefined method will be called instead of
        :meth:`on_api_error`. The :exc:`vk.exceptions.VkAPIError` object can be obtained via
        ``request.api_error``

        Args:
            request (vk.api.APIRequest): API request object

        Example:
            .. code-block:: python

                import vk

                class API(vk.APIBase):
                    def on_api_error_1(self, request):
                        print('An unknown error has occurred :(')

                api = API()
        """
        raise request.api_error


class API(APIBase):
    """The simplest VK API implementation. Can process `any API method <https://dev.vk.com/method>`__
    that can be called from the server

    Args:
        access_token (Optional[str]): Access token for API requests obtained by any means
            (see :ref:`documentation <Getting access>`). Optional when using :class:`InteractiveMixin`
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

    def __init__(self, access_token=None, **kwargs):
        super().__init__(**kwargs)
        self.access_token = access_token

    def get_captcha_key(self, api_error):
        """Callback to retrieve CAPTCHA key. Default behavior is to raise exception,
        redefine in a subclass

        Args:
            api_error (vk.exceptions.VkAPIError): Captcha error that occurred

        Returns:
            Captcha solution (a short string consisting of lowercase letters and numbers)
        """
        raise api_error

    def on_api_error_14(self, request):
        """Captcha error handler. Retrieves captcha via :meth:`API.get_captcha_key` and
        resends request
        """
        request.method_params['captcha_key'] = self.get_captcha_key(request)
        request.method_params['captcha_sid'] = request.api_error.captcha_sid

        return self.send(request)

    def prepare_request(self, request):
        request.method_params.setdefault('access_token', self.access_token)


class UserAPI(API):
    """Subclass of :class:`vk.session.API`. It differs only in that it can get access token
    using user credentials (`Implicit flow authorization
    <https://dev.vk.com/api/access-token/implicit-flow-user>`__).

    Args:
        user_login (Optional[str]): User login, optional when using :class:`InteractiveMixin`
        user_password (Optional[str]): User password, optional when using :class:`InteractiveMixin`
        client_id (Optional[int]): ID of the application to authorize with, defaults to
            "VK Admin" app ID
        scope (Optional[Union[str, int]]): Access rights you need. Can be passed
            comma-separated list of scopes, or bitmask sum all of them (see `official
            documentation <https://dev.vk.com/reference/access-rights>`__). Defaults
            to 'offline'
        **kwargs (any): Additional parameters, which will be passed to each request.
            The most useful is `v` - API version and `lang` - language of responses
            (see :ref:`documentation <Making API request>`)

    Example:
        .. code-block:: python

            >>> import vk
            >>> api = vk.UserAPI(
            ...     user_login='...',
            ...     user_password='...',
            ...     scope='offline,wall',
            ...     v='5.131'
            ... )
            >>> print(api.users.get(user_ids=1))
            [{'id': 1, 'first_name': 'Павел', 'last_name': 'Дуров', ... }]
    """
    LOGIN_URL = 'https://oauth.vk.com'
    AUTHORIZE_URL = 'https://oauth.vk.com/authorize'

    def __init__(self, user_login=None, user_password=None, client_id=6121396, scope='offline', **kwargs):
        self.user_login = user_login
        self.user_password = user_password
        self.client_id = client_id
        self.scope = scope

        super().__init__(self.get_access_token(), **kwargs)

    @staticmethod
    def _get_form_action(response):
        form_action = findall(r'<form(?= ).* action="(.+)"', response.text)
        if form_action:
            return form_action[0]
        raise VkAuthError(f'No form on page {response.url}')

    @staticmethod
    def _get_input_value(response, name):
        input_value = findall(rf'<input.* type="hidden".* name="{name}".* value="(.+)"', response.text)
        if input_value:
            return input_value[0]
        raise VkAuthError(f'No input with name `{name}` on page {response.url}')

    @staticmethod
    def _get_url_queries(url):
        parsed_url = urllib.parse.urlparse(url)
        # We lose repeating keys values
        return dict(urllib.parse.parse_qsl(parsed_url.fragment or parsed_url.query))

    @staticmethod
    def _oauth_is_request_success(response):
        if not response.ok:
            if response.status_code == 401:
                description = response.json()['error_description']
                logger.error('OAuth authorization failed: %s', description)
                raise VkAuthError(description)
            response.raise_for_status()

    def get_access_token(self):
        auth_session = requests.Session()
        auth_session.headers['Origin'] = 'https://oauth.vk.com'

        if self.login(auth_session):
            return self.authorize(auth_session)

    def get_login_form_data(self, response):
        return {
            'ip_h': self._get_input_value(response, 'ip_h'),
            'lg_domain_h': self._get_input_value(response, 'lg_domain_h'),
            'to': self._get_input_value(response, 'to'),
            'email': self.user_login,
            'pass': self.user_password,
        }

    def login(self, auth_session, login_response=None):
        if not login_response:
            logger.debug('Start of the login process')
            # Get login page
            login_page_response = auth_session.get(self.AUTHORIZE_URL, params=self.get_auth_params())
            # Check if params for OAuth is enough
            self._oauth_is_request_success(login_page_response)
            # Get login form action
            login_action = self._get_form_action(login_page_response)
            # Login using user credentials
            login_response = auth_session.post(login_action, self.get_login_form_data(login_page_response))

        if 'remixsid' in auth_session.cookies or 'remixsid6' in auth_session.cookies:
            logger.debug('Successfully logged in')
            return True

        url_queries = self._get_url_queries(login_response.url)

        if 'sid' in url_queries:
            logger.debug('Auth captcha is needed')
            return self.auth_captcha_is_needed(auth_session, login_response)

        if url_queries.get('act') == 'authcheck':
            logger.debug('Auth check code is needed')
            return self.auth_check_is_needed(auth_session, login_response)

        if 'security_check' in url_queries:
            logger.debug('Phone number is needed')
            return self.phone_number_is_needed(auth_session, login_response)

        logger.error('Unknown login error. Last URL: %s.', login_response.url)
        raise VkAuthError('Login error (e.g. incorrect password)')

    def auth_captcha_is_needed(self, auth_session, response):
        # Get login form action
        login_action = self._get_form_action(response)

        # Get captcha data (img and sid)
        captcha_img = findall(r'<img.* id="captcha".* src="([^\"]+)"', response.text)
        if captcha_img:
            captcha_img = captcha_img[0]
        else:
            raise VkAuthError(f'No captcha on page {response.url}')

        captcha_sid = self._get_input_value(response, 'captcha_sid')

        # Create a bogus error
        error_data = {
            'error_code': ErrorCodes.CAPTCHA_NEEDED,
            'error_msg': 'Captcha error occured during authorization',
            'captcha_sid': captcha_sid,
            'captcha_img': captcha_img
        }
        error = VkAPIError(error_data)

        # Login again using user credentials and solved captcha
        login_form_data = {
            **self.get_login_form_data(response),
            'captcha_sid': captcha_sid,
            'captcha_key': self.get_captcha_key(error)
        }
        login_response = auth_session.post(login_action, login_form_data)

        # Re-login with solved captcha
        return self.login(auth_session, login_response)

    def get_auth_check_code(self):
        """Callback to retrieve authentication check code (if account supports 2FA). Default
        behavior is to raise exception, redefine in a subclass

        Returns:
            The authentication check code can be obtained in the sent SMS, using Google
            Authenticator (or another authenticator), or it can be one of ten backup codes
        """
        raise NotImplementedError

    def auth_check_is_needed(self, auth_session, response):
        auth_check_action = self.LOGIN_URL + self._get_form_action(response)
        login_response = auth_session.post(auth_check_action, {'code': self.get_auth_check_code()})

        # Re-login with auth check code
        return self.login(auth_session, login_response)

    def phone_number_is_needed(self, auth_session, response):  # noqa: U100
        raise NotImplementedError

    def get_auth_params(self):
        return {
            'client_id': self.client_id,
            'scope': self.scope,
            'display': 'mobile',
            'response_type': 'token',
        }

    def authorize(self, auth_session):
        logger.debug('Start of the OAuth authorization process')
        # Ask access
        ask_access_response = auth_session.post(self.AUTHORIZE_URL, self.get_auth_params())
        self._oauth_is_request_success(ask_access_response)
        url_queries = self._get_url_queries(ask_access_response.url)

        if 'authorize_url' not in url_queries:
            logger.debug('Grant access to app')
            # Grant access
            grant_access_action = self._get_form_action(ask_access_response)
            grant_access_response = auth_session.post(grant_access_action)
            url_queries = self._get_url_queries(grant_access_response.url)

        url_queries = self._get_url_queries(urllib.parse.unquote(url_queries['authorize_url']))

        self.expires_in = url_queries.get('expires_in')
        self.user_id = url_queries.get('user_id')

        if 'access_token' in url_queries:
            logger.debug('Successfully authorized')
            return url_queries['access_token']

        logger.error('Unknown OAuth authorization error. URL queries = %s.', url_queries)
        raise VkAuthError('OAuth authorization failed')


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
    """Mixin that receives the necessary data from the console

    Example:
        .. code-block:: python

            import vk
            from vk.session import InteractiveMixin

            class API(InteractiveMixin, vk.API):
                pass

            api = API()

            # The input will appear: `VK API access token: `
    """

    def __setattr__(self, name, value):
        attrs = dir(self.__class__)

        if name in attrs and not value:
            return

        if name in filter(lambda x: isinstance(getattr(self.__class__, x), property), attrs):
            return object.__setattr__(self, '_cached_' + name, value)

        return object.__setattr__(self, name, value)

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

    def get_captcha_key(self, api_error):
        """
        Read CAPTCHA key from shell
        """
        print('Open CAPTCHA image url: ', api_error.captcha_img)
        return input('Enter CAPTCHA key: ')

    def get_auth_check_code(self):
        """
        Read Auth code from shell
        """
        return input('Auth check code: ')
