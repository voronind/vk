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
        """Default behavior on CAPTCHA is to raise exception. Redefine in a subclass
        """
        raise api_error

    def on_api_error_14(self, request):
        """Captcha error handler. Retrieves captcha via :meth:`API.get_captcha_key` and
        resends request
        """
        request.method_params['captcha_key'] = self.get_captcha_key(request.api_error)
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
            ...     app_id=123456,
            ...     scope='offline,wall',
            ...     v='5.131'
            ... )
            >>> print(api.users.get(user_ids=1))
            [{'id': 1, 'first_name': 'Павел', 'last_name': 'Дуров', ... }]
    """
    LOGIN_URL = 'https://m.vk.com'
    AUTHORIZE_URL = 'https://oauth.vk.com/token'

    def __init__(
        self,
        user_login=None,
        user_password=None,
        client_id=2274003,
        client_secret='hHbZxrka2uZ6jB1inYsH',
        scope='offline',
        **kwargs
    ):
        self.user_login = user_login
        self.user_password = user_password
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope

        super().__init__(self.get_access_token(), **kwargs)

    @staticmethod
    def _get_form_action(res):
        form_action = findall(r'<form(?= ).* action="(.+)"', res.text)
        if form_action:
            return form_action[0]
        else:
            raise VkAuthError('No form on page {}'.format(res.url))

    @staticmethod
    def _get_url_queries(url):
        parsed_url = urllib.parse.urlparse(url)
        url_queries = urllib.parse.parse_qsl(parsed_url.fragment)
        # We lose repeating keys values
        return dict(url_queries)

    def _process_auth_url_queries(self, url_queries):
        if 'fail' in url_queries:
            raise VkAuthError('Unknown error')

        self.user_id = url_queries.get('user_id')
        return url_queries['access_token']

    def get_access_token(self):
        auth_session = requests.Session()
        res = auth_session.post(self.AUTHORIZE_URL, params=self._get_auth_params()).json()

        if 'error' in res:
            return {
                'need_validation': self.auth_check_is_needed,
                'need_captcha': self.auth_captcha_is_needed
            }.get(res['error'], self.auth_failed)(auth_session, res)

        return res['access_token']

    def auth_check_is_needed(self, auth_session, response):
        validation_page = auth_session.get(response['redirect_uri'])
        action_url = self.LOGIN_URL + self._get_form_action(validation_page)

        res = auth_session.post(action_url, self._get_validation_params())
        url_queries = self._get_url_queries(res.url)

        return self._process_auth_url_queries(url_queries)

    def auth_captcha_is_needed(self, auth_session, response):
        error_data = {
            'error_code': ErrorCodes.CAPTCHA_NEEDED,
            'error_msg': 'Captcha error occured during authorization',
            'captcha_sid': response['captcha_sid'],
            'captcha_img': response['captcha_img']
        }
        error = VkAPIError(error_data)

        return auth_session.post(
            self.AUTHORIZE_URL,
            params={
                'captcha_sid': error.captcha_sid,
                'captcha_img': self.get_captcha_key(error),
                **self._get_auth_params()
            }
        ).json()['access_token']

    def auth_failed(self, auth_session, response):  # noqa: U100
        logger.error(f'Authorization failed: unknown error. response_params = {response}')
        raise VkAuthError(f'Authorization failed: unknown error. response_params = {response}')

    def _get_auth_params(self):
        return {
            'grant_type': 'password',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'username': self.user_login,
            'password': self.user_password,
            'scope': self.scope,
            '2fa_supported': 1
        }

    def _get_validation_params(self):
        return {
            'code': self.get_auth_check_code(),
            'remember': 1
        }

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
        if name in dir(self.__class__) and not value:
            return

        if name in filter(property, dir(self.__class__)):
            object.__setattr__(self, '_cached_' + name, value)

        else:
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
