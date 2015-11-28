# coding=utf8

import logging
import abc
from vk.exceptions import VkAuthError, VkAPIError
from vk.utils import raw_input, parse_url_query_params, LoggingSession, get_form_action, \
    str_type, json_iter_parse, stringify_values, get_masked_phone_number
import six


logger = logging.getLogger('vk')


@six.add_metaclass(abc.ABCMeta)
class BaseAuthAPI(object):
    """"Base auth api interface"""

    LOGIN_URL = 'https://m.vk.com'
    # REDIRECT_URI = 'https://oauth.vk.com/blank.html'
    AUTHORIZE_URL = 'https://oauth.vk.com/authorize'
    CAPTCHA_URI = 'https://m.vk.com/captcha.php'
    API_VERSION = '5.40'

    def __init__(self, app_id=None, user_login='', user_password='',
                 scope='offline', **kwargs):
        logger.debug('Init AuthMixin: %r', self)

        self.app_id = app_id
        self._login = user_login
        self._password = user_password
        self._kwargs = kwargs
        self.scope = scope
        self._access_token = None

        # Some API methods get args (e.g. user id) from access token.
        # If we define user login, we need get access token now.
        if self._login:
            self.renew_access_token()

    def __repr__(self):
        return '%s(app_id=%d, login=%s, password=%s, **kwargs=%s)' % (
            self.__class__.__name__, self.app_id, self._login,
            self._password, self._kwargs)

    @property
    def access_token(self):
        if self._access_token is None:
            self._access_token = self.get_access_token()
        return self._access_token

    def renew_access_token(self):
        """Force to get new access token

        """
        self._access_token = self.get_access_token()

    @abc.abstractmethod
    def get_access_token(self):
        """Implement this in subclasses

        """
        pass

    @abc.abstractmethod
    def get_sms_code(self):
        """Get sms code method when user enabled 2-factor auth

        """
        pass

    @staticmethod
    def get_captcha_key(captcha_image_url):
        """Default behavior on CAPTCHA is to raise exception if this method
        return None.
        Reload this in child if needed

        :param captcha_image_url: str
        """
        return None


class AuthAPI(BaseAuthAPI):
    """Default auth API"""

    def get_access_token(self):
        """
        Get access token using app id and user login and password.
        """

        if not all([self.app_id, self._login, self._password]):
            raise ValueError(
                'app_id=%s, login=%s password=%s (masked) must be given' % (
                    self.app_id, self._login, bool(self._password)))

        logger.info("Getting access token for user '%s'" % self._login)
        with LoggingSession() as s:
            self.do_login(session=s)
            url_query_params = self.do_oauth2_authorization(session=s)

        if 'access_token' in url_query_params:
            logger.info('Done')
            return url_query_params['access_token']
        else:
            raise VkAuthError('OAuth2 authorization error')

    def do_login(self, session):
        """Do vk login

        :param session: vk.utils.LoggingSession: http session
        """

        response = session.get(self.LOGIN_URL)
        login_form_action = get_form_action(response.text)
        if not login_form_action:
            raise VkAuthError('VK changed login flow')

        login_form_data = {'email': self._login, 'pass': self._password}
        response = session.post(login_form_action, login_form_data)
        logger.debug('Cookies: %s', session.cookies)

        response_url_query = parse_url_query_params(
            response.url, fragment=False)
        act = response_url_query.get('act')

        # Check response url query params firstly
        if 'sid' in response_url_query:
            self.require_auth_captcha(
                response, login_form_data, session=session)

        elif act == 'authcheck':
            self.require_sms_code(response.text, session=session)

        elif act == 'security_check':
            # Interactive call
            self.require_phone_number(html=response.text, session=session)

        session_cookies = ('remixsid' in session.cookies,
                           'remixsid6' in session.cookies)

        if any(session_cookies):
            # Session is already established
            logger.info('Session is already established')
            return None
        else:
            message = 'Authorization error (incorrect password)'
            logger.error(message)
            raise VkAuthError(message)

    def do_oauth2_authorization(self, session):
        """ OAuth2. More info: https://vk.com/dev/auth_mobile
        """
        logger.info('Doing oauth2')
        auth_data = {
            'client_id': self.app_id,
            'display': 'mobile',
            'response_type': 'token',
            'scope': self.scope,
            'v': self.API_VERSION
        }
        response = session.post(self.AUTHORIZE_URL, auth_data)
        url_query_params = parse_url_query_params(response.url)
        if 'expires_in' in url_query_params:
            logger.info('Token will be expired in %s sec.' %
                        url_query_params['expires_in'])
        if 'access_token' in url_query_params:
            return url_query_params

        # Permissions is needed
        logger.info('Getting permissions')
        form_action = get_form_action(response.text)
        logger.debug('Response form action: %s', form_action)

        if form_action:
            response = session.get(form_action)
            url_query_params = parse_url_query_params(response.url)
            return url_query_params
        try:
            response_json = response.json()
        except ValueError:  # not JSON in response
            error_message = 'OAuth2 grant access error'
            logger.error(response.text)
        else:
            error_message = 'VK error: [{}] {}'.format(
                response_json['error'], response_json['error_description'])
        logger.error('Permissions obtained')
        raise VkAuthError(error_message)

    def require_sms_code(self, html, session):
        logger.info('User enabled 2 factors authorization. '
                    'Auth check code is needed')
        auth_check_form_action = get_form_action(html)
        auth_check_code = self.get_sms_code()
        auth_check_data = {
            'code': auth_check_code,
            '_ajax': '1',
            'remember': '1'
        }
        response = session.post(auth_check_form_action, data=auth_check_data)
        return response

    def require_auth_captcha(self, response, login_form_data, session):
        logger.info('Captcha is needed')

        response_url_dict = parse_url_query_params(response.url)
        captcha_form_action = get_form_action(response.text)
        logger.debug('form_url %s', captcha_form_action)
        if not captcha_form_action:
            raise VkAuthError('Cannot find form url')

        # TODO: Are we sure that `response_url_dict` doesn't contain CAPTCHA image url?
        captcha_url = '%s?s=%s&sid=%s' % (
            self.CAPTCHA_URI, response_url_dict['s'], response_url_dict['sid'])
        # logger.debug('Captcha url %s', captcha_url)

        login_form_data['captcha_sid'] = response_url_dict['sid']
        login_form_data['captcha_key'] = self.get_captcha_key(captcha_url)

        response = session.post(captcha_form_action, login_form_data)
        return response

    @classmethod
    def require_phone_number(cls, html, session):
        logger.info(
            'Auth requires phone number. You do login from unusual place')
        form_action_url = get_form_action(html)

        # Get masked phone from html to make things more clear
        phone_prefix, phone_suffix = get_masked_phone_number(html)
        prompt = 'Phone number (%s****%s): ' % (
            phone_prefix, phone_suffix)
        phone_number = raw_input(prompt)

        params = parse_url_query_params(form_action_url, fragment=False)
        auth_data = {
            'code': phone_number,
            'act': 'security_check',
            'hash': params['hash']}
        response = session.post(
            url=cls.LOGIN_URL + form_action_url, data=auth_data)
        logger.info(response.text)

    def get_sms_code(self):
        raise VkAuthError('Auth check code is needed')


class InteractiveAuthAPI(AuthAPI):
    """Interactive auth api with manual login, password, captcha management"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._login = InteractiveAuthAPI.get_user_login()
        self._password = InteractiveAuthAPI.get_user_password()

    @staticmethod
    def get_user_login():
        user_login = raw_input('VK user login: ')
        return user_login.strip()

    @staticmethod
    def get_user_password():
        import getpass

        user_password = getpass.getpass('VK user password: ')
        return user_password

    def get_access_token(self):
        logger.debug('InteractiveMixin.get_access_token()')
        access_token = super(InteractiveAuthAPI, self).get_access_token()
        if not access_token:
            access_token = raw_input('VK API access token: ')
        return access_token

    @staticmethod
    def get_captcha_key(captcha_image_url):
        """Read CAPTCHA key from user input
        """

        print('Open CAPTCHA image url: ', captcha_image_url)
        captcha_key = raw_input('Enter CAPTCHA key: ')
        return captcha_key

    def get_sms_code(self):
        """
        Read Auth code from shell
        """
        auth_check_code = raw_input('Auth check code: ')
        return auth_check_code.strip()


class VKSession(object):
    API_URL = 'https://api.vk.com/method/'
    AUTH_API_CLS = AuthAPI

    def __init__(self, app_id=None, user_login=None, user_password=None):
        self.auth_api = VKSession.get_auth_api(
            app_id, user_login, user_password)

        self.censored_access_token = None
        # Require token if any of auth parameters are being passed
        self.is_token_required = any([app_id, user_login, user_password])

        # requests.Session subclass instance
        self.http_session = LoggingSession()
        self.http_session.headers['Accept'] = 'application/json'
        self.http_session.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    @classmethod
    def get_auth_api(cls, app_id, login, password):
        """Get auth api instance
        """

        if not issubclass(cls.AUTH_API_CLS, BaseAuthAPI):
            raise TypeError(
                'Wrong AUTH_API_CLS %s, must be subclass of %s' %
                (cls.AUTH_API_CLS, BaseAuthAPI.__name__, ))

        return cls.AUTH_API_CLS(
            app_id=app_id, user_login=login, user_password=password)

    @property
    def access_token(self):
        return self.auth_api.access_token

    @access_token.setter
    def access_token(self, value):
        self.auth_api._access_token = value
        if isinstance(value, str_type) and len(value) >= 12:
            self.censored_access_token = '{}***{}'.format(value[:4], value[-4:])
        else:
            self.censored_access_token = value
        logger.debug('access_token = %r', self.censored_access_token)

    def make_request(self, request_obj, captcha_response=None):
        logger.debug('Prepare API Method request')
        response = self.send_api_request(request=request_obj,
                                         captcha_response=captcha_response)
        # todo Replace with something less exceptional
        response.raise_for_status()

        # there are may be 2 dicts in one JSON
        # for example: "{'error': ...}{'response': ...}"
        for response_or_error in json_iter_parse(response.text):
            if 'error' in response_or_error:
                error_data = response_or_error['error']
                vk_error = VkAPIError(error_data)

                if vk_error.is_captcha_needed():
                    captcha_key = self.auth_api.get_captcha_key(
                        vk_error.captcha_img)

                    if not captcha_key:
                        raise vk_error

                    captcha_response = {
                        'sid': vk_error.captcha_sid,
                        'key': captcha_key,
                    }
                    return self.make_request(
                        request_obj, captcha_response=captcha_response)

                elif vk_error.is_access_token_incorrect():
                    logger.info(
                        'Authorization failed. Access token will be dropped')
                    self.access_token = None
                    return self.make_request(request_obj)

                else:
                    raise vk_error
            elif 'execute_errors' in response_or_error:
                # can take place while running .execute vk method
                # See more: https://vk.com/dev/execute
                raise VkAPIError(response_or_error['execute_errors'][0])
            elif 'response' in response_or_error:
                # todo Can we have error and response simultaneously
                # for error in errors:
                #     logger.warning(str(error))

                return response_or_error['response']

    def send_api_request(self, request, captcha_response=None):
        url = self.API_URL + request.get_method_name()
        vk_api = request.get_api()

        method_args = vk_api.get_default_args()
        method_args.update(stringify_values(request.get_method_args()))
        if self.is_token_required:
            # Auth api call if access_token weren't be got earlier
            method_args['access_token'] = self.access_token
        if captcha_response:
            method_args['captcha_sid'] = captcha_response['sid']
            method_args['captcha_key'] = captcha_response['key']

        response = self.http_session.post(
            url, method_args, timeout=vk_api.get_timeout())
        return response

    def __repr__(self):
        return "%s(api_url='%s', access_token='%s')" % (
            self.__class__.__name__, self.API_URL, self.auth_api._access_token)


class InteractiveVKSession(VKSession):
    AUTH_API_CLS = InteractiveAuthAPI