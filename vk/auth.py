# coding=utf8

import logging
import abc
from vk.exceptions import VkAuthError, VkAPIError
from vk.utils import raw_input, parse_url_query_params, LoggingSession, get_form_action, \
    str_type, json_iter_parse, stringify_values
import six


logger = logging.getLogger('vk')


@six.add_metaclass(abc.ABCMeta)
class BaseAuthAPI(object):
    """"Base auth api interface"""

    LOGIN_URL = 'https://m.vk.com'
    # REDIRECT_URI = 'https://oauth.vk.com/blank.html'
    AUTHORIZE_URL = 'https://oauth.vk.com/authorize'
    CAPTCHA_URI = 'https://m.vk.com/captcha.php'

    def __init__(self, app_id=None, user_login='', user_password='',
                 scope='offline', **kwargs):
        logger.debug('Init AuthMixin: %r', self)

        self.app_id = app_id
        self._login = user_login
        self._password = user_password
        self._kwargs = kwargs
        self.scope = scope

        # Some API methods get args (e.g. user id) from access token.
        # If we define user login, we need get access token now.
        if self._login:
            self.access_token = self.get_access_token()

    def __repr__(self):
        return '%s(app_id=%d, login=%s, password=%s, **kwargs=%s)' % (
            self.__class__.__name__, self.app_id, self._login,
            self._password, self._kwargs)

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

        response_url_query = parse_url_query_params(response.url)

        session_cookies = ('remixsid' in session.cookies,
                           'remixsid6' in session.cookies)
        if any(session_cookies):
            # Session is already established
            return None

        if 'sid' in response_url_query:
            self.is_auth_captcha_needed(response, login_form_data,
                                        session=session)
        elif response_url_query.get('act') == 'authcheck':
            self.is_sms_code_needed(response.text, session=session)
        elif 'security_check' in response_url_query:
            self.is_phone_number_needed(response.text)
        else:
            message = 'Authorization error (incorrect password)'
            logger.error(message)
            raise VkAuthError(message)

    def do_oauth2_authorization(self, session):
        """ OAuth2
        """
        logger.info('Doing oauth2')
        auth_data = {
            'client_id': self.app_id,
            'display': 'mobile',
            'response_type': 'token',
            'scope': self.scope,
            'v': '5.28',
        }
        response = session.post(self.AUTHORIZE_URL, auth_data)
        url_query_params = parse_url_query_params(response.url)
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
        else:
            error_message = 'VK error: [{}] {}'.format(
                response_json['error'], response_json['error_description'])
        logger.error('Permissions obtained')
        raise VkAuthError(error_message)

    def is_sms_code_needed(self, html, session):
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

    def is_auth_captcha_needed(self, response, login_form_data, session):
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

    @staticmethod
    def is_phone_number_needed(text):
        raise VkAuthError('Phone number is needed')

    def get_sms_code(self):
        raise VkAuthError('Auth check code is needed')


class InteractiveAuthAPI(AuthAPI):
    """Interactive auth api with manual login, password, captcha management"""

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
    AUTH_SESSION_CLS = AuthAPI

    def __init__(self, app_id, user_login, user_password):
        self.auth_api = VKSession.get_auth_api(
            app_id, user_login, user_password)

        self._access_token = None
        self.censored_access_token = None
        self.is_access_token_required = False

        # requests.Session subclass instance
        self.http_session = LoggingSession()
        self.http_session.headers['Accept'] = 'application/json'
        self.http_session.headers['Content-Type'] = 'application/x-www-form-urlencoded'

    @classmethod
    def get_auth_api(cls, app_id, login, password):
        """Get auth api instance
        """
        if not issubclass(cls.AUTH_SESSION_CLS, BaseAuthAPI):
            raise TypeError(
                'Wrong AUTH_SESSION_CLS %s, must be subclass of %s' %
                (cls.AUTH_SESSION_CLS, BaseAuthAPI.__name__, ))
        return cls.AUTH_SESSION_CLS(
            app_id=app_id, user_login=login, user_password=password)

    @property
    def access_token(self):
        logger.debug('Check that we need new access token')
        if self.is_access_token_required:
            logger.debug('We need new access token. Try to get it.')
            self._access_token = self.auth_api.get_access_token()
        else:
            logger.debug('Use old access token')
        return self._access_token

    @access_token.setter
    def access_token(self, value):
        self._access_token = value
        if isinstance(value, str_type) and len(value) >= 12:
            self.censored_access_token = '{}***{}'.format(value[:4], value[-4:])
        else:
            self.censored_access_token = value
        logger.debug('access_token = %r', self.censored_access_token)
        self.is_access_token_required = not self._access_token

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
                error = VkAPIError(error_data)

                if error.is_captcha_needed():
                    captcha_key = self.auth_api.get_captcha_key(
                        error.captcha_img)

                    if not captcha_key:
                        raise error

                    captcha_response = {
                        'sid': error.captcha_sid,
                        'key': captcha_key,
                    }
                    return self.make_request(
                        request_obj, captcha_response=captcha_response)

                elif error.is_access_token_incorrect():
                    logger.info(
                        'Authorization failed. Access token will be dropped')
                    self.access_token = None
                    return self.make_request(request_obj)

                else:
                    raise error

            elif 'response' in response_or_error:
                # todo Can we have error and response simultaneously
                # for error in errors:
                #     logger.warning(str(error))

                return response_or_error['response']

    def send_api_request(self, request, captcha_response=None):
        url = self.API_URL + request._method_name
        method_args = request._api._method_default_args.copy()
        method_args.update(stringify_values(request._method_args))
        access_token = self.access_token
        if access_token:
            method_args['access_token'] = access_token
        if captcha_response:
            method_args['captcha_sid'] = captcha_response['sid']
            method_args['captcha_key'] = captcha_response['key']
        timeout = request._api._timeout

        # TODO: add option to use get or post for VK API
        response = self.http_session.post(url, method_args, timeout=timeout)
        return response

    def __repr__(self):
        return "%s(api_url='%s', access_token='%s')" % (
            self.__class__.__name__, self.API_URL, self.access_token)


class InteractiveVKSession(VKSession):
    AUTH_SESSION_CLS = InteractiveAuthAPI