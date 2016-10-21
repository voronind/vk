# coding=utf8

import logging
import logging.config
from vk.auth import VKSession
from vk.settings import LOGGING_CONFIG


VERSION = '2.0.2'

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger('vk')


class API(object):
    def __init__(self, session, timeout=10, **method_default_args):
        self._session = session
        self._timeout = timeout
        self._method_default_args = method_default_args

    @classmethod
    def create_api(cls, app_id=None, login=None, password=None, timeout=10,
                   **method_default_args):
        """Factory method to explicitly create API with app_id, login and
        password parameters.
        If those are not passed - token-free session will be created
        automatically

        :return: vk.API instance
        """
        session = VKSession(app_id, login, password)
        instance = cls(session=session, timeout=timeout, **method_default_args)
        return instance

    def get_default_args(self):
        return self._method_default_args.copy()

    def get_timeout(self):
        return self._timeout

    def make_request(self, request_obj):
        return self._session.make_request(request_obj)

    def __getattr__(self, method_name):
        return Request(self, method_name)

    def __call__(self, method_name, **method_kwargs):
        return getattr(self, method_name)(**method_kwargs)


class Request(object):
    __slots__ = ('_api', '_method_name', '_method_args')

    def __init__(self, api, method_name):
        self._api = api
        self._method_name = method_name
        self._method_args = None  # will be set with __call__ execution

    def get_api(self):
        return self._api

    def get_method_name(self):
        return self._method_name

    def get_method_args(self):
        return self._method_args

    def __getattr__(self, method_name):
        return Request(self._api, self._method_name + '.' + method_name)

    def __call__(self, **method_args):
        self._method_args = method_args
        return self._api.make_request(request_obj=self)

    def __repr__(self):
        return "%s(method='%s', args=%s)" % (
            self.__class__.__name__, self.get_method_name(),
            self.get_method_args())
