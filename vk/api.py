import logging

from .session import Session

logger = logging.getLogger('vk')


class API(object):
    def __init__(self, *args, **kwargs):
        session_class = kwargs.pop('session_class', Session)
        self.session = session_class(*args, **kwargs)

    def __getattr__(self, method_name):
        return Request(self, method_name)

    def __call__(self, method_name, **method_kwargs):
        return getattr(self, method_name)(**method_kwargs)


class Request(object):
    __slots__ = ('_api', '_method_name', '_method_args')

    def __init__(self, api, method_name):
        self._api = api
        self._method_name = method_name
        self._method_args = {}

    def __getattr__(self, method_name):
        return Request(self._api, self._method_name + '.' + method_name)

    def __call__(self, **method_args):
        self._method_args = method_args
        return self._api.session.make_request(self)
