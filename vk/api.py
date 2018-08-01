import logging

from .session import Session

logger = logging.getLogger('vk')


class API:
    def __init__(self, session: Session=None, **kwargs):
        if session is None:
            session = Session(**kwargs)
        self._session = session

    def __getattr__(self, method):
        return APIMethod(self._session, method)

    def __call__(self, method, **method_params):
        return APIMethod(self._session, method)(**method_params)


class APIMethod:
    def __init__(self, session, method):
        self._session = session
        self._method = method

    def __getattr__(self, method):
        return APIMethod(self._session, self._method + '.' + method)

    def __call__(self, **method_params):
        request = APIRequest(self._method, method_params)
        return self._session.send(request)


class APIRequest:
    def __init__(self, method, method_params):
        self.method = method
        self.method_params = method_params
