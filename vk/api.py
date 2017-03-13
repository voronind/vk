import logging

from .session import Session

logger = logging.getLogger('vk')


class API(object):
    def __init__(self, *args, **kwargs):
        session_class = kwargs.pop('session_class', Session)
        self.session = session_class(*args, **kwargs)

    def new_chain(self):
        return Chain(self)

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


class ChainRequest(object):
    __slots__ = ('_chain', '_method_name', '_method_args')

    def __init__(self, chain, method_name):
        self._chain = chain
        self._method_name = method_name
        self._method_args = {}

    def __getattr__(self, method_name):
        return ChainRequest(self._chain, self._method_name + '.' + method_name)

    def __call__(self, **method_args):
        self._method_args = method_args
        self._chain._requests.append(self)
        return self._chain

    # repr() returns {'key': 'value'} for dicts which is unacceptable
    def _repr_args(self):
        result = ', '.join('"{}": "{}"'.format(k, v)
                           for k, v in self._method_args.items())
        return '{' + result + '}'

    def get_code(self):
        return 'API.{}({})'.format(self._method_name, self._repr_args())


class Chain(object):
    __slots__ = ('_requests', '_api')

    def __init__(self, api):
        self._api = api
        self._requests = []

    def execute(self):
        return self._api.execute(code=self._get_code())

    def __getattr__(self, method_name):
        return ChainRequest(self, method_name)

    def _get_code(self):
        code = ', '.join(r.get_code() for r in self._requests)
        code = 'return [{}];'.format(code)
        return code
