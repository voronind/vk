import requests

import pytest
from vk.session import APIBase


@pytest.fixture(scope='session')
def v():
    """
    Actual vk API version
    """
    return '5.80'


class Attributable(object):
    def set_attrs(self, attributes):
        for attr_name, attr_value in attributes.items():
            setattr(self, attr_name, attr_value)


class RequestData(Attributable):
    def __init__(self, data):
        self.set_attrs(data)

    def __repr__(self):
        return '<RequestData {}>'.format(self.__dict__)


class Request(Attributable):
    def __init__(self, method, url, **kwargs):
        self.method = method
        self.url = url

        self.data = RequestData(kwargs.pop('data', {}))
        self.set_attrs(kwargs)


class Response(object):
    def __init__(self, text='', status_code=200, url=None):
        self.text = text
        self.status_code = status_code
        self.url = url

    def raise_for_status(self):
        if self.status_code != 200:
            raise ValueError(self.status_code)


@pytest.fixture
def response_class():
    return Response


class MockedSessionBase(requests.Session):

    def __init__(self):
        super(MockedSessionBase, self).__init__()

        self.history = []
        self.last_request = None

    def request(self, method, url, **kwargs):
        self.last_request = Request(method, url, **kwargs)

        response = self.mocked_request(method, url, **kwargs)
        if not response:
            raise NotImplementedError

        return response


@pytest.fixture
def session_class():
    return MockedSessionBase


@pytest.fixture
def mock_requests_session(monkeypatch):

    class MockedSession(MockedSessionBase):

        def mocked_request(self, verb, url, **kwargs):
            if verb == 'POST':
                if url.startswith(APIBase.API_URL):
                    # method = url[len(vk.Session.API_URL):]
                    return Response()

    monkeypatch.setattr('requests.Session', MockedSession)
