import pytest
from vk.api import APINamespace, APIMethod, APIRequest


class APISessionMock:
    def send(self, request):
        return request


@pytest.fixture(scope='module')
def api_namespace():
    return APINamespace(APISessionMock(), {'param': 'value'})


def test_api_namespace_getattr(api_namespace):
    assert isinstance(api_namespace.some_method, APIMethod)
    assert api_namespace.some_method._method == 'some_method'


def test_api_namespace_call(api_namespace):
    assert isinstance(api_namespace('some_method'), APIMethod)
    assert api_namespace('some_method')._method == 'some_method'


def test_method_getattr(api_namespace):
    assert isinstance(api_namespace.method.some_method, APIMethod)
    assert api_namespace.method.some_method._method == 'method.some_method'


def test_method_call(api_namespace):
    request = api_namespace.method()

    assert isinstance(request, APIRequest)
    assert request.method == 'method'
    assert request.method_params == {'param': 'value'}


def test_params_merging(api_namespace):
    request = api_namespace.method(param2='value2')

    assert request.method_params == {'param': 'value', 'param2': 'value2'}


def test_params_overriding(api_namespace):
    request = api_namespace.method(param='new-value')

    assert request.method_params == {'param': 'new-value'}
