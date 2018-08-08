from pytest import fixture

from vk.api import APINamespace, APIMethod, APIRequest


class APISessionMock:
    def send(self, request):
        return request


@fixture('module')
def api():
    return APINamespace(APISessionMock(), {'param': 'value'})


def test_api_getattr(api):
    assert isinstance(api.some_method, APIMethod)
    assert api.some_method._method == 'some_method'


def test_api_call(api):
    assert isinstance(api('some_method'), APIMethod)
    assert api('some_method')._method == 'some_method'


def test_method_getattr(api):
    assert isinstance(api.method.some_method, APIMethod)
    assert api.method.some_method._method == 'method.some_method'


def test_method_call(api):
    request = api.method()

    assert isinstance(request, APIRequest)
    assert request.method == 'method'
    assert request.method_params == {'param': 'value'}


def test_params_merging(api):
    request = api.method(param2='value2')

    assert request.method_params == {'param': 'value', 'param2': 'value2'}


def test_params_overriding(api):
    request = api.method(param='new-value')

    assert request.method_params == {'param': 'new-value'}
