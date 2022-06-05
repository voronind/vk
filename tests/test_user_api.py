import getpass
import sys
from io import StringIO

import pytest

import vk
from vk.session import InteractiveMixin


@pytest.fixture
def user_login():
    return 'user-login'


@pytest.fixture
def user_password():
    return 'user-password'


@pytest.fixture
def app_id():
    return 'app-id'


@pytest.fixture
def scope():
    return 'scope'


@pytest.fixture(autouse=True)
def mock_requests_session(monkeypatch, user_login, user_password, access_token, response_class, session_class):

    class MockedSession(session_class):

        def mocked_request(self, method, url, **kwargs):
            data = kwargs.get('data')

            if method == 'GET':
                if url == 'https://m.vk.com':
                    return response_class('<html><form method="post" action="/login"></form></html>')

            elif method == 'POST':

                if url == '/login':
                    if data == {'email': user_login, 'pass': user_password}:
                        self.cookies['remixsid'] = 'REMIX-SID'

                    return response_class(url='/login')

                elif url == 'https://oauth.vk.com/authorize':
                    return response_class(url='/ANY#access_token={}'.format(access_token))

            raise NotImplementedError

    monkeypatch.setattr('requests.Session', MockedSession)


@pytest.mark.skip
def test_login(user_login, user_password, app_id, scope, access_token):

    api = vk.API(user_login=user_login, user_password=user_password, app_id=app_id, scope=scope)
    assert 'access_token' not in api._session.method_default_params

    api._session.update_access_token()
    assert api._session.method_default_params.get('access_token') == access_token


def test_interactive_mixin(monkeypatch):
    mixin = InteractiveMixin()

    monkeypatch.setattr(sys, 'stdin', StringIO('test_login_321'))
    assert mixin.user_login == 'test_login_321'

    mixin.user_login = None
    assert mixin.user_login == 'test_login_321'

    monkeypatch.setattr(getpass, 'getpass', lambda *args, **kwargs: '123_test_password')  # noqa: U100
    assert mixin.user_password == '123_test_password'

    monkeypatch.setattr(sys, 'stdin', StringIO('test_access_token'))
    assert mixin.access_token == 'test_access_token'

    monkeypatch.setattr(sys, 'stdin', StringIO('SuperCaptcha'))
    assert mixin.get_captcha_key('http://example.com') == 'SuperCaptcha'

    monkeypatch.setattr(sys, 'stdin', StringIO('123789456'))
    assert mixin.get_auth_check_code() == '123789456'
