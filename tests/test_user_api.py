from pytest import fixture, mark

import vk


@fixture
def user_login():
    return 'user-login'


@fixture
def user_password():
    return 'user-password'


@fixture
def app_id():
    return 'app-id'


@fixture
def scope():
    return 'scope'


@fixture(autouse=True)
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


@mark.skip
def test_login(user_login, user_password, app_id, scope, access_token):

    api = vk.API(user_login=user_login, user_password=user_password, app_id=app_id, scope=scope)
    assert 'access_token' not in api._session.method_default_params

    api._session.update_access_token()
    assert api._session.method_default_params.get('access_token') == access_token
