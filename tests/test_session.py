import logging
from io import StringIO

import pytest

from vk import API, UserAPI
from vk.exceptions import VkAuthError
from vk.session import InteractiveMixin


@pytest.fixture
def api(access_token, v, lang):
    return API(access_token, v=v, lang=lang)


@pytest.fixture
def user_api(user_login, user_password, v, lang):
    return UserAPI(user_login, user_password, v=v, lang=lang)


def test_api_durov(api):
    users = api.users.get(user_ids=1)
    assert users[0]['last_name'] == 'Durov'


def test_execute(caplog, api):
    with caplog.at_level(logging.WARNING, logger='vk'):
        api.execute(code='var x = API.storage.get(); '
                         'return API.users.get({user_ids: 1});')

    assert len(caplog.records) == 1

    log = caplog.records[0]
    assert log.levelno == logging.WARNING
    assert 'Execute "storage.get" error' in log.message


def test_user_api_durov(user_api):
    users = user_api.users.get(user_ids=1)
    assert users[0]['last_name'] == 'Durov'


def test_user_api_invalid_credentials():
    with pytest.raises(VkAuthError, match=r'Login error \(e.g. incorrect password\)'):
        UserAPI('foo', 'bar')


def test_interactive_mixin(monkeypatch):
    mixin = InteractiveMixin()

    monkeypatch.setattr('sys.stdin', StringIO('test_login_321'))
    assert mixin.user_login == 'test_login_321'

    mixin.user_login = None
    assert mixin.user_login == 'test_login_321'

    monkeypatch.setattr('getpass.getpass', lambda *args, **kwargs: '123_test_password')  # noqa: U100
    assert mixin.user_password == '123_test_password'

    monkeypatch.setattr('sys.stdin', StringIO('test_access_token'))
    assert mixin.access_token == 'test_access_token'

    monkeypatch.setattr('sys.stdin', StringIO('SuperCaptcha'))
    assert mixin.get_captcha_key('http://example.com') == 'SuperCaptcha'

    monkeypatch.setattr('sys.stdin', StringIO('123789456'))
    assert mixin.get_auth_check_code() == '123789456'


def test_interactive_mixin_mixed(monkeypatch, access_token, v, lang):
    class InteractiveAPI(InteractiveMixin, API):
        pass

    monkeypatch.setattr('sys.stdin', StringIO(access_token))

    api = InteractiveAPI(v=v, lang=lang)

    users = api.users.get(user_ids=1)
    assert users[0]['last_name'] == 'Durov'
