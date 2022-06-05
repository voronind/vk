from io import StringIO

from vk.session import InteractiveMixin


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
