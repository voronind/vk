import vk


def test_login(user_login, user_password, app_id, scope, access_token):

    api = vk.API()
    assert api._session.access_token == ''

    api._session.login(user_login, user_password, app_id, scope)
    assert api._session.access_token == access_token
