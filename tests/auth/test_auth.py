import vk


def test_login(user_login, user_password, app_id, scope, access_token):

    api = vk.API()
    assert api.session.access_token == ''

    api.session.login(user_login, user_password, app_id, scope)
    assert api.session.access_token == access_token
