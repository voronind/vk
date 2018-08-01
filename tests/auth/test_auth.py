from pytest import mark

import vk


@mark.skip()
def test_login(user_login, user_password, app_id, scope, access_token):

    api = vk.API(user_login=user_login, user_password=user_password, app_id=app_id, scope=scope)
    assert 'access_token' not in api._session.method_default_params

    api._session.update_access_token()
    assert api._session.method_default_params.get('access_token') == access_token
