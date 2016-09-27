import pytest

import vk


@pytest.fixture
def base_api():
    return vk.API()


@pytest.fixture
def user_login():
    return 'user-login'


@pytest.fixture
def user_password():
    return 'user-password'


@pytest.fixture
def api(user_login, user_password):
    return vk.API(user_login=user_login, user_password=user_password)
