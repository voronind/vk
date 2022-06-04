import pytest

from vk import API


@pytest.fixture
def api(access_token, v):
    return API(access_token, v=v, lang='en')


def test_durov(api):
    """
    Get users
    """
    users = api.users.get(user_id=1)
    assert users[0]['last_name'] == 'Durov'
