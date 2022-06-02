import os
import time

import pytest

from vk import API
from vk.exceptions import VkAPIError


@pytest.fixture(scope='session')
def service_token():
    return os.environ['TEST_APP_SERVICE_TOKEN']


@pytest.fixture
def api(service_token, v):
    return API(service_token, v=v, lang='en')


@pytest.mark.skip
def test_v_param(service_token, v):
    """
    Missed version on API instance
    """
    api = API(service_token)

    with pytest.raises(VkAPIError, match=r'8\. Invalid request: v \(version\) is required'):
        api.getServerTime()

    assert api.getServerTime(v=v) > time.time() - 10


@pytest.mark.skip
def test_durov(api):
    """
    Get users
    """
    users = api.users.get(user_id=1)
    assert users[0]['last_name'] == 'Durov'
