import os
import time

from pytest import fixture, raises

from vk import ServiceAPI
from vk.exceptions import VkAPIError


@fixture('session')
def service_token():
    return os.environ['TEST_APP_SERVICE_TOKEN']


@fixture
def service_api(service_token, v):
    return ServiceAPI(service_token, v=v, lang='en')


def test_v_param(service_token, v):
    """
    Missed version on API instance
    """
    service_api = ServiceAPI(service_token)

    with raises(VkAPIError, match='8\. Invalid request: v \(version\) is required'):
        service_api.getServerTime()

    assert service_api.getServerTime(v=v) > time.time() - 10


def test_durov(service_api):
    """
    Get users
    """
    users = service_api.users.get(user_id=1)
    assert users[0]['last_name'] == 'Durov'
