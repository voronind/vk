import time

import pytest

import vk
from vk.exceptions import VkAuthError


class TestVersion():

    def test_missed_version(self):
        """
        Missed version on API instance
        """
        api = vk.API()
        with pytest.raises(VkAuthError):
            api.getServerTime()

    def test_version_in_API_instance(self, api):
        assert api.getServerTime()

    def test_version_in_method(self, access_token, v):
        api = vk.API(access_token=access_token)
        assert api.getServerTime(v=v)


def test_default_arg(mock_requests_session):
    api = vk.API(lang='language', v='v')

    api.some_method()
    assert api._session.requests_session.last_request.data.lang == 'language'

    api.some_method(lang='redefined-language')
    assert api._session.requests_session.last_request.data.lang == 'redefined-language'


class TestTrueAPI():

    def test_get_server_time(self, api):
        """
        Get server time
        """
        vk_server_time = api.getServerTime()
        assert abs(time.time() - vk_server_time) < 5 * 60

    def test_durov(self, access_token, v):
        """
        Get users
        """
        api = vk.API(access_token=access_token, v=v, lang='en')
        profiles = api.users.get(user_id=1)
        assert profiles[0]['last_name'] == 'Durov'


class TestAPI():

    def test_using_version(self):
        pass
