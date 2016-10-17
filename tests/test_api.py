import time

import pytest

import vk


class TestVersion():

    def test_missed_version(self):
        """
        Missed version on API instance
        """
        api = vk.API()
        with pytest.raises(AssertionError):
            api.getServerTime()

    def test_version_in_API_instance(self, v):
        api = vk.API(v=v)
        assert api.getServerTime()

    def test_version_in_method(self, v):
        api = vk.API()
        assert api.getServerTime(v=v)


def test_default_arg(mock_requests_session):
    api = vk.API(lang='language', v='v')

    api.some_method()
    assert api.session.requests_session.last_request.data.lang == 'language'

    api.some_method(lang='redefined-language')
    assert api.session.requests_session.last_request.data.lang == 'redefined-language'


class TestTrueAPI():

    def test_get_server_time(v):
        """
        Get server time
        """
        api = vk.API(v=v)
        vk_server_time = api.getServerTime()
        assert abs(time.time() - vk_server_time) < 5 * 60

    def test_durov(v):
        """
        Get users
        """
        api = vk.API(v=v, lang='en')
        profiles = api.users.get(user_id=1)
        assert profiles[0]['last_name'] == 'Durov'


class TestAPI():

    def test_using_version(self):
        pass
