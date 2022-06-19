import logging

import pytest

from vk import API


@pytest.fixture
def api(access_token, v):
    return API(access_token, v=v, lang='en')


def test_durov(api):
    users = api.users.get(user_ids=1)
    assert users[0]['last_name'] == 'Durov'


def test_execute(caplog, api):
    with caplog.at_level(logging.WARNING, logger='vk'):
        api.execute(code='var x = API.storage.get(); '
                         'return API.users.get({user_ids: 1});')

    assert len(caplog.records) == 1

    log = caplog.records[0]
    assert log.levelno == logging.WARNING
    assert 'Execute "storage.get" error' in log.message
