# coding=utf8

import time


def test_get_server_time(base_api):
    vk_server_time = base_api.getServerTime()
    assert abs(time.time() - vk_server_time) < 60


def test_token_instance():
    pass


def test_users_get(base_api):
    profiles = base_api.users.get(user_id=1)
    assert profiles[0]['last_name'] == 'Durov'
