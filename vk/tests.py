# coding=utf8

import os
import sys
import time

import unittest
import vk
from vk.utils import HandyList, make_handy, HandyDict

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# copy to test_props.py and fill it
APP_ID = ''  # aka API/Client id

USER_LOGIN = ''  # user email or phone number
USER_PASSWORD = ''

from test_props import APP_ID, USER_LOGIN, USER_PASSWORD


class VkTestCase(unittest.TestCase):

    def setUp(self):
        self.vk_api = vk.API(APP_ID, USER_LOGIN, USER_PASSWORD)
        self.vk_token_api = vk.API(access_token=self.vk_api.access_token)

    def test_get_server_time(self):
        time_1 = time.time() - 1
        time_2 = time_1 + 10
        server_time = self.vk_api.getServerTime()
        self.assertTrue(time_1 <= server_time <= time_2)

    def test_get_server_time_via_token_api(self):
        time_1 = time.time() - 1
        time_2 = time_1 + 10
        server_time = self.vk_token_api.getServerTime()
        self.assertTrue(time_1 <= server_time <= time_2)

    def test_get_profiles_via_token(self):
        profiles = self.vk_api.users.get(user_id=1)
        profiles = make_handy(profiles)
        self.assertEqual(profiles.first.last_name, u'Дуров')


class HandyContainersTestCase(unittest.TestCase):

    def test_list(self):
        handy_list = make_handy([1, 2, 3])
        self.assertIsInstance(handy_list, HandyList)
        self.assertEqual(handy_list.first, 1)


    def test_handy_dict(self):
        handy_dict = make_handy({'key1': 'val1', 'key2': 'val2'})
        self.assertIsInstance(handy_dict, HandyDict)
        self.assertEqual(handy_dict.key1, 'val1')


if __name__ == '__main__':
    unittest.main()
