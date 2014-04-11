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
APP_SECRET = ''  # aka API/Client secret

USER_EMAIL = ''
USER_PASSWORD = ''

import test_props


class VkTestCase(unittest.TestCase):

    def setUp(self):
        self.vk_token_api = vk.API(test_props.APP_ID, test_props.USER_EMAIL, test_props.USER_PASSWORD)
        self.vk_secret_api = vk.API(test_props.APP_ID, app_secret=test_props.APP_SECRET)

    def test_get_server_time_via_token(self):
        time_1 = time.time() - 1
        time_2 = time_1 + 10
        server_time = self.vk_token_api.getServerTime()
        self.assertTrue(time_1 <= server_time <= time_2)

    def test_get_server_time_via_secret(self):
        time_1 = time.time() - 1
        time_2 = time_1 + 10
        server_time = self.vk_secret_api.getServerTime()
        self.assertTrue(time_1 <= server_time <= time_2)


    def test_get_profiles_via_token(self):
        profiles = self.vk_token_api.users.get(user_id=1)
        profiles = make_handy(profiles)
        self.assertEqual(profiles.first.last_name, u'Дуров')

    def test_get_profiles_via_secret(self):
        profiles = self.vk_secret_api.users.get(user_id=1)
        self.assertEqual(profiles[0]['last_name'], u'Дуров')


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
