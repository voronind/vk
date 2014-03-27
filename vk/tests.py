# coding=utf8

import os
import sys
import time

import unittest
import vk

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# copy to test_props.py and fill it
APP_ID = ''  # aka API id
APP_SECRET = ''  # aka API secret

USER_EMAIL = ''
USER_PASSWORD = ''

import test_props



class VkTestCase(unittest.TestCase):

    def setUp(self):
        self.vk_token_api = vk.API(test_props.APP_ID, test_props.USER_EMAIL, test_props.USER_PASSWORD)
        self.vk_secret_api = vk.API(test_props.APP_ID, app_secret=test_props.APP_SECRET)


    def test_get_server_time_via_token(self):
        self._test_get_server_time(self.vk_token_api)

    def test_get_server_time_via_secret(self):
        self._test_get_server_time(self.vk_secret_api)

    def _test_get_server_time(self, vk_api):
        time_1 = time.time() - 1
        time_2 = time_1 + 10
        server_time = vk_api.getServerTime()
        self.assertTrue(time_1 <= server_time <= time_2)


    def test_get_profiles_via_token(self):
        self.assertEqual(self.get_first_profile(self.vk_token_api), u'Дуров')

    def test_get_profiles_via_secret(self):
        self.assertRaises(vk.VkAPIError, lambda: self.get_first_profile(self.vk_secret_api))

    def get_first_profile(self, vk_api):
        profiles = vk_api.getProfiles(uids=1)
        return profiles[0]['last_name']


if __name__ == '__main__':
    unittest.main()
