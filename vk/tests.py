# coding=utf8

import os
import sys
import time

import unittest

import vk

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# copy to test_props.py and fill it
USER_LOGIN = ''         # user email or phone number
USER_PASSWORD = ''      # user password
APP_ID = ''             # aka API/Client ID

from test_props import USER_LOGIN, USER_PASSWORD, APP_ID


class VkTestCase(unittest.TestCase):

    def setUp(self):
        auth_session = vk.AuthSession(app_id=APP_ID, user_login=USER_LOGIN, user_password=USER_PASSWORD)
        access_token, _ = auth_session.get_access_token()

        session = vk.Session(access_token=access_token)
        self.vk_api = vk.API(session, lang='ru')

    def test_get_server_time(self):
        time_1 = time.time() - 1
        time_2 = time_1 + 10
        server_time = self.vk_api.getServerTime()
        self.assertTrue(time_1 <= server_time <= time_2)

    def test_get_server_time_via_token_api(self):
        time_1 = time.time() - 1
        time_2 = time_1 + 10
        server_time = self.vk_api.getServerTime()
        self.assertTrue(time_1 <= server_time <= time_2)

    def test_get_profiles_via_token(self):
        profiles = self.vk_api.users.get(user_id=1)
        self.assertEqual(profiles[0]['last_name'], u'Дуров')


if __name__ == '__main__':
    unittest.main()
