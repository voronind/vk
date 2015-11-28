# coding=utf8

import os
import sys
import time

import unittest

import vk
from vk.exceptions import VkAPIError
import vk.utils as utils

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# copy to test_props.py and fill it
USER_LOGIN = ''         # user email or phone number
USER_PASSWORD = ''      # user password
APP_ID = None             # aka API/Client ID

# from vk.settings import USER_LOGIN, USER_PASSWORD, APP_ID

import sys
import os.path as op


FIXTURES_PATH = '/'.join([op.abspath(op.dirname(__file__)), 'fixtures'])


def get_fixture(filename):
    file_path = '/'.join([FIXTURES_PATH, filename])
    with open(file_path) as fd:
        return fd.read()


class UtilsTestCase(unittest.TestCase):
    def test_stringify(self):
        self.assertEqual({1: 'str,str2'}, utils.stringify_values({1: ['str', 'str2']}))

    def test_stringify_2(self):
        self.assertEqual({1: u'str,стр2'}, utils.stringify_values({1: ['str', u'стр2']}))

    def test_stringify_3(self):
        self.assertEqual({1: u'стр,стр2'}, utils.stringify_values({1: [u'стр', u'стр2']}))

    def test_parse_url_query_params(self):
        resp_url = 'https://m.vk.com/login.php?act=security_check&to=&al_page='
        params = utils.parse_url_query_params(resp_url)
        self.assertEqual(params['act'], 'security_check')
        # self.assertEqual(params['to'], '')
        # self.assertEqual(params['al_page'], '')

        resp_url = '/login.php?act=security_check&to=&hash=4b07a4650e9f22038b'
        params = utils.parse_url_query_params(resp_url)
        self.assertEqual(params['act'], 'security_check')
        self.assertEqual(params['hash'], '4b07a4650e9f22038b')

    def test_get_form_action(self):
        html = get_fixture('require_phone_num_resp.html')
        form = utils.get_form_action(html)
        self.assertEqual(
            form, '/login.php?act=security_check&to=&hash=4b07a4650e9f22038b')


class VkTestCase(unittest.TestCase):
    def setUp(self):
        self.vk_api = vk.API.create_api(lang='ru')

    def test_get_server_time(self):
        time_1 = time.time() - 1
        time_2 = time_1 + 10
        server_time = self.vk_api.getServerTime()
        self.assertTrue(time_1 <= server_time <= time_2)

    def test_get_server_time_via_token_api(self):
        time_1 = time.time() - 1
        time_2 = time_1 + 20
        server_time = self.vk_api.getServerTime()
        self.assertTrue(time_1 <= server_time <= time_2)

    def test_get_profiles_via_token(self):
        profiles = self.vk_api.users.get(user_id=1)
        self.assertEqual(profiles[0]['last_name'], u'Дуров')

    def test_users_search(self):
        request_opts = dict(
            city=2,
            age_from=18,
            age_to=50,
            offset=0,
            count=1000,
            fields=['screen_name'])

        # Expect api error because search method requires access token
        with self.assertRaises(VkAPIError) as err:
            resp = self.vk_api.users.search(**request_opts)
            self.assertIsNone(resp)
            self.assertIn('no access_token passed', str(err))

        # Create token-based API
        api = vk.API.create_api(
            app_id=APP_ID, login=USER_LOGIN, password=USER_PASSWORD)
        resp = api.users.search(**request_opts)
        total_num, items = resp[0], resp[1:]
        self.assertIsInstance(total_num, int)
        for item in items:
            self.assertIsInstance(item, dict)
            self.assertIn('screen_name', item)

    def test_get_friends(self):
        items = self.vk_api.friends.get(
            fields="nickname,city,can_see_all_posts",
            user_id=1)
        self.assertIsInstance(items, list)
        for item in items:
            if 'deactivated' in item:
                # skip deactivated users, they don't have extra fields
                continue
            self.assertIsInstance(item, dict)
            self.assertIn('city', item)
            self.assertIn('user_id', item)
            self.assertIn('can_see_all_posts', item)


class VkApiInstanceTest(unittest.TestCase):
    def test_create_api_without_token(self):
        api = vk.API.create_api()
        self.assertIsInstance(api, vk.API)
        self.assertIsNone(api._session.auth_api._access_token)

    def test_create_api_with_token(self):
        api = vk.API.create_api(
            app_id=APP_ID, login=USER_LOGIN, password=USER_PASSWORD)
        self.assertIsInstance(api, vk.API)

        # Check that we have got access token on init
        self.assertIsInstance(api._session.auth_api._access_token, str)


class VkTestInteractive(unittest.TestCase):
    def setUp(self):
        self.vk_api = vk.API.create_api(
            app_id=APP_ID, login=USER_LOGIN, password=USER_PASSWORD)

if __name__ == '__main__':
    unittest.main()
