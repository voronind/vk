
vk.com API
==========

To use vk.com API you need registered app and login in this social network.
vk.com developers guide: https://vk.com/dev/main

1. Sign up in social network.
2. Go to https://vk.com/dev/standalone and create new app. Choose name and select standalone type.
3. Remember app id.
4. User login and app id is used for getting access token
  auth_session = vk.AuthSession(app_id=APP_ID, user_login=USER_LOGIN, user_password=USER_PASSWORD)
  access_token, _ = auth_session.get_access_token()
  session = vk.Session(access_token=access_token)
  self.vk_api = vk.API(session, lang='ru')

5. After that you can use any API method: https://vk.com/dev/methods. Some methods don't require access token.
  print vk_api.users.get(user_ids=1)

Making API request
------------------

To make request to vk.com API we need send GET or POST HTTP request to address
https://api.vk.com/method/<method-name> with params of specific method and access token.
