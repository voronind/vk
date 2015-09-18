
Auth flow
=========


API(access_token)
.get_access_token:
  if token return token
  if no token raise Exception

AuthAPI(app_id, user_login, user_password)
.get_access_token:
    .get_user_login
    .get_user_password
    return access_token

InteractiveAPI()
.get_user_name
.get_user_password
.get_access_token


1. Start
  access_token = any
  needed = False

2. Incorrect access token. Drop
  access_token = False
  needed = True

3. Get-new
  access_token = get_new():
    True:
      needed = False
    False:
      needed = False
