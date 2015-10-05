
First request
=============

.. code:: python

    >>> import vk
    >>> session = vk.Session()
    >>> api = vk.API(session)
    >>> api.users.get(user_ids=1)
    [{'first_name': 'Павел', 'last_name': 'Дуров', 'id': 1}]


How it works
============

When we call

Need-request -> Check access token
If no token -> Try to get

Try to get -> If we have user_login and user_password -> Get token
Do-request

If bad access token -> self.access_token = None via self.on_bad_access_token

Authorization
============
First request doesn't require login and password of user. If your methods required more access you need to authorize.
    APP_ID = '123456'

    USER_LOGIN = '79112345'

    USER_PASSWORD = 'blapassbla'
    
    auth_session = vk.AuthSession(app_id=APP_ID, user_login=USER_LOGIN, user_password=USER_PASSWORD)
    access_token, _ = auth_session.get_access_token()
    session = vk.Session(access_token=access_token)
    self.vk_api = vk.API(session, lang='ru')
    print vk_api.account.getAppPermissions(user_id='123456789')
    
In result you're getting a number. What it's mean you can see here https://vk.com/dev/permissions
