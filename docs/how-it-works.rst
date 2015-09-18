
First request
=============

.. code:: python

    >>> import vk
    >>> vkapi = vk.API()
    >>> vkapi.users.get(user_ids='1')
    [{'first_name': 'Павел', 'last_name': 'Дуров', 'id': 1}]


How it works
============

When we call

Need-request -> Check access token
If no token -> Try to get

Try to get -> If we have user_login and user_password -> Get token
Do-request

If bad access token -> self.access_token = None via self.on_bad_access_token
