
First request
=============

.. code:: python

    >>> import vk
    >>> api = vk.API(v=5)
    >>> api.users.get(user_id=1)
    [{'first_name': 'Pavel', 'last_name': 'Durov', 'id': 1}]


How it works
============

When we call

Need-request -> Check access token
If no token -> Try to get

Try to get -> If we have user_login and user_password -> Get token
Do-request

If bad access token -> self.access_token = None via self.on_bad_access_token
