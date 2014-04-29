================================
vk.com API Python wrapper
================================

This is a vk.com (aka vkontakte.ru, largest Russian social network)
python API wrapper. The goal is to support all API methods (current and future)
that can be accessed from server.

Install
================

.. code:: bash

    pip install vk

Get access
================

.. code:: python

    import vk
    
    # Use app id, user email/phone and password for access to API
    vkapi = vk.API('my_app_id', 'user_login', 'user_password')
    # or ready access token
    vkapi = vk.API(access_token='access_token')
    
Make requests
===============
.. code:: python

    >>> vkapi.getServerTime()
    1395870238
    >>> profiles = vkapi.users.get(user_id=1)
    >>> profiles[0]['last_name']
    'Дуров'
    >>> # alternative syntax
    >>> profiles = vkapi('users.get', user_id=1)
    >>> profiles[0]['last_name']
    'Дуров'

All API methods that can be called from server should be supported.

See https://vk.com/dev/methods for detailed API help.
