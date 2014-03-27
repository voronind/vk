==============================
vk - vk.com API Python wrapper
==============================

This is a vk.com (aka vkontakte.ru, largest Russian social network)
python API wrapper. The goal is to support all API methods (current and future)
that can be accessed from server.

Installation
============

::

    $ pip install vk

Usage
=====

::

    >>> import vk

Login via 1 of 3 ways::

    >>> vk_api = vk.API('my_app_id', 'user_email', 'user_password')  # or
    >>> vk_api = vk.API(access_token='access_token')  # or
    >>> vk_api = vk.API('my_app_id', app_secret='my_app_secret')  # deprecated by vk.com

Make requests::

    >>> vk_api.getServerTime()
    1395870238
    >>> profiles = vk_api.getProfiles(uids=1)
    >>> profiles[0]['last_name']
    Дуров
    >>> # alternative syntax
    >>> profiles = vk_api('getProfiles', uids=1)
    >>> profiles[0]['last_name']
    Дуров

All API methods that can be called from server should be supported.

See https://vk.com/developers.php?id=-1_11226273 for detailed API help.
