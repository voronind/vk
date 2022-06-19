Usage
=====

API method request example
--------------------------

Several types of APIs are implemented in this module. Each of them is needed for certain purposes, but they are all united by the way of accessing the VK API. After initializing the class, you can call any method. Let's try to figure out what's going on here:

.. code-block:: python

    >>> import vk
    >>> api = vk.API(access_token='...', v='5.131')
    >>> print(api.users.get(user_ids=1))
    [{'id': 1, 'first_name': 'Павел', 'last_name': 'Дуров', ... }]


It gets user info with **user id** equal to **1**. :class:`vk.api.APINamespace` object is used to create API request and send it via original :class:`vk.session.API` class object (or another), which in turn, manages access token, sends API request, gets JSON response, parses and returns it.

| More formally, this forms the following POST request to the VK API:
| https://api.vk.com/method/users.get?user_ids=1&access_token=...&v=5.131


vk.API
------

.. autoclass:: vk.session.API


vk.UserAPI
----------

.. autoclass:: vk.session.UserAPI
    :members:


vk.CommunityAPI
---------------

.. autoclass:: vk.session.CommunityAPI
