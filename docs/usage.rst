
Usage
=====

API method request example
--------------------------

Get user info with **user id** equal to 1.

`vk.API` class object is used to create API request and send it via `vk.Session` class object.
Session object is used by API object to manage access token, send API request, get JSON response,
parse and return it.

API object `api` attribute getting defines vk.com API method name.
Call of gotten method sends request and returns parsed JSON response.
Keyword args becomes specified method params.

This example will send POST request to https://api.vk.com/method/users.get with "user_ids=1" query string.

vk.API
------

`vk.API` gets Session or subclass object as first argument,
\**kwargs as API method default args and `timeout` kwarg.
See https://vk.com/dev/api_requests for full list of common args.
The most useful is `v` - API version and `lang` - language of responses.

All API methods that can be called from server should be supported.
See https://vk.com/dev/methods for detailed API help.


vk.Session
----------

`vk.Session` gets optional `access_token` argument.
It will send access token with every API request after first "Autorization failed" error.
`Session` class can use only ready access token and raises error if can't get it.


vk.AuthSession
--------------

It's `vk.Session` subclass. Can get access token using app id and user credentials.


Debugging
---------

To understand that happens you can enable debug mode.

.. code:: python

    vk.logger.setLevel('DEBUG')

`vk.logger` is Python standard library `logging.Logger` instance.
