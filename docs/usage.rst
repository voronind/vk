
Usage
=====

Making first request
--------------------

Get user info with id=1.

 .. code:: python

    >>> import vk
    >>> session = vk.Session()
    >>> api = vk.API(session)
    >>> api.users.get(user_ids=1)
    [{'first_name': 'Pavel', 'last_name': 'Durov', 'id': 1}]

API object `api` uses to make request to vk.com API. Attributes converts to API method name.
Object method keyword args converts to method params. As result we will get POST request to
https://api.vk.com/method/users.get with "user_ids=1" param.
Instance of Session class is used to manage access token and send API requests.

API object
----------

`vk.API` gets Session class or subclass as first argument,
**kwargs as API method default args and timeout kwarg.

See https://vk.com/dev/api_requests for full list of common args.
The most useful is `v` - API version and `lang` - language of responses.

 .. code:: python

    ...
    assert isinstance(session, vk.Session)
    api = vk.API(session, timeout=10, **method_default_args)

After that we can use `api` attribute call to make requests to API.
All API methods that can be called from server should be supported.
See https://vk.com/dev/methods for detailed API help.

Session object
--------------

Session object applies access token as optional argument.

.. code:: python

    session = vk.Session(access_token=None)

| Session object sends API requests. If access token is present, it's added to method args.
| If request ends with access error, `session` tries to get actual access token.
| `Session` class can use only ready access token and raises error on corrupt access token. \
| `AuthSession` class can use user credentials and app id to get access token.
| `InteractiveSession` class can ask user access_token, user login, password and other things.
