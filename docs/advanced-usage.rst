Advanced usage
==============


Errors handling
---------------

The easiest way to catch an error is using the *try-except* statement:

.. code-block:: python

    import vk
    from vk.exceptions import VkAPIError

    api = vk.API(access_token='Invalid access token')

    try:
        user = api.users.get(user_ids=1)
    except VkAPIError as e:
        print(e)

    # 5. User authorization failed: invalid access_token (4).. request_params = { ... }


Class :class:`vk.exceptions.VkAPIError` provides basic functionality for error processing


.. autoexception:: vk.exceptions.VkAPIError
    :members:


For a simpler definition of the type of error, you can use the :class:`vk.exceptions.ErrorCodes`


.. autoclass:: vk.exceptions.ErrorCodes
    :members:


.. code-block:: python

    import vk
    from vk.exceptions import ErrorCodes, VkAPIError

    api = vk.API(access_token='Invalid access token')

    try:
        user = api.users.get(user_ids=1)
    except VkAPIError as e:
        print(e.code == ErrorCodes.AUTHORIZATION_FAILED)

    # True


Global errors handling
----------------------

Some errors can occur in any request and handling them every time the method called will be a very difficult task, so you can define a global handler for each error

.. automethod:: vk.session.APIBase.on_api_error

For some popular errors, the :class:`vk.session.API` already has its own handlers, for example, for processing captcha:

.. automethod:: vk.session.API.on_api_error_14

.. automethod:: vk.session.API.get_captcha_key


Interactive
-----------

.. autoclass:: vk.session.InteractiveMixin
