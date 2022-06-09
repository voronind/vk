vk.com API
==========


.. _`Getting access`:

Getting access
--------------

To use `vk.com <vk.com>`__ API you need an access token. There are several types of tokens, and the `official documentation <https://dev.vk.com/api/access-token/getting-started>`__ describes the process of obtaining each of them well. Based on our experience, we can offer you the fastest way to get a token - from the official application

Steps:

1. Sign up in social network
2. Go to https://vkhost.github.io and choose any application (I prefer vk.com)
3. Grant access to your account and copy *access_token* parameter from URL

Pros:
    - You can use methods that are prohibited by unofficial applications (*messages* section for example)
Cons:
    - The token has a certain lifetime (~12 hours)


.. _`Making API request`:

Making API request
------------------

To make request to vk.com API we need send GET or POST HTTP request to address https://api.vk.com/method/METHOD with parameters of specific method, access token, version and other parameters (see `official documentation <https://dev.vk.com/api/api-requests>`__ for more details). This module is needed in order to protect you from raw HTTP requests and provide a convenient interface for making requests.
