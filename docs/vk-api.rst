
vk.com API
==========

To use vk.com API you need registered app and login in this social network.
vk.com developers guide: https://vk.com/dev/main

1. Sign up in social network.
2. Go to https://vk.com/dev/standalone and create new app. Choose name and select **standalone** type.
3. Remember app id.
4. Use app id, list of required permissions and user credentials to get access token.
5. Use this access token to make method requests. List of all: https://vk.com/dev/methods. Some methods don't require access token.

Making API request
------------------

To make request to vk.com API we need send GET or POST HTTP request to address
https://api.vk.com/method/-method-name with params of specific method and access token.
