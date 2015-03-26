=========================
vk.com API Python wrapper
=========================

This is a vk.com (the largest Russian social network)
python API wrapper. The goal is to support all API methods (current and future)
that can be accessed from server.

Quickstart
==========

Install
-------

.. code:: bash

    pip install vk

Usage
-----

.. code:: python

    >>> import vk
    >>> vkapi = vk.API()
    >>> vkapi.users.get(user_ids='1')
    [{'first_name': 'Павел', 'last_name': 'Дуров', 'id': 1}]

See https://vk.com/dev/methods for detailed API guide.

More info
=========

`Read full documentation <http://vk.readthedocs.org>`_
