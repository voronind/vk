Python vk.com API wrapper
=========================

This is a vk.com (the largest Russian social network)
python API wrapper. The goal is to support all API methods (current and future)
that can be accessed from server.

Quickstart
==========

Install
-------

```console
pip install vk
```

Usage
-----

```python
>>> import vk
>>> session = vk.Session()
>>> api = vk.API(session)
>>> api.users.get(user_ids=1)
[{'first_name': 'Pavel', 'last_name': 'Durov', 'id': 1}]
```

See https://vk.com/dev/methods for detailed API guide.

More info
=========

Read full documentation https://vk.readthedocs.org
