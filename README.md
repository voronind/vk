# vk | python vk.com API wrapper

[![Maintanance](https://img.shields.io/maintenance/yes/2022?style=flat-square)](https://github.com/voronind/vk/commits/master)
[![PyPI](https://img.shields.io/pypi/pyversions/vk?style=flat-square)](https://pypi.org/project/vk/)
[![GitHub CI](https://img.shields.io/github/workflow/status/voronind/vk/Check/master?style=flat-square)](https://github.com/voronind/vk/actions)
[![Codecov](https://img.shields.io/codecov/c/github/voronind/vk?style=flat-square)](https://codecov.io/gh/voronind/vk)
[![Docs](https://img.shields.io/readthedocs/vk?style=flat-square)](https://vk.readthedocs.io/en/latest/)

This is a vk.com (the largest Russian social network) python API wrapper. <br>
The goal is to support all API methods (current and future) that can be accessed from server.


## Quickstart


### Install

```bash
pip install vk
```


### Usage

```python
>>> import vk
>>> api = vk.API(access_token='...')
>>> api.users.get(user_ids=1)
[{'first_name': 'Pavel', 'last_name': 'Durov', 'id': 1}]
```

See official VK [documentation](https://dev.vk.com/method) for detailed API guide.


## More info

Read full documentation on [Read the Docs](https://vk.readthedocs.org)
