Python vk.com API wrapper
=========================

[![PyPI](https://img.shields.io/pypi/pyversions/vk.svg)](https://pypi.org/project/vk/ "Latest version on PyPI")
[![Travis](https://travis-ci.com/voronind/vk.svg?branch=master)](https://travis-ci.com/voronind/vk "Travis CI")
[![Docs](https://readthedocs.org/projects/vk/badge/?version=stable)](https://vk.readthedocs.io/en/latest/ "Read the docs")
[![codecov](https://codecov.io/gh/voronind/vk/branch/master/graph/badge.svg)](https://codecov.io/gh/voronind/vk "Coverage")

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
