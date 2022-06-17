import os

import pytest

const_fixtures = {
    'v': '5.131',
    'lang': 'en'
}

env_fixtures = (
    'VK_ACCESS_TOKEN',
    'VK_USER_LOGIN',
    'VK_USER_PASSWORD'
)


def const_fixture(value):

    @pytest.fixture(scope='session')
    def fixture():
        return value

    return fixture


def env_fixture(var):

    @pytest.fixture(scope='session')
    def fixture():
        if os.getenv(var):
            return os.environ[var]

        pytest.skip(f'{var} env var not defined')  # pragma: no cover

    return fixture


for name, value in const_fixtures.items():
    globals()[name] = const_fixture(value)

for var in env_fixtures:
    globals()[var[var.startswith('VK_') * 3:].lower()] = env_fixture(var)
