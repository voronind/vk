import os

import pytest


@pytest.fixture(scope='session')
def v():
    """
    Actual vk API version
    """
    return '5.131'


@pytest.fixture(scope='session')
def access_token():
    if os.getenv('VK_ACCESS_TOKEN'):
        return os.environ['VK_ACCESS_TOKEN']

    pytest.skip('VK_ACCESS_TOKEN env var not defined')
