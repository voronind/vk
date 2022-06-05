from time import time

import pytest

from vk import API
from vk.exceptions import VkAPIError


def test_missed_v_param(access_token, v):
    """
    Missed version on API instance
    """
    api = API(access_token)

    with pytest.raises(VkAPIError, match=r'8\. Invalid request: v is required'):
        api.getServerTime()

    assert api.getServerTime(v=v) > time() - 10


def test_incorrect_token(v):
    """
    Incorrect token on API instance
    """
    api = API('?', v=v)

    with pytest.raises(VkAPIError, match=r'5\. User authorization failed') as exc_info:
        api.getServerTime()

    exc = exc_info.value

    assert exc.is_access_token_incorrect()
    assert not exc.is_captcha_needed()
    assert exc.captcha_sid is None
    assert exc.captcha_img is None
