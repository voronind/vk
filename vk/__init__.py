
from vk.api import APISession as API

from vk.mixins import EnterCaptchaMixin


class EnterCaptchaAPI(EnterCaptchaMixin, API):
    pass

from vk.api import OAuthAPI

API = OAuthAPI
