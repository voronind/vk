from vk.api import APISession as API
from vk.api import VkError, VkAuthorizationError, VkAPIMethodError

from vk.mixins import EnterCaptchaMixin


class EnterCaptchaAPI(EnterCaptchaMixin, API):
    pass
