from enum import IntEnum


class ErrorCodes(IntEnum):
    """Enumeration object of VK API error codes. See `official documentation
    <https://dev.vk.com/reference/errors>`__ for more details
    """

    AUTHORIZATION_FAILED = 5    #: Invalid access token
    PERMISSION_IS_DENIED = 7    #: No rights to perform this action
    CAPTCHA_NEEDED = 14         #: Need to enter the code from the image (Captcha)
    ACCESS_DENIED = 15          #: No access to call this method
    INVALID_USER_ID = 113       #: Invalid user ID or user deactivated


class VkException(Exception):
    """Base exception for this module
    """
    pass


class VkAuthError(VkException):
    pass


class VkAPIError(VkException):
    """Class to represent a VK API error

    Args:
        error_data (dict): Parsed JSON object of error

    Attributes:
        method (Union[str, None]): The method whose call resulted in an error.
            Relevant only for errors that occurred during the *execute* method
        code (int): Error code. To conveniently determine the type of error, you
            can use :class:`vk.exceptions.ErrorCodes` enumeration class
        message (str): A message explaining the nature and/or cause of the error
        request_params (dict): Dictionary (param-value) of request parameters that
            were passed to the API method
        redirect_uri (Union[str, None]): The link you need to click to pass validation.
            *None* for all errors except 17
        captcha_sid (Union[str, None]): Captcha SID. *None* for all errors except 14
        captcha_img (Union[str, None]): Link to the image to be solved. *None* for all
            errors except 14
    """
    __slots__ = (
        'error', 'code', 'message', 'request_params', 'redirect_uri', 'captcha_sid', 'captcha_img'
    )

    def __init__(self, error_data):
        super(VkAPIError, self).__init__()

        self.method = error_data.get('method')
        self.code = error_data['error_code']
        self.message = error_data['error_msg']
        self.request_params = self._get_pretty_request_params(error_data)

        self.redirect_uri = error_data.get('redirect_uri')

        self.captcha_sid = error_data.get('captcha_sid')
        self.captcha_img = error_data.get('captcha_img')

    @staticmethod
    def _get_pretty_request_params(error_data):
        return {
            param['key']: param['value']
            for param in error_data.get('request_params', ())
        }

    def is_access_token_incorrect(self):
        return self.code in (ErrorCodes.AUTHORIZATION_FAILED, ErrorCodes.ACCESS_DENIED)

    def is_captcha_needed(self):
        return self.code == ErrorCodes.CAPTCHA_NEEDED

    def __str__(self):
        error_message = f'{self.code}. {self.message}. request_params = {self.request_params}'
        if self.redirect_uri:
            error_message += f',\nredirect_uri = "{self.redirect_uri}"'
        return error_message
