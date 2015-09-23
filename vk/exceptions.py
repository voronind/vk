
# API Error Codes
AUTHORIZATION_FAILED = 5    # Invalid access token
CAPTCHA_IS_NEEDED = 14
ACCESS_DENIED = 15          # No access to call this method

class VkException(Exception):
    pass


class VkAuthError(VkException):
    pass


class VkAPIMethodError(VkException):
    __slots__ = ['error', 'code', 'message', 'request_params', 'redirect_uri']

    def __init__(self, error):
        super(VkAPIMethodError, self).__init__()
        self.error = error
        self.code = error.get('error_code')
        self.message = error.get('error_msg')
        self.request_params = error.get('request_params')
        self.redirect_uri = error.get('redirect_uri')

    def __str__(self):
        error_message = '{self.code}. {self.message}. request_params = {self.request_params}'.format(self=self)
        if self.redirect_uri:
            error_message += ',\nredirect_uri = "{self.redirect_uri}"'.format(self=self)
        return error_message
