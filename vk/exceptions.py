
# API Error Codes
AUTHORIZATION_FAILED = 5    # Invalid access token
PERMISSION_IS_DENIED = 7
CAPTCHA_IS_NEEDED = 14
ACCESS_DENIED = 15          # No access to call this method
                            # User deactivated
INVALID_USER_ID = 113


class VkException(Exception):
    pass


class VkAuthError(VkException):
    pass


class VkAPIError(VkException):
    __slots__ = ['error', 'code', 'message', 'request_params', 'redirect_uri']

    CAPTCHA_NEEDED = 14
    ACCESS_DENIED = 15

    def __init__(self, error_data):
        super(VkAPIError, self).__init__()
        self.error_data = error_data
        self.code = error_data.get('error_code')
        self.message = error_data.get('error_msg')
        self.request_params = self.get_pretty_request_params(error_data)
        self.redirect_uri = error_data.get('redirect_uri')

    @staticmethod
    def get_pretty_request_params(error_data):
        request_params = error_data.get('request_params', ())
        request_params = {param['key']: param['value'] for param in request_params}
        return request_params

    def is_access_token_incorrect(self):
        return self.code == self.ACCESS_DENIED and 'access_token' in self.message

    def is_captcha_needed(self):
        return self.code == self.CAPTCHA_NEEDED

    @property
    def captcha_sid(self):
        return self.error_data.get('captcha_sid')

    @property
    def captcha_img(self):
        return self.error_data.get('captcha_img')

    def __str__(self):
        error_message = '{self.code}. {self.message}. request_params = {self.request_params}'.format(self=self)
        if self.redirect_uri:
            error_message += ',\nredirect_uri = "{self.redirect_uri}"'.format(self=self)
        return error_message
