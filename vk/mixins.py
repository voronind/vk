

try:
    input = raw_input  # Python 2
except NameError:
    pass


class EnterCaptchaMixin(object):

    def captcha_is_needed(self, error_data, method_name, **method_kwargs):
        captcha_sid = error_data.get('captcha_sid')
        captcha_img = error_data.get('captcha_img')

        print('Captcha URL: {}'.format(captcha_img))
        captcha_key = input('Enter captcha text: ')

        method_kwargs['captcha_sid'] = captcha_sid
        method_kwargs['captcha_key'] = captcha_key
        return self(method_name, **method_kwargs)
