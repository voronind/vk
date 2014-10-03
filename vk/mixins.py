

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
    
    def auth_code_is_needed(self, content, session):
        curhash = re.findall("'/al_login\.php'. \{act: 'a_authcheck_sms', hash: '(.+?)'", response.content)
        code_data = {
            'act': 'a_authcheck_code',
            'hash': curhash[0],
            'code': self.get_auth_code()
        } 
        response = session.post(u"https://vk.com/al_login.php", code_data)
    
        def get_auth_code(self):
            return input("get 2-auth code: ")    