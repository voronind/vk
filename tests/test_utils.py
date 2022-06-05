from vk.utils import censor_access_token, stringify, stringify_values


def test_stringify():
    assert stringify(['str', 'str2']) == 'str,str2'
    assert stringify(['str', 'стр2']) == 'str,стр2'
    assert stringify(['стр', 'стр2']) == 'стр,стр2'


def test_stringify_values():
    assert stringify_values({1: ['str', 'str2']}) == {1: 'str,str2'}
    assert stringify_values({2: ['str', 'стр2']}) == {2: 'str,стр2'}
    assert stringify_values({3: ['стр', 'стр2']}) == {3: 'стр,стр2'}


def test_censor_access_token():
    assert censor_access_token('abcdfoobartestwxyz') == 'abcd***wxyz'
    assert censor_access_token('1234toadfamapgplrkpea4321') == '1234***4321'
    assert censor_access_token('foobar') == '***'
