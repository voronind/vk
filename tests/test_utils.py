# coding=utf8

from vk.utils import stringify_values


def test_stringify():
    assert stringify_values({1: ['str', 'str2']}) == {1: 'str,str2'}
    assert stringify_values({1: ['str', u'стр2']}) == {1: u'str,стр2'}
    assert stringify_values({1: [u'стр', u'стр2']}) == {1: u'стр,стр2'}
