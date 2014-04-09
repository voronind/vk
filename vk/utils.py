

class HandyList(list):

    @property
    def first(self):
        if self:
            return self[0]
        else:
            return None

    def __getitem__(self, item):
        obj = list.__getitem__(self, item)

        if type(obj) == dict:
            return HandyDict(obj)

        return obj


class HandyDict(dict):

    def __getattr__(self, item):
        return self[item]


def make_handy(obj):

    if type(obj) == list:
        return HandyList(obj)

    elif type(obj) == dict:
        return HandyDict(obj)

    return obj
