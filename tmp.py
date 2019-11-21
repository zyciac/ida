import write_log

def yield_func():
    _list = [i for i in range(3)]
    for i in _list:
        yield i*i


def prnt(stuff):
    stuff = list(stuff)
    print stuff

class A(object):

    def __init__(self):
        self.a = 1
    def getA(self):
        print self.a

    # def getAG(self):
    #     print aG

class B(A):
    def __init__(self):
        A.__init__(self)
        self.b  = 0

    def getB(self):
        print self.b

a = A()
b = B()

b.getA()

