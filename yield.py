def yield_func():
    _list = [i for i in range(3)]
    for i in _list:
        yield i*i
    
    _long_list=[2*i for i in range(10)]
    for i in _long_list:
        yield i*10


a = yield_func()
b = [item for item in a]
print b