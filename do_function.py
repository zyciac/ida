import idautils
import idc
import idaapi
import ida_funcs
import idc_bc695

import re
import datetime
import inspect
import os

class idaObject(object):
    ''' 
        create general class for idaObject 
        To Be complete
    '''
    # _functions = []
    # _funInNames = []
    # _funNotInNames = []

    def __init__(self):
        self._functions = self.__initFunctionList()
        self._funInNames = self.__initFunctionsInNames()
        self._funNotInNames = self.__initFunctionsNotInName()
        
    def __initFunctionList(self):
        return list(idautils.Functions())

    def __initFunctionsInNames(self):
        nameList = idautils.Names()
        addrInNameList = []
        for addr_name_pairs in nameList:
            addrInNameList.append(addr_name_pairs[0])
        return [funcaddr for funcaddr in self._functions if funcaddr in addrInNameList] 

    def __initFunctionsNotInName(self):
        return [funcaddr for funcaddr in self._functions if funcaddr not in self._funInNames]

    def getFunctionsInNames(self):
        return self._funInNames

class idaObjectFunction(idaObject):
    def __init__(self):
        idaObject.__init__(self)
        self.

    def __setattr__(self):
        return super(idaObjectFunction, self).__setattr__()
