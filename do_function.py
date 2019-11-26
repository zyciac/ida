import idautils
import idc
import idaapi
import ida_funcs
import idc_bc695

import re
import datetime
import inspect
import os




class wLog:
    __path = "/Users/Zyciac/Desktop/log/log.txt"
    __writing_type = 'a'
    __is_Exception = False
    __rpath = "/Users/Zyciac/Desktop/log/"
    __epath = "/Users/Zyciac/Desktop/log/exception.txt"

    def __init__(self, is_Exception=None, writing_type = None, path = None, epath=None):
        self.__path  = path
        self.__epath = epath
        # self.__writing_types_enum = ['a', 'w', 'a+', 'w+']
        self.__writing_type = writing_type
        self.__is_Exception = is_Exception
        self.__logcount = 0
        self.__init_helper()
        time = self.__getCurTime()
        self.write('\n\n', self.__path, self.__writing_type)
        if not self.__is_Exception:
            self.__writeString(time, self.__path, self.__writing_type)

    def __init_helper(self):
        if self.__path is None:
            self.__path = wLog.__path
        if self.__epath is None:
            self.__epath = wLog.__epath
        if self.__writing_type is None:
            self.__writing_type = wLog.__writing_type
        if self.__is_Exception is None:
            self.__is_Exception = wLog.__is_Exception


    def getWritingType(self):
        return self.__writing_type

    def __create_newfile(self):
        new_file = os.path.join(wLog.__rpath, 'log'+str(self.__logcount)+'.txt')
        while os.path.exists(new_file):
            self.__logcount+=1
            new_file = os.path.join(wLog.__rpath, 'log'+str(self.__logcount)+'.txt')
        return new_file

    def write_newfile(self, stuff):
        if self.__is_Exception:
            self.__writeException("Exception logger cannot write new file")
            return
        ffile = self.__create_newfile()
        with open(ffile, self.__writing_type) as f:
            time = self.__getCurTime()
            f.write(time)
            f.write('\n')

        self.write(stuff, ffile)

    def __getCurTime(self):
        self._curTime = datetime.datetime.now()
        return str(self._curTime)
    
    def __retrieve_name(self, var):
        callers_local_vars = inspect.currentframe().f_back.f_back.f_back.f_locals.items()
        return [var_name for var_name, var_val in callers_local_vars if var_val is var][0]

    def __retrieve_name_FN(self, var):
        callers_local_vars = inspect.currentframe().f_back.f_back.f_back.f_back.f_locals.items()
        return [var_name for var_name, var_val in callers_local_vars if var_val is var][0]

    def write(self, stuff, path=None, ttype=None):

        # The following code solves the "Cannot use self.attribute\
        # as function default value" problem.
        if ttype is None:
            ttype = self.__writing_type

        if path is None:
            path = wLog.__path

        if self.__is_Exception:
            self.__writeException(stuff)
            return

        stuffType = str(type(stuff))
        
        # print stuffType=="<type 'str'>"

        if stuffType == "<type 'list'>":
            self.__writeList(stuff, path, ttype)
        elif stuffType == "<type 'tuple'>":
            self.__writeTuple(stuff, path, ttype)
        elif stuffType == "<type 'dict'>":
            self.__writeDict(stuff, path, ttype)
        elif stuffType == "<type 'str'>":
            self.__writeString(stuff, path, ttype)
        elif stuffType == "<type 'generator'>":
            self.__writeGenerator(stuff, path, ttype)
        else:
            self.__writeException("the type of writing stuff is not considered: {}".format(stuffType))
            print "the type of writing stuff is not considered: {}".format(stuffType)
        
        return None
    

    def __writeException(self, sentences="Exceptions", ffile=None, ttype='a'):
        if ffile is None:
            ffile = self.__epath
        with open(ffile, ttype) as f:
            cur_time = self.__getCurTime()
            f.write('\n'+str(cur_time)+'\n')
            f.write("*Exception*:\n")
            f.write(sentences)
            f.write('\n')

        return None
    

    def __writeList(self, stuff, ffile, ttype):
        with open(ffile, ttype) as f:
            # f.write('\n'+self.__getCurTime()+'\n')
            f.write("*List*:\n")
            #f.write(self.__retrieve_name(stuff)+':\n')
            for item in stuff:
                f.write(str(item)+'\n')
            f.write('\n')
        return


    def __writeDict(self, stuff, ffile, ttype):
        with open(ffile, ttype) as f:
            # f.write('\n'+self.__getCurTime()+'\n')
            f.write("Dict*:\n")
            #f.write(self.__retrieve_name(stuff)+':\n')
            for k in stuff.keys():
                f.write("{}: {}\n".format(str(k), str(stuff[k])))
            f.write('\n')
        return


    def __writeTuple(self, stuff, ffile, ttype):
        self.__writeList(stuff, ffile, ttype)

        return
    

    def __writeString(self, stuff, ffile, ttype):
        with open(ffile, ttype) as f:
            # f.write('\n'+self.__getCurTime()+'\n')
            # f.write("*These are sentences*\n")
            # f.write(self.__retrieve_name(stuff)+':\n')
            f.write(stuff) 
            f.write('\n\n')

        return


    def __writeGenerator(self, stuff, ffile, ttype):
        stuff = list(stuff)
        self.write(stuff, ffile, ttype)

        return


class idaObject(object):
    ''' 
        create general class for idaObject 
        To Be complete
    '''
    # _functions = []
    # _funInNames = []
    # _funNotInNames = []

    def __init__(self):
        self._names = self.__initNames()
        self._functions = self.__initFunctionList()
        self._funInNames = self.__initFunctionsInNames()
        self._funNotInNames = self.__initFunctionsNotInName()
        self._funPairInNames = self.__initFunctionPairsInNames()

    def __initNames(self):
        return list(idautils.Names())

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

    def __initFunctionPairsInNames(self):
        nameList = self._names
        funcPairInNames = []
        for pair in nameList:
            addr, name = pair
            if addr in self._functions:
                funcPairInNames.append(pair)
        return funcPairInNames
    
    def getFunctionPairInNames(self):
        return self._funPairInNames

class idaObject_Function(idaObject):
    def __init__(self):
        idaObject.__init__(self)

        self.functionCallMnem = [
            'BL', 'B', 'BR', 'B.NE', 'B.EQ', 
            'B.CC', 'B.HI', 'B.LE', 'B.LT', 
            'BLR', 'B.LS', 'B.CS','B.GT', 'B.PL', 
            'B.MI', 'B.GE', 'BFI']

        self.subrParaReg = ['X0', 'X1', 'X2', 'X3', 'X4', 'X5', 'X6', 'X7']
        self.subrRetReg  = ['X0', 'X1', 'X2', 'X3', 'X4', 'X5', 'X6', 'X7']
        self.frmReg = 'X29'
        self.calleeSaveReg = ['X19', 'X20', 'X21', 'X22', 'X23', 'X24', 'X25',
                            'X26', 'X27', 'X28', 'X29']
        self.callerSaveReg = ['X9', 'X10', 'X11', 'X12', 'X13', 'X14', 'X15']

        self._msgSendPairs = self.__initMsgSendPairs()
        # self._objcRuntimeCollection = self.__initObjcRuntimeCollection()


    def __initMsgSendPairs(self):
        positiveReg = re.compile('.*_objc_msgsend', re.IGNORECASE)
        negativeReg = re.compile('^$', re.IGNORECASE)
        rtList = []
        for namePair in self._names:
            faddr, fname = namePair
            if positiveReg.match(fname) and not negativeReg.match(fname):
                rtList.append(namePair)
        return rtList
    
    def __initObjcRuntimeCollection(self):
        positiveReg = re.compile('.*_objc_', re.IGNORECASE)
        rtList = []
        for namePair in self._funPairInNames:
            faddr, fname = namePair
            if positiveReg.match(fname):
                rtList.append(namePair)
        return rtList
    
    def getMsgSendPair(self):
        return self._msgSendPairs

    def getObjcRuntimeCollection(self):
        return self._objcRuntimeCollection

    

print 'begin'
logger = wLog()
obj = idaObject_Function()
logger.write_newfile(obj.getObjcRuntimeCollection())
print "end"

