'''
    this file containes:
        the definition of wLog
        the definition of idaObject
        the definition of idaObject_Opcode

    
    Make changes to this file first and then copy to others
'''

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

def _locate_objc_runtime_functions(target_msgsend_list):
	'''
	Find the references to 
	id objc_msgSend(id self, SEL op, ...);
	This is the target of all calls and jmps for ObjC calls.
	
	RDI == self
	RSI == selector
	X86/64 args: RDI, RSI, RDX, RCX, R8, R9 ... 
	
	This function populates self.target_objc_msgsend with the intention of
	using this array in other functions to find indirect calls to the various
	ways objc_msgsend is referenced in binaries.
	
	The negative_reg variable below is blank, but is included in case some functions need to be excluded...
	
	TODO: Handle all other objective c runtime functions, not just objc_msgsend
	TODO: generalize to all architectures
	TODO: check that the matched names are in the proper mach-o sections based on the address in the tuple
	'''
	positive_reg = re.compile('.*_objc_msgsend', re.IGNORECASE)
	negative_reg = re.compile('^$', re.IGNORECASE)
	
	# if self.printflag: print "Finding Objective C runtime functions..."

	for name_tuple in idautils.Names(): # returns a tuple (address, name)
		addr, name = name_tuple
		if positive_reg.match(name) and not negative_reg.match(name):
			# if True: print "0x%08x\t%s" % (addr, name)
			if name_tuple not in target_msgsend_list:
				target_msgsend_list.append(name_tuple)

	return target_msgsend_list



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
        self.logger = wLog()
        self.elooger = wLog(is_Exception=True)

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
class idaObject_Opcode(idaObject):
    ''' 
        inherit from idaObject for do_opcode.py function
    '''
    def __init__(self):
        idaObject.__init__(self)
        self._opcodeFreq = {}
        self._opcodeList = []
        self.functionCallMnemNoSub = [
                            'B', 'BR', 'B.NE', 'B.EQ', 
                            'B.CC', 'B.HI', 'B.LE', 'B.LT', 
                            'B.LS', 'B.CS','B.GT', 'B.PL', 
                            'B.MI', 'B.GE', 'CBZ', 'CBNZ',
                            'TBZ','TBNZ'
                            ]
        self.locRe = re.compile(".*_[0-9A-Fa-f]{9}$")
        self.subPreRe = re.compile("^sub")
        self.jptRe = re.compile("^jpt")
        self.__calculateOpcodeFreq()

    def __calculateOpcodeFreq(self):
        for func_addr in self._functions:
            self.__processFunOp(func_addr)
        self._opcodeFreq = sorted(self._opcodeFreq.items(), key=lambda x: x[1], reverse=True)
    
    def __processFunOp(self, func_start_addr):
        instruction = func_start_addr
        my_func = ida_funcs.get_func(func_start_addr)
        while instruction < my_func.endEA:
            self.__updateOpcode(idc.GetMnem(instruction))
            instruction = idc.next_head(instruction, my_func.endEA)

    def __updateOpcode(self, mn):
        if mn not in self._opcodeList:
            self._opcodeList.append(mn)
            self._opcodeFreq[mn]=1
        else:
            self._opcodeFreq[mn]+=1

    def getOpcodeList(self):
        return self._opcodeList
    
    def getOpcodeFreq(self):
        if len(self._opcodeList) == 0:
            print "Opcode list has not been calculated"
            return 
        return self._opcodeFreq
 

    def iterateFunction(self, func_addr, do_some_thing):
        instruction = func_addr
        tmpFun = ida_funcs.get_func(func_addr)
        while instruction<tmpFun.endEA:
            do_some_thing(instruction)
            instruction = idc.next_head(instruction, tmpFun.endEA)
    
    def find_loc(self, addr):
        opcode = idc.GetMnem(addr)
        operand0 = idc.print_operand(addr, 0) # when instruction has only 1 argument, it oprand[1] = oprand[0]
        operand1 = idc.print_operand(addr, 1)
        operand2 = idc.print_operand(addr, 2)
        if opcode == 'ADR':
            if self.jptRe.match(operand1):
                code = idc.GetDisasm(addr)
                print (str(hex(addr))+' ' +str(code))
        return


        

eLogger = wLog(is_Exception=True)
logger  = wLog()

    

print "--- starting ---"
obj = idaObject_Opcode()
for addr in obj._functions:
    obj.iterateFunction(addr, obj.find_loc)
print "--- ending ---"
#idc.Exit(0)