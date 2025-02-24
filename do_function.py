import idautils
import idc
import idaapi
import ida_funcs
import idc_bc695

import re
import datetime
import inspect
import os
import copy

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

class idaObject_Function(idaObject):
    def __init__(self):
        idaObject.__init__(self)
        self.curFunc = myFuncClass()
        self.tmpFunc = myFuncClass()

        self.functionCallMnemNoSub = [
                                    'B', 'BR', 'B.NE', 'B.EQ', 
                                    'B.CC', 'B.HI', 'B.LE', 'B.LT', 
                                    'B.LS', 'B.CS','B.GT', 'B.PL', 
                                    'B.MI', 'B.GE', 'CBZ', 'CBNZ'
                                    'TBZ','TBNZ'
                                    ]

        self.functionCallMnemWithSub = ['BLR', 'BL']

        # To be completed
        self.assignRegMnem = [
                            'MOV', 'LDR', 'LDP', 'ADD', 'SUB', 'BFI',
                            'LDRSW', 'LDRB', 'CMP', 'MOVI', 'FMUL', 
                            'FADD', 'FCMP', 'CSET', 'CSEL'
                            ]

        # Assert assignRegPcShiftMnem is followed by a assignRegMnem such as "LDR"
        self.assignRegPcShiftMnem = ['ADR', 'ADRP']

        # Use "collect" and it means after this operation, the register is collected to be use after
        self.collectRegMnem = ['STP', 'STR', 'STRB', 'STUR']

        # Arm64 Integer registers
        self.subrParaReg = ['X0', 'X1', 'X2', 'X3', 'X4', 'X5', 'X6', 'X7']
        self.subrRetReg  = ['X0', 'X1', 'X2', 'X3', 'X4', 'X5', 'X6', 'X7']

        # SP is different from Frame Pointer
        self.frmReg = 'X29'
        self.sp = 'SP'

        # Interprocedueral Call Scratch Reg
        self.ips = ['X16', 'X17']
        self.returnBlockReg = 'X8'

        self.linkReg = 'X30' # Address to return after a subroutine call


        # Change from calleeSaveReg to regsSaveByCallee because those regs are saved by the callee(er)
        self.regsSaveByCallee = ['X19', 'X20', 'X21', 'X22', 'X23', 'X24', 'X25',
                            'X26', 'X27', 'X28']
        self.regsSaveByCaller = ['X9', 'X10', 'X11', 'X12', 'X13', 'X14', 'X15']

        # SIMD or FP regs
        self.fpRegPrefix = ['D', 'V']

        # Properties for Specific Purpose
        self._msgSendPairs = self.__initMsgSendPairs()
        #self._objcRuntimeCollection = self.__initObjcRuntimeCollection()

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

    def startGetCallGraph(self, func_start_addr):
        curFun = self.tmpFunc.set_start(func_start_addr)

        # Re construct the following to not use self._funPairInNames
        name = None
        for funcPairs in self._funPairInNames:
            if func_start_addr == funcPairs[0]:
                name = funcPairs[1]
                break
        if name == None:
            name = 'sub_'+str(hex(func_start_addr))
        curFun.set_name(name)

        self.getCallingAddress(curFun)
        # print curFun.callingAddr: Worked

        for callingAddr in curFun.callingAddr:
            receiver = self.resolveCallingAddressBackwards(curFun, 'X0', callingAddr, curFun.start)
            sel = self.resolveCallingAddressBackwards(curFun, 'X1', callingAddr, curFun.start)
            # print str(hex(callingAddr))
            # print receiver
            # print sel 
            # print ''
            self.logger.write(str(hex(callingAddr)))
            if receiver is not None:
                self.logger.write(receiver)
            else:
                self.logger.write("None")
            if sel is not None:
                self.logger.write(sel)
            else:
                self.logger.write("None")
            self.logger.write('\n')

        #TODO
        # Collect all the func calls and combine to get the call graph

        return 

    def getCallingAddress(self, func):
        # print func.funcName
        self.logger.write(func.funcName)
        pc = func.start
        while pc < func.end: # or pc != idc.BADADDR
            # print str(hex(pc))+' '+idc.GetDisasm(pc)
            # Assume LDR can be tracked by idautils.DataRefsFrom()
            # And Assume MOV can be tracked directly
            opcode = idc.GetMnem(pc)
            if opcode in self.functionCallMnemWithSub:
                if opcode == 'BL':
                    operand = idc.print_operand(pc ,0)
                    # print operand
                    msgsendRe = re.compile('.*msgsend.*', re.IGNORECASE)
                    if msgsendRe.match(operand):
                        # print idc.GetDisasm(pc)
                        func.callingAddr.append(pc)
                elif opcode == 'BLR':
                    print idc.GetDisasm(pc)
            pc = idc.next_head(pc, func.end)

    def resolveCallingAddressBackwards(self, func, target, start, end):
        '''
        start is callingAddr
        end is curFun.start
        '''
        
        pc = start
        pc = idc.prev_head(pc, 0)
        while pc > end:
            opcode = idc.GetMnem(pc)
            opTarget = idc.print_operand(pc, 0)
            # print hex(pc)
            # print opcode
            # print target
            # print '\n'

            value = None
            if opcode in self.collectRegMnem and opTarget == target:
                return None

            if opcode in self.assignRegMnem and opTarget == target:
                if opcode == 'MOV':
                    nextTarget = idc.print_operand(pc, 1)
                    return self.resolveCallingAddressBackwards(func, nextTarget, pc, end)
                    
                elif opcode == 'LDR':
                    dataref = list(idautils.DataRefsFrom(pc))[0]
                    value = idc.print_operand(dataref, 0)

                    return value
                    
            pc = idc.prev_head(pc, 0)
        return None
        
    def startGetControlFlow(self, func_start_addr):
        curFun = self.tmpFunc.set_start(func_start_addr)
        return curFun.getCFG()


class myFuncClass(object):
    def __init__(self):
        self.funcObj = None
        self.start = None
        self.end = None
        self.funcName = ""
        self.funcAddr = None

        self.cfg = None
        self.locations = []
        self.basicblocks = []

        self.beCalledList = [] # functions that call me 

        self.functionsCalled = [] # functions addrs that are called
        self.callsiteAddr = [] # exact callsite addr
        self.functionCallMnemNoSubNoBR = [
                                    'B','BR', 'B.NE', 'B.EQ', 
                                    'B.CC', 'B.HI', 'B.LE', 'B.LT', 
                                    'B.LS', 'B.CS','B.GT', 'B.PL', 
                                    'B.MI', 'B.GE', 'CBZ', 'CBNZ'
                                    'TBZ','TBNZ'
                                    ]
        self.jptRe = re.compile("^jpt")
        self.locRe = re.compile(".*_[0-9A-Fa-f]{9}$")

    def set_start(self, start_addr):
        self.start = start_addr
        self.funcObj = ida_funcs.get_func(start_addr)
        self.end = self.funcObj.endEA
        return self

    def getCFG(self):
        self.__getAllBBs()
        self.__getAllEdges()
        self.__drawCFG()
    
    def __locationToEa(self, location):
        '''
        location string to int
        '''
        hexStr = '0x'+location.split('_')[1]
        return int(hexStr, 16)

    def __isJpt(self, ea):
        opcode = idc.GetMnem(ea)
        # operand0 = idc.print_operand(ea, 0) # when instruction has only 1 argument, it oprand[1] = oprand[0]
        operand1 = idc.print_operand(ea, 1)
        # operand2 = idc.print_operand(ea, 2)
        if opcode == 'ADR':
            if self.jptRe.match(operand1):
                return True
        return False
    
    def __extractJpt(self, jptEa):
        '''return a list of location in function'''
        addr = list(idautils.DataRefsFrom(jptEa))[0]
        instruction = idc.GetDisasm(addr).split()
        opcode = instruction[0]
        while opcode == 'DCD':
            self.locations.append(self.__locationToEa(instruction[1]))
            addr = idc.next_head(addr, idc.BADADDR)
            instruction = idc.GetDisasm(addr).split()
            opcode = instruction[0]
    
    def __ifBranchWithNoSubCall(self, ea):
        instruction = idc.GetMnem(ea)
        if instruction in self.functionCallMnemNoSubNoBR:
            return True

        return False


    def __getAllBBs(self):
        self.basicblocks = []
        self.locations = []

        pc = self.start

        locCounter = 0
        curCB = basicblock()
        isNewBB = True
        while pc < self.end:
            locCounter +=1
            pcNext = idc.next_head(pc, idc.BADADDR)
            if isNewBB:
                curCB.startAddr = pc
                isNewBB = False

            if self.__isJpt(pc):
                self.__extractJpt(pc)

            if pcNext in self.locations or pcNext == self.end or self.__ifBranchWithNoSubCall(pc):
                if self.__ifBranchWithNoSubCall(pc):
                    operand0 = idc.print_operand(pc, 0)
                    operand1 = idc.print_operand(pc, 1)
                    operand2 = idc.print_operand(pc, 2)
                    if self.locRe.match(operand0):
                        self.locations.append(self.__locationToEa(operand0))
                    if self.locRe.match(operand1):
                        self.locations.append(self.__locationToEa(operand1))
                    if self.locRe.match(operand2):
                        self.locations.append(self.__locationToEa(operand2))
                curCB.endAddr = pc
                isNewBB = True
                curCB.locs = locCounter
                locCounter = 0
                self.basicblocks.append(copy.deepcopy(curCB))
                curCB = basicblock()
            pc = idc.next_head(pc, idc.BADADDR)

    def __getAllEdges(self):
        ''' 
            
            TODO: Find all the B objc_runtime that indicating an return 
            Find B x0, indicating a recursion.
        '''
        return

    def __drawCFG(self):
        '''
            This function should update self.CFG
        '''
        return

class basicblock:
    def __init__(self):
        # self.seqNumber = None
        self.startAddr=None
        self.endAddr=None
        self.locs=None
        self.edgeList = []
        
class edge:
    def __init__(self):
        self.jumpBackWards = None
        self.ifBranch = None
        self.src = None
        self.dst = None


print '---------------------------begin'
#logger = wLog()
fun = myFuncClass()
fun.set_start(0x0000000100026D8C)
# print "set complete"
fun.getCFG()
# print "get complete"
for item in fun.basicblocks:
    print "basicblock:"
    print item.locs
    print hex(item.startAddr)
    print hex(item.endAddr)
    print ""
print "----------------------------end"

