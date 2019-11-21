import write_log
import sys
import os
import re

'''
Input an MachO, extract the general information, such as opcode frequency
'''

class Gia:
    def __init__(self, binary):
        self._analyze_targets = ['dummy','do_opcode']
        # 1 for opcode
        self._binary = binary
        self._target = self._binary+'.i64'
        self._myLogger = write_log.wLog()
        self._myELogger = write_log.wLog(is_Exception=True)
        self._ida = "/Applications/ida.app/Contents/MacOS/ida64"
        self._idaRoot = "/Applications/ida.app/Contents/MacOS"
        self._scriptRoot = "/Users/Zyciac/Desktop/ida_script"

    # def __if_exist_target(self):
    #     target = self._target
    #     return os.path.exists(target)

    # def __if_exist_binary(self):
    #     binary = self._binary
    #     return os.path.exists(binary)

    def __prepare(self):
        if not os.path.exists(self._binary):
            self._myELogger.write("Binary does not exist")
            return
        self._myLogger.write("Preparing the IDA datebase for binary {}".format(self._binary))
        cmdPre = self._ida+' -B {}'.format(self._binary)
        # print cmdPre
        os.system(cmdPre)
    
    def __get_script_file(self, ttype):
        file = self._analyze_targets[ttype]+'.py'
        filePath = os.path.join(self._scriptRoot, file)
        try:
            if not os.path.exists(filePath):
                raise Exception("Script {} not found".format(filePath))
        except:
            self._myELogger.write("Script {} not found".format(filePath))
            exit(0)
        return filePath

    def run(self, analyzeType):
        script = self.__get_script_file(analyzeType)
        if not os.path.exists(self._target):
            self.__prepare()
        cmdRun = self._ida+' -A -S{} {}'.format(script, self._target)
        # print cmdRun
        os.system(cmdRun)
        

if __name__ == "__main__":
    testBinary = "/Users/Zyciac/Desktop/baiduweather"
    g = Gia(testBinary)
    g.run(1)