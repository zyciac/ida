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
            f.write('\n'+self.__getCurTime()+'\n')
            f.write("*List*:\n")
            #f.write(self.__retrieve_name(stuff)+':\n')
            for item in stuff:
                f.write(str(item)+'\n')
        return


    def __writeDict(self, stuff, ffile, ttype):
        with open(ffile, ttype) as f:
            f.write('\n'+self.__getCurTime()+'\n')
            f.write("Dict*:\n")
            #f.write(self.__retrieve_name(stuff)+':\n')
            for k in stuff.keys():
                f.write("{}: {}\n".format(str(k), str(stuff[k])))
        return


    def __writeTuple(self, stuff, ffile, ttype):
        self.__writeList(stuff, ffile, ttype)

        return
    

    def __writeString(self, stuff, ffile, ttype):
        with open(ffile, ttype) as f:
            f.write('\n'+self.__getCurTime()+'\n')
            # f.write("*These are sentences*\n")
            # f.write(self.__retrieve_name(stuff)+':\n')
            f.write(stuff)
            f.write('\n')

        return


    def __writeGenerator(self, stuff, ffile, ttype):
        stuff = list(stuff)
        self.write(stuff, ffile, ttype)

        return