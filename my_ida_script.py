'''
main() writes log, controls the feedbacks of main logic of the test script"
other useful output can be implemented using other functions
'''

import sys
import os
import datetime

import idautils
import idc
import idaapi
import ida_funcs
import idc_bc695

__DEBUG = False
__LOG_ROOT_PATH = "/Users/Zyciac/Desktop"
__LOG_FILE_NAME = "log.txt"
__FUNCTION_NAME_FILE = "function_name.txt"

def get_func_literal(func_addr, address_list, literals_list):
	if func_addr in address_list:
		return literals_list[address_list.index(func_addr)]
	return None

def return_functions_XrefsFrom(function_address_name_pairs):
	return list(idautils.XrefsFrom(function_address_name_pairs[0]))

def return_functions_XrefsTo(function_address_name_pairs):
	return list(idautils.XrefsTo(function_address_name_pairs[0]))

def is_the_function_calling_nothing(function_address_name_pairs, file):
	function_calls = return_functions_XrefsFrom(function_address_name_pairs)
	if __DEBUG:
		file.write("DEBUG: is_the_function_calling_nothing({})".format(function_address_name_pairs[1]))
		file.write(str(list(function_calls))+'\n')
	if len(function_calls) ==  0:
		return True
	return False

def is_the_function_called_by_others(function_address_name_pairs, file):
	function_being_called = return_functions_XrefsTo(function_address_name_pairs)
	if __DEBUG:
		file.write("DEBUG: is_the_function_called_by_others({}): ".format(function_address_name_pairs[1]))
		file.write(str(list(function_being_called))+'\n')
	if len(function_being_called) == 0:
		return True
	return False

def return_functions_in_Names():
	names = idautils.Names()
	name_addresses = []
	name_literals = []
	functions_found = []

	for item in names:
		name_addresses.append(item[0])
		name_literals.append(item[1])

	func_gen = idautils.Functions()
	for item in func_gen:
		func_literal = get_func_literal(item, name_addresses, name_literals)
		if func_literal is None:
			print "function at {} cannot be found in idautils.Names()\n".format(str(hex(item)))
		else:
			functions_found.append((item, func_literal))
	return functions_found

def main():
	with open(os.path.join(__LOG_ROOT_PATH, __LOG_FILE_NAME), 'w') as f:
		if __DEBUG:
			f.write("successfully opened {}\n".format(os.path.join(__LOG_ROOT_PATH, __LOG_FILE_NAME)))

		f.write("{} \t=========zyc_test begins!=========\n\n".format(str(datetime.datetime.now())))
		names = idautils.Names()
		name_addresses = []
		name_literals = []
		functions_found = []

		for item in names:
			name_addresses.append(item[0])
			name_literals.append(item[1])

		if __DEBUG:
			f.write("\nNAME Address Pairs:\n")
			for i in range(len(name_addresses)):
				f.write("Name and Address Pair -- Name: {}, Address: {}\n".format(str(name_literals[i]), str(hex(name_addresses[i]))))
			f.write('\n')

		func_gen = idautils.Functions()
		
		if __DEBUG:
			f.write("succesfully called idautils.Functions()\n")

		if __DEBUG:
			f.write("\nFunction Names:\n")
		for item in func_gen:
			func_literal = get_func_literal(item, name_addresses, name_literals)
			if func_literal is None:
				f.write("function at {} cannot be found in idautils.Names()\n".format(str(hex(item))))
			else:
				if __DEBUG:
					f.write("function at {} is named: {}\n".format(str(hex(item)),func_literal))
				functions_found.append((item, func_literal))
		
		atomic_functions = []
		entry_functions = []

		for function_address_name_pairs in functions_found:
			if is_the_function_calling_nothing(function_address_name_pairs, f):
				atomic_functions.append(function_address_name_pairs)
			if is_the_function_called_by_others(function_address_name_pairs, f):
				entry_functions.append(function_address_name_pairs)

		for pairs in atomic_functions:
			f.write("I call nothing: {}, at {}\n".format(pairs[1], pairs[0]))
		for pairs in entry_functions:
			f.write("nothings called me: {}, at {}\n".format(pairs[1], pairs[0]))

		f.write("\n{} \t========zyc_test terminates!========\n".format(str(datetime.datetime.now())))
	
	#uncomment this line when starting batch analysis
	idc.Exit(0)
  
	return 0

if __name__ == "__main__":
	main()