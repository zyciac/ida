import re

import idautils
import idc
import idaapi
import ida_funcs
import idc_bc695

def get_func_literal(func_addr, address_list, literals_list):
	if func_addr in address_list:
		return literals_list[address_list.index(func_addr)]
	return None

def return_start_addr(functions_found_dict):
	if "start" in functions_found_dict["name"]:
		index = functions_found_dict["name"].index("start")
		return functions_found_dict["addr"][index]
	return None

def return_function_addr_given_name(functions_found_dict, function_name="start"):
	if function_name in functions_found_dict["name"]:
		index = functions_found_dict["name"].index(function_name)
		return functions_found_dict["addr"][index]
	return None

def return_function_name_given_addr(functions_found_dict, function_addr):
	if function_addr in functions_found_dict["addr"]:
		index = functions_found_dict["addr"].index(function_addr)
		return functions_found_dict["name"][index]
	return None

def return_functions_in_Names():
	names = idautils.Names()
	name_addresses = []
	name_literals = []
	functions_found = {}
	functions_found["addr"] = []
	functions_found["name"] = []

	for item in names:
		name_addresses.append(item[0])
		name_literals.append(item[1])

	func_gen = idautils.Functions()
	for item in func_gen:
		func_literal = get_func_literal(item, name_addresses, name_literals)
		if func_literal is None:
			# print "function at {} cannot be found in idautils.Names()\n".format(str(hex(item)))
			pass
		else:
			functions_found["name"].append(func_literal)
			functions_found["addr"].append(item)
	return functions_found

def print_function_opcode(func_start_addr):
	instruction = func_start_addr
	my_func = ida_funcs.get_func(func_start_addr)
	while instruction < my_func.endEA:
		# print idc.GetMnem(instruction)+" instruction: "+ idc.GetDisasm(instruction)
		instruction = idc.next_head(instruction, my_func.endEA)

def return_function_opcode_addr_pair(func_start_addr):
	instruction = func_start_addr
	my_func = ida_funcs.get_func(func_start_addr)
	
def is_function(addr, function_list):
	return addr in function_list

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
			if True: print "0x%08x\t%s" % (addr, name)
			if name_tuple not in target_msgsend_list:
				target_msgsend_list.append(name_tuple)

	return target_msgsend_list

a = return_functions_in_Names()
print len(a["addr"])
for item in a["addr"]:
	print_function_opcode(item)
print "done"