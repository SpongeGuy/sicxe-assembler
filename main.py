import re

OPCODE_TABLE = {
	"ADD": (0x18, 3),
	"ADDF": (0x58, 3),
	"ADDR": (0x90, 2),
	"AND": (0x40, 3),
	"CLEAR": (0xB4, 2),
	"COMP": (0x28, 3),
	"COMPF": (0x88, 3),
	"COMPR": (0xA0, 2),
	"DIV": (0x24, 3),
	"DIVF": (0x64, 3),
	"DIVR": (0x9C, 2),
	"FIX": (0xC4, 1),
	"FLOAT": (0xC0, 1),
	"HIO": (0xF4, 1),
	"J": (0x3C, 3),
	"JEQ": (0x30, 3),
	"JGT": (0x34, 3),
	"JLT": (0x38, 3),
	"JSUB": (0x48, 3),
	"LDA": (0x00, 3),
	"LDB": (0x68, 3),
	"LDCH": (0x50, 3),
	"LDF": (0x70, 3),
	"LDL": (0x08, 3),
	"LDS": (0x6C, 3),
	"LDT": (0x74, 3),
	"LDX": (0x04, 3),
	"LPS": (0xD0, 3),
	"MUL": (0x20, 3),
	"MULF": (0x60, 3),
	"MULR": (0x98, 2),
	"NORM": (0xC8, 1),
	"OR": (0x44, 3),
	"RD": (0xD8, 3),
	"RMO": (0xAC, 2),
	"RSUB": (0x4C, 3),
	"SHIFTL": (0xA4, 2),
	"SHIFTR": (0xA8, 2),
	"SIO": (0xF0, 1),
	"SSK": (0xEC, 3),
	"STA": (0x0C, 3),
	"STB": (0x78, 3),
	"STCH": (0x54, 3),
	"STF": (0x80, 3),
	"STI": (0xD4, 3),
	"STL": (0x14, 3),
	"STS": (0x7C, 3),
	"STSW": (0xE8, 3),
	"STT": (0x84, 3),
	"STX": (0x10, 3),
	"SUB": (0x1C, 3),
	"SUBF": (0x5C, 3),
	"SUBR": (0x94, 2),
	"SVC": (0xB0, 2),
	"TD": (0xE0, 3),
	"TIO": (0xF8, 1),
	"TIX": (0x2C, 3),
	"TIXR": (0xB8, 2),
	"WD": (0xDC, 3),
}

REG_VALUES = {
	"A": 0,
	"X": 1,
	"L": 2,
	"B": 3,
	"S": 4,
	"T": 5,
	"F": 6,
	"PC": 8,
	"SW": 9,
}

DIRECTIVES = {
	"RESD",
	"RESQ",
	"NOBASE",
	"EQU",
	"BYTE",
	"WORD",
	"RESW",
	"RESB",
	"BASE",
	"LTORG",
	"CSECT",
	"EXTREF",
	"EXTDEF",
	"MACRO",
	"MEND",
}

SYMBOL_TABLE = []
CONTROL_SECTION_ID = 0

WORKING_LITERAL_TABLE = []
LITERAL_TABLE = []
EXTREFS = []
MACROS = []

LOCCTR = 0x0000
LOCATION_COUNTERS = [['', 0, 0x0, 0x0, True]] # [name, id, starting_address, length, active_flag]
ACTIVE_LOCCTR_ID = LOCATION_COUNTERS[0][1]

REG_X = 0
REG_B = 0

sample = "samples/functions.txt"

def scrub_newlines(statement):
	return [s.strip() for s in statement]


def get_instruction_data_length(instruction_data):
	directive_lengths = {
		"RESD": lambda x: 4 * int(x[2]),
		"RESQ": lambda x: 8 * int(x[2]),
		"RESW": lambda x: 3 * int(x[2]),
		"RESB": lambda x: int(x[2]),
		"BYTE": lambda x: get_literal_code(x[2])[1],
		"WORD": lambda x: 3,
		"EQU": lambda x: 0,
		"BASE": lambda x: 0,
		"NOBASE": lambda x: 0,
		"LTORG": lambda x: 0,
	}
	try:
		if '.' in instruction_data[0]:
			return 0
		instruction = instruction_data[1]
		operand = instruction_data[2]
		function = directive_lengths.get(instruction)
		if function:
			return int(function(instruction_data))

		# if not return here, then instruction is an operation
		if parse_instruction(instruction) in OPCODE_TABLE:
			if '+' in instruction:
				return 4
			else:
				return OPCODE_TABLE[instruction][1]
	except Exception as e:
		print(f"Could not get length of instruction: {e}")


def get_next_address(instruction_data):
	# take a parsed_instruction (no special characters) and returns the next memory address variable based on size of instruction
	try:
		c = int(instruction_data[3][2:], 16)
		value = get_instruction_data_length(instruction_data)
		if value:
			c += value
		return c
	except Exception as e:
		print(f"An error occurred while getting next PC: {e}")


def parse_instruction(instruction):
	# returns a stripped string including only capital letters
	try:
		match = re.search(r'[A-Z]+', instruction)
		return match.group()
	except Exception as e:
		print(f"Error while parsing instruction: {e}")

def get_literal_code(literal):
	# literal is in form  #'#' or =#'#' 
	# given the instruction is BYTE, get the length of the instruction and the object code
	try:
		value = 0
		match = re.findall(r"([CX])'([A-Za-z0-9]+)'", literal)
		if match[0][0] == 'X':
			# operand is hexadecimal constant
			value = match[0][1]
		elif match[0][0] == 'C':
			# operand is a string of characters
			value = ''.join([format(ord(c), '02X') for c in match[0][1]])

		length = len(value) / 2
		obj_code = "0x" + value
		return (obj_code, length)
	except Exception as e:
		print(f"error getting literal code: {e}")

def update_symbol_table(instruction_data):
	# grabs instructions with labels and appends them to symbol table
	try:
		flags = []
		for entry in SYMBOL_TABLE:
			if instruction_data[0] == entry[1]:
				flags.append("REPEAT")
		if instruction_data[0] != '' and '.' not in instruction_data[0]:
			SYMBOL_TABLE.append((instruction_data[3], instruction_data[0], flags, ACTIVE_LOCCTR_ID, CONTROL_SECTION_ID))
	except Exception as e:
		print(f"Could not update SYMTAB: {e}")

def update_literal_table(statement):
	# reads statement and determines if operand is in literal table
	# if not, add it to literal table and change operand of statement to match that of the index of literal table entry
	global LOCCTR
	try:
		match_lit = re.findall(r"^=([CX])'([A-Za-z0-9]+)'$", statement[2])
		match_star = re.findall(r"=(\*)", statement[2])
		index = len(LITERAL_TABLE)
		# behave differently if literal references location counter
		if match_star != []:
			WORKING_LITERAL_TABLE.insert(0, ['', match_star, index, ''])
			LITERAL_TABLE.append(['', match_star, index, ''])
			index = len(LITERAL_TABLE)
			statement[2] = f'={index - 1}'
			return
		if match_lit == []:
			return None

		# if entry already in working literal table, do not add it again NO DUPLICATES 
		# (unless literal has already been defined somewhere)
		for entry in LITERAL_TABLE:
			if match_lit == entry[1]:
				statement[2] = f'={index - 1}'
				return
		# match is not in literal table
		WORKING_LITERAL_TABLE.insert(0, ['', match_lit, index, ''])
		LITERAL_TABLE.append(['', match_lit, index, ''])
		index = len(LITERAL_TABLE)
		statement[2] = f'={index - 1}'
		
	except Exception as e:
		print(f"could not update literal table: {e}")

def get_literal_length(literal_match):
	try:
		value = 0
		if literal_match[0] == 'C':
			value = len(literal_match[1])
		elif literal_match[0] == 'X':
			value = int(len(literal_match[1]) / 2)
		else:
			raise Exception("literal invalid")

		return value
	except Exception as e:
		print(f"could not get literal length: {e}")	

def get_literal_pool(statement):
	# LTORG OPERATION, inject each literal in the array into the intermediate file
	# assigns addresses to literal values
	global LOCCTR
	global ACTIVE_LOCCTR_ID
	literals = []
	while len(WORKING_LITERAL_TABLE) != 0:
		entry = WORKING_LITERAL_TABLE.pop()
		for fella in LITERAL_TABLE:
			if entry[2] == fella[2]:
				fella[0] = hex(LOCCTR)
				fella[3] = ACTIVE_LOCCTR_ID

		if entry[1][0] == '*':
			literals.append(('*', f"={entry[1][0]}", '', hex(LOCCTR), ACTIVE_LOCCTR_ID, CONTROL_SECTION_ID, entry[2]))
			LOCCTR = LOCCTR + int(len(hex(LOCCTR)[2:]) / 2)
		else:
			literals.append(('*', f"={entry[1][0][0]}'{entry[1][0][1]}'", '', hex(LOCCTR), ACTIVE_LOCCTR_ID, CONTROL_SECTION_ID, entry[2]))
			LOCCTR = LOCCTR + get_literal_length(entry[1][0])
	return literals

def generate_macro_instruction_data(statement, macro):
	macro_data = []
	file = macro[1].splitlines()
	symbols = re.findall(r'(&\w+)', macro[2])
	parameters = re.findall(r'(\w+)', statement[2])
	for x in range(len(symbols)):
		for line in range(len(file)):
			file[line] = file[line].replace(symbols[x], parameters[x])
	for line in file:
		statement = line.split('\t')
		macro_data.append(statement)

	return macro_data
	
def do_macros():
	path = sample
	try:
		with open(path, 'r') as file:
			# define macros
			capturing = False
			macros_present = False
			body = ""
			name = ""
			parameters = ""
			for line in file:
				if "MEND" in line:
					macros_present = True
					break

			if macros_present:
				for line in file:
					statement = line.split('\t')
					
					if '.' in statement[0] or statement == [''] or statement == ['\n']:
						continue

					if 'MEND' in statement[1]:
						capturing = False
						MACROS.append([name, body, parameters])
						body = ""
						name = ""
						parameters = ""
					
					if capturing:
						body += line

					if 'MACRO' in statement[1]:
						parameters = statement[2]
						name = statement[0]
						capturing = True

		with open(path, 'r') as file:
			# invoke macros and set up file for assembly
			finished_file = []
			if MACROS == []:
				for line in file:
					statement = line.split('\t')
					finished_file.append(statement)
			else:
				ignoring = False
				for line in file:
					statement = line.split('\t')
					if statement[1] == 'START':
						finished_file.append(statement)
						ignoring = True
					if statement[1] == 'STL':
						ignoring = False
					if not ignoring:
						# make sure that the line invoking the macro is not part of the finished file
						metastatement = statement
						for macro in MACROS:
							if statement[1] == macro[0]:
								metastatement = None
						if metastatement:
							finished_file.append(statement)
						for macro in MACROS:
							if statement[1] == macro[0]:
								macro_data = generate_macro_instruction_data(statement, macro)
								if macro_data != []:
									for x in range(len(macro_data)):
										if x == 0:
											macro_data[x][0] = statement[0]
										finished_file.append(macro_data[x])
						
		
			return finished_file

	except Exception as e:
		print(f"could not do macro: {e}")

def update_location_counters(statement):
	global LOCCTR
	# LOCATION_COUNTERS = [[name, id, starting_address, length, active_flag], ...]
	counter_present = False
	for counter in LOCATION_COUNTERS:
		# if name of counter already present, don't do anything
		if statement[2] in counter:
			counter_present = True
	
	if counter_present == False:
		LOCATION_COUNTERS.append([statement[2], len(LOCATION_COUNTERS), 0x0, 0x0, False])

	for counter in LOCATION_COUNTERS:
		# update current location counter value
		if counter[4] == True:
			counter[3] = LOCCTR
	
	for counter in LOCATION_COUNTERS:
		counter[4] = False
		if statement[2] == counter[0]:
			counter[4] = True
			LOCCTR = counter[3]

def first_pass(finished_file):
	path = sample
	global LOCCTR
	global EXTREFS
	global ACTIVE_LOCCTR_ID
	global CONTROL_SECTION_ID
	intermediate_file = []
	# iterate through file
	try:
		for statement in finished_file:
			
			if '.' in statement[0] or statement == [''] or statement == ['\n']:
				continue
			# initialize location counter starting address
			if statement[1] == 'START':
				program_starting_address = int(statement[2])
				LOCCTR = program_starting_address
			# column 0 is symbol, column 1 is instruction, column 2 is operand, column 3 is comment
			# fill out SYMBOL_TABLE
			# check if instruction is in opcode table, if it is, increment program counter
			# grab any labels & program counter and add to symbol table
			instruction_data = ()
			print(f"{hex(LOCCTR)}\t {statement}")

			for macro in MACROS:
				if statement[1] == macro[0]:
					print("con")
					generate_macro_instruction_data(statement, macro)
			statement = scrub_newlines(statement)
			# detect literals in operand field and add to literal table
			if statement[1] not in DIRECTIVES:
				update_literal_table(statement)


			# external references
			if statement[1] == 'EXTREF':
				match = re.findall(r'(\w+)', statement[2])
				for entry in match:
					EXTREFS.append((match, CONTROL_SECTION_ID))

			# control sections
			if statement[1] == 'CSECT':
				LOCCTR = 0
				CONTROL_SECTION_ID += 1

			# program blocks
			if statement[1] == 'USE':
				update_location_counters(statement)


			active_location_counter_id = None
			for counter in LOCATION_COUNTERS:
				if counter[4] == True:
					ACTIVE_LOCCTR_ID = counter[1]



			# create refined instruction data (label, operator, operand, location) and add it to intermediate file
			# EQU statements
			if statement[1] == 'EQU' and '*' not in statement[2]:
				match_words = re.findall(r'(\w+)', statement[2])
				match_operators = re.findall(r'([+-])', statement[2])
				symbol_addresses = []
				for entry in SYMBOL_TABLE:
					for word in match_words:
						if entry[1] == word:
							symbol_addresses.insert(0, entry[0])
				address = int(symbol_addresses[0], 16)
				for x in range(len(match_operators)):
					if match_operators[x] == '-':
						address -= int(symbol_addresses[x+1], 16)
					elif match_operators[x] == '+':
						address += int(symbol_addresses[x+1], 16)
				instruction_data = (statement[0], statement[1], statement[2], hex(address), ACTIVE_LOCCTR_ID, CONTROL_SECTION_ID)
				intermediate_file.append(instruction_data)
				update_symbol_table(instruction_data)
			# all other statements !!! :))))
			else:
				operand = ''
				if len(statement) >= 3:
					operand = statement[2]
				instruction_data = (statement[0], statement[1], operand, hex(LOCCTR), ACTIVE_LOCCTR_ID, CONTROL_SECTION_ID)
				intermediate_file.append(instruction_data)
				update_symbol_table(instruction_data)
				if statement[1]:
					LOCCTR = get_next_address(instruction_data)

			
			literals = []
			if statement[1] == 'LTORG' or statement[1] == 'END':
				literals = get_literal_pool(statement)
			
			if literals != []:
				for entry in literals:
					intermediate_file.append(entry)


		update_location_counters(['', 'USE', '', ''])
		# update starting addresses of all location counters
		# LOCATION_COUNTERS = [[name, id, starting_address, length, active_flag], ...]

		total_memory_used = 0
		for x in range(1, len(LOCATION_COUNTERS)):
			total_memory_used += LOCATION_COUNTERS[x-1][3]
			LOCATION_COUNTERS[x][2] = total_memory_used


		print()
		print()
		print("EXTREFS")
		print(EXTREFS)
		print()
		print("LOCATION_COUNTERS")
		print(LOCATION_COUNTERS)
		print()
		print("SYMBOL_TABLE")
		print(SYMBOL_TABLE)
		print()
		print("LITERAL_TABLE")
		print(LITERAL_TABLE)
		print()
		print()


		return intermediate_file

	except FileNotFoundError:
		print(f"File not found: {path}")
	except Exception as e:
		print(f"An error occurred during first pass: {e}")



def second_pass(intermediate_file):
	path = sample
	# iterate through file
	try:
		object_code = []
		for statement in intermediate_file:
			print(statement)

			# update base register per statement
			if statement[1] == 'BASE':
				set_base_register(statement)

			object_code.append(generate_obj_code(statement, intermediate_file))

		for code in object_code:
			print(code)
		print()
		print()

	except FileNotFoundError:
		print(f"File not found: {path}")
	except Exception as e:
		print(f"An error occurred during second pass: {e}")
	pass

def set_base_register(statement):
	global REG_B
	operand = statement[2]
	try:
		for entry in SYMBOL_TABLE:
			if operand == entry[1]:
				REG_B = int(entry[0][2:], 16)
	except Exception as e:
		print(f"an error occurred while setting base register: {e}")

def parse_operand(operand):
	try:
		if '*' in operand:
			return operand
		else:
			match = re.search(r'[A-Z0-9]+', operand)
			return match.group()
	except Exception as e:
		print(f"Error while parsing operand: {e}")

def wrap_4bit_hex(negative_hex):
    return str(hex(0xffff + (negative_hex + 0x1)))

def generate_obj_code(statement, intermediate_file):
	nixbpe = [0, 0, 0, 0, 0, 0]
	instruction = None
	operand = None
	try:
		if 2 not in range(len(statement)) or SYMBOL_TABLE == {}:
			return None
		instruction = statement[1]
		operand = statement[2]
			
		
		if instruction.startswith('+'):
			# format 4 instruction
			nixbpe[5] = 1

		if operand.startswith('#'):
			# immediate addressing
			nixbpe[1] = 1
		elif operand.startswith('@'):
			# indirect addressing
			nixbpe[0] = 1
		else:
			# simple addressing
			nixbpe[0] = 1
			nixbpe[1] = 1
		
		if re.search(r',\ ?X', operand):
			# indexed addressing
			nixbpe[2] = 1
	except Exception as e:
		print(f"Error occurred finding pre-nixbpe: {e}")
	# next i need to figure out how to get b/p
	# for that i need to program a (PC) and a (B)
	# i also need to do a first pass to make a symtab
	# this will generate location values for all symbols so that (TA) is not empty

	instruction = parse_instruction(instruction)

	form = 0
	if instruction in OPCODE_TABLE:
		form = OPCODE_TABLE[instruction][1]

	print(f'format: {form}')
	operand = None
	if len(statement) >= 2:
		if statement[2] == '': # no operand
			operand = ''
		elif instruction in OPCODE_TABLE and form == 2 and ',' in statement[2]: # format 2 instruction (not CLEAR) operand
			operand = re.findall(r'(\D+),(\D+)', statement[2])
		else: # format 3/4 instruction operand
			operand = parse_operand(statement[2])
	else:
		return None
	print(f"instruction: {instruction}")
	print(f"operand: {operand}")
	print(f"pre-nixbpe: {nixbpe}")

	# first pick which type of operand it is (c or m)
	# c means a constant between 0 and 4095
	# m means a memory address or constant value larger than 4095

	# all values in runtime should be in binary to simplify operations
	c = 0
	m = 0
	prog_block_offset = 0
	
	op = None
	location_counter_operand = None
	if not isinstance(operand, list):
		location_counter_operand = re.findall(r'(?:(\*)([+-])(\d+))|(\*)', operand)

	if not isinstance(operand, list) and re.search(r'^\d+$', operand) and not '=' in statement[2]: # if operand is numeric
		print(f"numeric operand")
		if int(operand) > 4095:
			m = bin(int(operand, 10))[2:]
		else:
			c = bin(int(operand, 10))[2:]
	elif '=' in statement[2]:
		print("literal here")
		match = re.findall(r'=(\d+)', statement[2])
		print(match[0])
		for entry in LITERAL_TABLE:
			if int(match[0]) == entry[2]:
				print(entry)
				prog_block_offset = LOCATION_COUNTERS[entry[3]][2]
				print(f"prog_block_offset: {hex(prog_block_offset)}")
				m = bin(int(entry[0], 16))[2:]
	elif location_counter_operand:
		# if there is * or *+-number in operand, this will pass
		print("location counter operand")
		print(location_counter_operand)
		location_counter_operand = location_counter_operand[0]
		if location_counter_operand[0] != '':
			if location_counter_operand[1] == '-':
				c = bin(int(statement[3], 16) - int(location_counter_operand[2]))[2:]
			else:
				c = bin(int(statement[3], 16) + int(location_counter_operand[2]))[2:]
		else:
			c = bin(int(statement[3], 16))[2:]
	elif statement[2] != '':
		# get address of operand
		print(f"operand definitely memory address symbol")
		

		# check if there is a symbol in the correct control section
		symbol = None
		for entry in SYMBOL_TABLE:
			if operand == entry[1] and entry[4] == statement[5]:
				symbol = entry

		if symbol == None:
			# symbol in symbol table is outside of the current control section
			print("symbol outside control section")
			nixbpe[5] = 1
			m = bin(0)[2:].zfill(12)
		else:
			print(type(symbol[0]), symbol[0])
			prog_block_offset = LOCATION_COUNTERS[symbol[3]][2]
			print(f"prog_block_offset: {hex(prog_block_offset)}")
			m = bin(int(symbol[0][2:], 16))[2:].zfill(8)

	# get obj code as a string of binary
	try:
		for entry in OPCODE_TABLE:
			if instruction == entry:
				op = bin(OPCODE_TABLE[entry][0])[2:]
				op = op.zfill(8)
		if op == 0:
			raise Exception("no entry in opcode table for instruction")

	except Exception as e:
		print(f"error getting opcode: {e}")


	print(f"opcode: {op}")
	print(f"c: {c}")
	print(f"m: {m}")

	# fix up nixbpe and then get it as a string of binary
	# for base relative, 0 <= disp <= 4095
	# for pc relative, -2048 <= disp <= 2047
	disp = None

	obj_code = None

	# instruction is a directive
	if form == 0:
		if statement[1] == 'BYTE':
			obj_code, code_length = get_literal_code(statement[2])
		elif statement[0] == '*':
			obj_code, code_length = get_literal_code(statement[1])

	if form == 2:
		try:
			# in format 2, registers are 1-byte values represented in object code
			r1 = ""
			r2 = ""
			
			if isinstance(operand, list):
				print(REG_VALUES[operand[0][0]])
				r1 = bin(REG_VALUES[operand[0][0]])[2:].zfill(4)
				r2 = bin(REG_VALUES[operand[0][1]])[2:].zfill(4)
				print(r1, r2)
			else:
				r1 = bin(REG_VALUES[operand[0][0]])[2:].zfill(4)
				r2 = "0000"

			obj_code = hex(int(op + r1 + r2, 2))
		except Exception as e:
			print(f"error calculating object code: {e}")

	if form == 3:
		try:
			if m:
				# assume pc relative unless disp does not follow rules
				# operand is not a constant, so we are doing relative addresing or extended format
				if nixbpe[5] == 0: # if no extended format, then relative addressing.
					nixbpe[4] = 1

			print(f"step2 nixbpe: {nixbpe}")

			# now that nixbpe has been fixed, calculate disp according to nixbpe values
			# if not x or p (at this point in code), TA is disp/address (operand value)
			
			if nixbpe[2] == 0 and nixbpe[4] == 0:
				print("disp = ta")
				if m:
					disp = m.zfill(12)
					print(disp)
				elif c:
					disp = c.zfill(12)
				else:
					disp = "000000000000"



			# if extended, then fill up the disp to make a 20-length address
			if nixbpe[5] == 1:
				print("extended")
				if disp == None:
					disp = "00000000000000000000"
				disp = disp.zfill(20)

			# now handle all relative addressing

			# pc-relative, calculate disp here
			if nixbpe[4] == 1:
				print("assuming pc-relative")
				PC = get_next_address(statement)

				disp = (int(m, 2) + prog_block_offset) - PC
				print(f"disp: {hex(disp)}")

				if disp < -2048 or disp > 2047:
					# pc-relative displacement value out of range, try base relative
					print("pc-relative displacement out of range")
					nixbpe[4] = 0
					nixbpe[3] = 1

				if disp < 0:
					disp = bin(int(wrap_4bit_hex(disp)[2:], 16))[2:].zfill(16)
				else:
					disp = bin(disp)[2:].zfill(16)

				disp = disp[4:]


			# if pc-relative fails, then base relative protocol will activate
			if nixbpe[3] == 1:
				print("using base relative")
				print(f"REG_B: {hex(REG_B)}")
				# dont forget m is target address
				disp = int(m, 2) - REG_B
				print(f"disp: {disp}")

				if disp < 0 or disp > 4095:
					raise Exception("both pc-relative and base-relative displacement values are out of bounds")

				disp = bin(disp)[2:].zfill(16)
				disp = disp[4:]

			# subtract index register value if applicable
			if nixbpe[2] == 1:
				print(f"REG_X: {hex(REG_X)}")
				disp = int(disp, 2) - REG_X
				if nixbpe[5] == 1:
					disp = bin(disp)[2:].zfill(20)
				else:
					disp = bin(disp)[2:].zfill(16)
					disp = disp[4:]

		except Exception as e:
			print(f"error calculating object code: {e}")

		print(f"disp: {disp}")

		str_nixbpe = ""
		for num in nixbpe:
			str_nixbpe += str(num)

		print(type(op), type(str_nixbpe), type(disp))
		if op and str_nixbpe and disp:
			obj_code = op[:-2] + str_nixbpe + disp
			obj_code = hex(int(obj_code, 2)).zfill(6)

	print(f"object code: {obj_code}")

	print()
	print()
	return obj_code

def print_intermediate_file(intermediate_file):
	try:
		for entry in intermediate_file:
			try:
				print(f'{entry[3]}\t {entry}')
			except Exception as e:
				print(f"you dumb idiot: {e}")
	except Exception as e:
		print(f"you have died: {e}")



print()
print()
finished_file = do_macros()
print()
print()
print()

intermediate_file = first_pass(finished_file)

print_intermediate_file(intermediate_file)

print()
print()
second_pass(intermediate_file)