import re

OPCODE_TABLE = {
	"ADD": [0x18, 3],
	"ADDF": [0x58, 3],
	"ADDR": [0x90, 2],
	"AND": [0x40, 3],
	"CLEAR": [0xB4, 2],
	"COMP": [0x28, 3],
	"COMPF": [0x88, 3],
	"COMPR": [0xA0, 2],
	"DIV": [0x24, 3],
	"DIVF": [0x64, 3],
	"DIVR": [0x9C, 2],
	"FIX": [0xC4, 1],
	"FLOAT": [0xC0, 1],
	"HIO": [0xF4, 1],
	"J": [0x3C, 3],
	"JEQ": [0x30, 3],
	"JGT": [0x34, 3],
	"JLT": [0x38, 3],
	"JSUB": [0x48, 3],
	"LDA": [0x00, 3],
	"LDB": [0x68, 3],
	"LDCH": [0x50, 3],
	"LDF": [0x70, 3],
	"LDL": [0x08, 3],
	"LDS": [0x6C, 3],
	"LDT": [0x74, 3],
	"LDX": [0x04, 3],
	"LPS": [0xD0, 3],
	"MUL": [0x20, 3],
	"MULF": [0x60, 3],
	"MULR": [0x98, 2],
	"NORM": [0xC8, 1],
	"OR": [0x44, 3],
	"RD": [0xD8, 3],
	"RMO": [0xAC, 2],
	"RSUB": [0x4C, 3],
	"SHIFTL": [0xA4, 2],
	"SHIFTR": [0xA8, 2],
	"SIO": [0xF0, 1],
	"SSK": [0xEC, 3],
	"STA": [0x0C, 3],
	"STB": [0x78, 3],
	"STCH": [0x54, 3],
	"STF": [0x80, 3],
	"STI": [0xD4, 3],
	"STL": [0x14, 3],
	"STS": [0x7C, 3],
	"STSW": [0xE8, 3],
	"STT": [0x84, 3],
	"STX": [0x10, 3],
	"SUB": [0x1C, 3],
	"SUBF": [0x5C, 3],
	"SUBR": [0x94, 2],
	"SVC": [0xB0, 2],
	"TD": [0xE0, 3],
	"TIO": [0xF8, 1],
	"TIX": [0x2C, 3],
	"TIXR": [0xB8, 2],
	"WD": [0xDC, 3],
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
	"BYTE",
	"WORD",
	"RESW",
	"RESB",
}

SYMBOL_TABLE = []

PROGRAM_COUNTER = 0x0000
BASE_REGISTER = 0x0000

def bin_to_hex(value):
	decimal = int(value, 2)
	hex_value = hex(decimal)[2:]
	padded_hex_value = hex_value.zfill(2)
	return padded_hex_value

def hex_to_bin(value):
	decimal = int(value, 16)
	binary = bin(decimal)[2:]
	padded_binary = binary.zfill(len(value) * 4)
	return padded_binary

# take a parsed_instruction (no special characters) and returns the next pc variable based on the size of instruction
def get_next_PC(instruction):
	global PROGRAM_COUNTER
	try:
		parsed_instruction = parse_instruction(instruction)
		c = PROGRAM_COUNTER
		#print("ughhhh", parsed_instruction)
		if parsed_instruction in OPCODE_TABLE or parsed_instruction in DIRECTIVES:
			#print("yes")
			if '+' in instruction:
				c += 0x4
				#print("4")
			elif parsed_instruction in OPCODE_TABLE:
				c += OPCODE_TABLE[parsed_instruction][1]
				#print("3")
			else:
				c += 3
		return c
	except Exception as e:
		print(f"An error occurred while getting next PC: {e}")

# returns a stripped string including only capital letters (input whole statement array)
def parse_statement_for_instruction(statement):
	instruction_match = None
	parsed_instruction = None
	if 1 in range(len(statement)):
		instruction_match = re.search(r'[A-Z]+', statement[1])
	if instruction_match:
		parsed_instruction = instruction_match.group()
	return parsed_instruction

# returns a stripped string including only capital letters (input just instruction ('statement[1]' sometimes))
def parse_instruction(instruction):
	try:
		match = re.search(r'[A-Z]+', instruction)
		return match.group()
	except Exception as e:
		print(f"Error while parsing instruction: {e}")

def first_pass():
	path = "samples/functions.txt"
	global PROGRAM_COUNTER
	# iterate through file
	try:
		PROGRAM_COUNTER = 0x0000
		with open(path, 'r') as file:
			for line in file:
				statement = line.split('\t')
				# column 0 is symbol, column 1 is instruction, column 2 is operand, column 3 is comment
				# fill out SYMBOL_TABLE

				# check if instruction is in opcode table, if it is, increment program counter
				# grab any labels & program counter and add to symbol table
				#parsed_instruction = parse_statement_for_instruction(statement)
				print(statement, hex(PROGRAM_COUNTER))

				# if instruction in opcode table (count for format 3/4 instructions)
				# eventually i might have to add support for format 1/2 instructions too idk
				
				if statement[0] != '':
					SYMBOL_TABLE.append([hex(PROGRAM_COUNTER), statement[0]])
				
				if len(statement) >= 2 and statement[1]:
					PROGRAM_COUNTER = get_next_PC(statement[1])
				
				
		print(SYMBOL_TABLE)

	except FileNotFoundError:
		print(f"File not found: {path}")
	except Exception as e:
		print(f"An error occurred while first passing: {e}")



def second_pass():
	path = "samples/functions.txt"
	global PROGRAM_COUNTER
	# iterate through file
	try:
		PROGRAM_COUNTER = 0x0000
		with open(path, 'r') as file:
			for line in file:
				statement = line.split('\t')
				print(statement)
				get_addressing_mode(statement)
				if len(statement) >= 2 and statement[1]:
					PROGRAM_COUNTER = get_next_PC(statement[1])
				
		print(SYMBOL_TABLE)

	except FileNotFoundError:
		print(f"File not found: {path}")
	except Exception as e:
		print(f"An error occurred: {e}")
	pass

def parse_operand(operand):
	try:
		match = re.search(r'[A-Z0-9]+', operand)
		return match.group()
	except Exception as e:
		print(f"Error while parsing operand: {e}")

def wrap_4bit_hex(negative_hex):
    return str(hex(0xffff + (negative_hex + 0x1)))

def get_addressing_mode(statement):
	nixbpe = [0, 0, 0, 0, 0, 0]
	instruction = None
	operand = None
	try:
		if 2 not in range(len(statement)) or SYMBOL_TABLE == {}:
			return None
		instruction = statement[1]
		operand = statement[2]
			
		
		if re.search(r'\+', instruction):
			# format 4 instruction
			nixbpe[5] = 1

		if re.search(r'#', operand):
			# immediate addressing
			nixbpe[1] = 1
		elif re.search(r'@', operand):
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
	
	op = None
	if not isinstance(operand, list) and re.search(r'^\d+$', operand): # if operand is numeric
		if int(operand) > 4095:
			m = bin(int(operand, 10))[2:]
		else:
			c = bin(int(operand, 10))[2:]
	else:
		# get address of operand
		for entry in SYMBOL_TABLE:
			if operand == entry[1]:
				m = bin(int(entry[0][2:], 16))[2:].zfill(8)

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
				if nixbpe[5] == 0: # if no extended format, then relative addressing.
					nixbpe[4] = 1

			print(f"step2 nixbpe: {nixbpe}")

			# now that nixbpe has been fixed, calculate disp according to nixbpe values
			# if not x or p (at this point in code), TA is disp/address (operand value)
			
			if nixbpe[2] == 0 and nixbpe[4] == 0:
				print("disp = ta")
				if m:
					print('hero')
					disp = m.zfill(12)
					print(disp)
				elif c:
					disp = c.zfill(12)
				else:
					disp = "000000000000"

			# if extended, then fill up the disp to make a 20-length address
			if nixbpe[5] == 1:
				print("extended")
				disp = disp.zfill(20)

			# now handle all relative addressing

			# pc-relative, calculate disp here
			if nixbpe[4] == 1:
				print("assuming pc-relative")
				PC = get_next_PC(instruction)
				print(int(m, 2) - PC)
				disp = int(m, 2) - PC

				if disp < -2048:
					raise Exception("ERROR: displacement value cannot be less than 2048")
				if disp > 2047:
					raise Exception("base relative handle here")

				if disp < 0:
					disp = bin(int(wrap_4bit_hex(disp)[2:], 16))[2:].zfill(16)
					print(disp, type(disp))
				else:
					disp = bin(disp)[2:].zfill(16)

				disp = disp[4:]

			if nixbpe[2] == 1:
				raise Exception("i dont know how to do index addressing yet")
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




print()
print()
print()

first_pass()
second_pass()