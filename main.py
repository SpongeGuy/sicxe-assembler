import re

OPCODE_TABLE = {
	"ADD": [0x18],
	"ADDF": [0x58],
	"ADDR": [0x90],
	"AND": [0x40],
	"CLEAR": [0xB4],
	"COMP": [0x28],
	"COMPF": [0x88],
	"COMPR": [0xA0],
	"DIV": [0x24],
	"DIVF": [0x64],
	"DIVR": [0x9C],
	"FIX": [0xC4],
	"FLOAT": [0xC0],
	"HIO": [0xF4],
	"J": [0x3C],
	"JEQ": [0x30],
	"JGT": [0x34],
	"JLT": [0x38],
	"JSUB": [0x48],
	"LDA": [0x00],
	"LDB": [0x68],
	"LDCH": [0x50],
	"LDF": [0x70],
	"LDL": [0x08],
	"LDS": [0x6C],
	"LDT": [0x74],
	"LDX": [0x04],
	"LPS": [0xD0],
	"MUL": [0x20],
	"MULF": [0x60],
	"MULR": [0x98],
	"NORM": [0xC8],
	"OR": [0x44],
	"RD": [0xD8],
	"RMO": [0xAC],
	"RSUB": [0x4C],
	"SHIFTL": [0xA4],
	"SHIFTR": [0xA8],
	"SIO": [0xF0],
	"SSK": [0xEC],
	"STA": [0x0C],
	"STB": [0x78],
	"STCH": [0x54],
	"STF": [0x80],
	"STI": [0xD4],
	"STL": [0x14],
	"STS": [0x7C],
	"STSW": [0xE8],
	"STT": [0x84],
	"STX": [0x10],
	"SUB": [0x1C],
	"SUBF": [0x5C],
	"SUBR": [0x94],
	"SVC": [0xB0],
	"TD": [0xE0],
	"TIO": [0xF8],
	"TIX": [0x2C],
	"TIXR": [0xB8],
	"WD": [0xDC],
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
def get_next_PC(parsed_instruction):
	global PROGRAM_COUNTER
	c = PROGRAM_COUNTER
	if parsed_instruction in OPCODE_TABLE:
		if '+' in parsed_instruction:
			c += 0x4
		else:
			c += 0x3
	return c

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
	match = re.search(r'[A-Z]+', instruction)
	return match.group()

def first_pass():
	path = "samples/functions.txt"
	global PROGRAM_COUNTER
	# iterate through file
	try:
		PROGRAM_COUNTER = 0x0000
		with open(path, 'r') as file:
			for line in file:
				statement = line.split('\t')
				print(statement)
				# column 0 is symbol, column 1 is instruction, column 2 is operand, column 3 is comment
				# fill out SYMBOL_TABLE

				# check if instruction is in opcode table, if it is, increment program counter
				# grab any labels & program counter and add to symbol table
				parsed_instruction = parse_statement_for_instruction(statement)

				# if instruction in opcode table (count for format 3/4 instructions)
				# eventually i might have to add support for format 1/2 instructions too idk
				if parsed_instruction:
					if statement[0] != '':
						SYMBOL_TABLE.append([hex(PROGRAM_COUNTER), statement[0]])

				PROGRAM_COUNTER = get_next_PC(parsed_instruction)
		print(SYMBOL_TABLE)

	except FileNotFoundError:
		print(f"File not found: {path}")
	except Exception as e:
		print(f"An error occurred: {e}")



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
				PROGRAM_COUNTER = get_next_PC(parse_statement_for_instruction(statement))
		print(SYMBOL_TABLE)

	except FileNotFoundError:
		print(f"File not found: {path}")
	except Exception as e:
		print(f"An error occurred: {e}")
	pass

def get_addressing_mode(statement):
	if 1 not in range(len(statement)) or SYMBOL_TABLE == {}:
		return None
	instruction = statement[1]
	nixbpe = [0, 0, 0, 0, 0, 0]
	if re.search(r'\+', instruction):
		# format 4 instruction
		nixbpe[5] = 1

	if re.search(r'#', instruction):
		# immediate addressing
		nixbpe[1] = 1
	elif re.search(r'@', instruction):
		# indirect addressing
		nixbpe[0] = 1
	else:
		# simple addressing
		nixbpe[0] = 1
		nixbpe[1] = 1
	
	if re.search(r',\ ?X', instruction):
		# indexed addressing
		nixbpe[2] = 1
	
	# next i need to figure out how to get b/p
	# for that i need to program a (PC) and a (B)
	# i also need to do a first pass to make a symtab
		# this will generate location values for all symbols so that (TA) is not empty
	operand = None
	if 2 not in range(len(statement)):
		return None
	operand = statement[2]
	print(f"operand: {operand}")

	TA = 0x0
	for entry in SYMBOL_TABLE:
		if statement[2] == entry[1]:
			TA = entry[0]

	disp = TA

	# handle pc-relative, change this later bc is stupid af
	if not (nixbpe[5] == 1 or nixbpe[2] == 1) and TA != 0:
		PC = get_next_PC(instruction)

		# convert ta and pc to int to subtract them
		if isinstance(TA, str):
			TA = int(TA, 16)
		if isinstance(PC, str):
			PC = int(PC, 16)

		disp = hex(TA - PC)
		disp = int(disp, 16)

		print(f"TA, PC: {hex(TA)}, {hex(PC)}")
	
	if disp != 0:
		try:
			nixbpe[4] = 1 #pc-relative

			print(f"disp: {hex(disp)}")
			# calculate object code here
			ni = [nixbpe[0], nixbpe[1]]
			opcode = OPCODE_TABLE[parse_instruction(instruction)][0]
			ni = int(''.join(map(str, ni)), 2)
			# print(bin(opcode))
			# print(bin(ni))
			# print(f"{type(opcode)}, {type(ni)}") 
			opcode = opcode + ni
			# print(bin(opcode))
			str_opcode = str(bin(opcode)).replace("0b", "")
			str_opcode = str_opcode.zfill((len(str_opcode) + 3) // 4 * 4)
			# print(f"opcode: {str_opcode}")


			xbpe = [nixbpe[2], nixbpe[3], nixbpe[4], nixbpe[5]]
			xbpe = ''.join(map(str, xbpe))
			# print(f"xbpe: {xbpe}")

			if disp > 0:
				str_disp = str(bin(disp)).replace("0b", "")
				str_disp = str_disp.zfill(12)
				# print(f"disp: {str_disp}")

				obj_code = str_opcode + xbpe + str_disp
				print(hex(int(obj_code, 2)))

		except Exception as e:
			print(f"An error occurred while calculating object code: {e}")

	#mode = ''.join(nixbpe)
	#print(f"nixbpe: {mode}")
	print()
	print()
	#return mode


print()
print()
print()

first_pass()
second_pass()