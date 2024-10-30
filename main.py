OPCODE_TABLE = {
	"ADD": "18",
	"ADDF": "58",
	"ADDR": "90",
	"AND": "40",
	"CLEAR": "B4",
	"COMP": "28",
	"COMPF": "88",
	"COMPR": "A0",
	"DIV": "24",
	"DIVF": "64",
	"DIVR": "9C",
	"FIX": "C4",
	"FLOAT": "C0",
	"HIO": "F4",
	"J": "3C",
	"JEQ": "30",
	"JGT": "34",
	"JLT": "38",
	"JSUB": "48",
	"LDA": "00",
	"LDB": "68",
	"LDCH": "50",
	"LDF": "70",
	"LDL": "08",
	"LDS": "6C",
	"LDT": "74",
	"LDX": "04",
	"LPS": "D0",
	"MUL": "20",
	"MULF": "60",
	"MULR": "98",
	"NORM": "C8",
	"OR": "44",
	"RD": "D8",
	"RMO": "AC",
	"RSUB": "4C",
	"SHIFTL": "A4",
	"SHIFTR": "A8",
	"SIO": "F0",
	"SSK": "EC",
	"STA": "0C",
	"STB": "78",
	"STCH": "54",
	"STF": "80",
	"STI": "D4",
	"STL": "14",
	"STS": "7C",
	"STSW": "E8",
	"STT": "84",
	"STX": "10",
	"SUB": "1C",
	"SUBF": "5C",
	"SUBR": "94",
	"SVC": "B0",
	"TD": "E0",
	"TIO": "F8",
	"TIX": "2C",
	"TIXR": "B8",
	"WD": "DC",
}

PROGRAM_COUNTER = 0
BASE_REGISTER = 0

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

def first_pass():
	# iterate through
	pass

def second_pass():
	pass

def get_addressing_mode(instruction):
	nixbpe = ["0", "0", "0", "0", "0", "0"]
	if '+' in instruction:
		# format 4 instruction
		nixbpe[5] = "1"

	if '#' in instruction:
		# immediate addressing
		nixbpe[1] = "1"
	elif '@' in instruction:
		# indirect addressing
		nixbpe[0] = "1"
	else:
		# simple addressing
		nixbpe[0] = "1"
		nixbpe[1] = "1"

	# next i need to figure out how to get b/p
	# for that i need to program a (PC) and a (B)
	# i also need to do a first pass to make a symtab
		# this will generate location values for all symbols so that (TA) is not empty
	mode = ''.join(nixbpe)
	print(mode)

print(hex_to_bin(OPCODE_TABLE["SVC"]))
get_addressing_mode("+JSUB	#WRECC")