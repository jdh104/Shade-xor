#!/usr/bin/env python3

Author = "Jonah Haney"
Version = "2017.9.21"

import os
import sys
import argparse

files = []

parser = argparse.ArgumentParser()
key_type_group = parser.add_mutually_exclusive_group(required = True)

key_type_group.add_argument("-p", metavar = "<P>", dest = "p", help = "Use Passphrase <P> as key (relatively vulnerable)", default = None)
key_type_group.add_argument("-F", metavar = "<K>", dest = "F", help = "Use File <K> as key", default = None)
key_type_group.add_argument("-G", metavar = "<K>", dest = "G", help = "Generate keyfile named <K>", default = None)
parser.add_argument("-s", metavar = "<S>", dest = "s", help = "Generate random key of size <S> in bytes (Default: 16) Ignored if -G not used (Note: key sizes higher than 16 illegal for international use [USA])", default = 16, type = int)
parser.add_argument("f", metavar = "<file>", help = "File(s) to operate on", nargs = "*")

args = parser.parse_args()

# Print message to stderr without flushing
def log(message):
	sys.stderr.buffer.write(bytes([ord(c) for c in str(sys.argv[0] + ": " + message + "\n")]))

# Exit with an exit message (to stderr) and de-allocate all file resources
def terminate(exit_message):
	log(exit_message)
	for f in files:
		try:
			f.close()
		except:
			log("Failed to close file: " + f.name)
	sys.stderr.flush()
	quit()

# Open a file, use this in place of open()
def fopen(file_name, mode):
	try:
		t = open(file_name, mode)
		files.append(t)
		return t
	except:
		log("Could not open file: " + file_name)
		return None

# Extends or trims key to given size
def keystream(key, size):
	return key * (int(size / len(key))) + key[:(size % len(key))]

# Basic xor crypto, returns array of bytes
# NOTE that keyfile must be file_2
def xor_with_file(file_1, file_2):
	log("\nOperating on " + file_1.name + " ...")
	
	# Initialize below loop
	x, y = file_1.read(1), file_2.read(1)
	z = fopen(".shade.temp", "rb+")
	len_1, len_2 = os.path.getsize(file_1.name), os.path.getsize(file_2.name)
	check, addup = 0, 0
	i, mile = 0, 1
	goal = max(len_1, len_2)
	while i < goal:
		z.write(bytes([ord(x) ^ ord(y)]))
		i += 1

		# Scrambler Start ######################
		addup = (addup + ord(y) + 1) % 0x100  ##
		check = (addup + check) % len_2       ##
		file_2.seek(check)                    ##
		# Scrambler End ########################

		x, y = file_1.read(1), file_2.read(1)
		if (x == b''): # Should only happen if keysize > opsize
			overwrite(z, file_1)
			file_1.seek(0)
			x = file_1.read(1)
			z.seek(0)
		if (y == b''): # Shouldn't happen
			file_2.seek(0)
			y = file_2.read(1)
			log("Unexpected end of keyfile reached, fixed")
		if (i * 100) / goal > mile: # Progress Logging
			log(str(i * 100 / goal)[:5] + "%")
			mile = (i * 100 / goal) + 1
			sys.stderr.flush()
	return z

# Used when given a passphrase instead of a file (note the plaintext attack vector vulnerability)
def xor_with_pass(op, key):
	log("\nOperating on " + op.name + " ...")
	x = op.read(1)
	z = fopen(".shade.temp", "wb+")
	len_1, len_2 = os.path.getsize(op.name), len(key)
	goal = max(len_1, len_2)
	check, addup = 0, 0
	mile = 1
	while i < goal:
		z.write(bytes([ord(x) ^ ord(key[check])]))

		# Scrambler Start ###############################
		addup = (addup + ord(key[check]) + 1) % 0x100  ##
		check = (addup + check) % len_2                ##
		# Scrambler End #################################
		
		x = op.read(1)
		i += 1
		if (i * 100) / goal > mile: # Progress Logging:
			log(str(i * 100 / goal)[:5] + "%")
			mile = (i * 100 / goal) + 1
			sys.stderr.flush()

		if x == b'': # End of operand file:
			overwrite(z, op)
			z.seek(0)
			op.seek(0)
			x = op.read(1)
	return z

# Do not use, irreversible as is
def shift_bytes(bytes_1, bytes_2):
	terminate("Error: shifting not implemented yet") #TODO

# Do not use, irreversible as is
def unshift_bytes(bytes_1, bytes_2):
	terminate("Error: shifting not implemented yet") #TODO

# Write contents of file 'fro' to file 'to'
def overwrite(fro, to):
	to.seek(0)
	fro.seek(0)
	x = fro.read(1)
	while x != b'':
		to.write(x)
		x = fro.read(1)
	to.truncate()

# Generate cryptographically secure random byte stream for key
def generate_key_file(name, strength):
	gen = fopen(name, "wb+")
	for i in range(strength):
		last = os.urandom(1)[0]
		gen.write(bytes([last]))
	gen.truncate()
	gen.seek(0)
	return gen

#####################################################
#####################################################
#####################################################
##################                 ##################
##################      BEGIN      ##################
##################                 ##################
#####################################################
#####################################################
#####################################################

keyfile = None
key = None

if args.G:
	keyfile = generate_key_file(args.G, args.s)
elif args.F:
	keyfile = fopen(args.F, "rb+")
else: #if args.p
	key = args.p

if key == None and keyfile == None:
	terminate("Error: No valid key given")

for op in args.f:
	operand = fopen(op, "rb+")
	result = None
	
	if keyfile != None:
		if operand == None:
			terminate("No file to convert")
		else:
			result = xor_with_file(operand, keyfile)
	else:
		key = keystream(key, os.path.getsize(operand.name))
		result = xor_with_pass(operand, key)
	overwrite(result, operand)
	os.remove(".shade.temp")

terminate("Success")
