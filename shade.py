#!/usr/bin/env python3

import os
import sys
import argparse

files = []

parser = argparse.ArgumentParser()
key_type_group = parser.add_mutually_exclusive_group(required = True)

key_type_group.add_argument("-p", metavar = "<K>", dest = "p", help = "Use Passphrase <K> as key", default = None)
key_type_group.add_argument("-F", metavar = "<K>", dest = "F", help = "Use File <K> as key", default = None)
key_type_group.add_argument("-G", metavar = "<K>", dest = "G", help = "Generate keyfile named <K>", default = None)
parser.add_argument("-s", metavar = "<S>", dest = "s", help = "Generate random key of size <S> in bytes (Default: 64) Ignored if -G not used", default = 64, type = int)
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
def xor_with_file(file_1, file_2):
	log("\nOperating on " + file_1.name + " ...")
	x, y = file_1.read(1), file_2.read(1)
	z = fopen(".shade.temp", "wb+")
	flag1, flag2 = False, False
	goal = max(os.path.getsize(file_1.name), os.path.getsize(file_2.name))
	mile = 1
	i = 0
	while (not flag1) or (not flag2):
		z.write(bytes([ord(x) ^ ord(y)]))
		i += 1
		x, y = file_1.read(1), file_2.read(1)
		if (x == b''):
			file_1.seek(0)
			x = file_1.read(1)
			z.seek(0)
			flag1 = True
		if (y == b''):
			file_2.seek(0)
			y = file_2.read(1)
			flag2 = True
		if (i * 100) / goal > mile:
			log(str(i * 100 / goal)[:5] + "%")
			mile = (i * 100 / goal) + 1
			sys.stderr.flush()
	return z

def xor_with_key(op, key):
	log("\nOperating on " + op.name + " ...")
	x = op.read(1)
	z = fopen(".shade.temp", "wb+")
	goal = max(os.path.getsize(op.name), len(key))
	mile = 1
	i = 0
	while x != b'':
		z.write(bytes([ord(x) ^ ord(key[i])]))
		x = op.read(1)
		i += 1
		if (i * 100) / goal > mile:
			log(str(i * 100 / goal)[:5] + "%")
			mile = (i * 100 / goal) + 1
			sys.stderr.flush()
	return z

# Do not use, irreversible as is
def shift_bytes(bytes_1, bytes_2):
	if len(bytes_1) != len(bytes_2):
		log("Error: shift_bytes not same length")
		return None
	else:
		result = []
		for i in range(len(bytes_1)):
			result.append(bytes_1[i] >> bytes_2[i]) # NOT COMPLETE, NEED TO ROTATE
		return result

# Do not use, irreversible as is
def unshift_bytes(bytes_1, bytes_2):
	if len(bytes_1) != len(bytes_2):
		log("Error: unshift_bytes not same length")
		return None
	else:
		result = []
		for i in range(len(bytes_1)):
			result.append(bytes_1[i] << bytes_2[i]) # NOT COMPLETE, NEED TO ROTATE
		return result

def overwrite(fro, to):
	to.seek(0)
	fro.seek(0)
	x = fro.read(1)
	while x != b'':
		to.write(x)
		x = fro.read(1)
	

def generate_key_file(name, strength):
	gen = fopen(name, "wb+")
	for i in range(strength):
		gen.write(os.urandom(1))
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
		result = xor_with_file(operand, keyfile)
	else:
		key = keystream(key, os.path.getsize(operand.name))
		result = xor_with_key(operand, key)
	overwrite(result, operand)
	os.remove(".shade.temp")

terminate("Successful conversion")
