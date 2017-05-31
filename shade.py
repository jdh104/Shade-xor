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
parser.add_argument("-s", metavar = "<S>", dest = "s", help = "Generate random key of size <S> in bytes (Default: 4096) Ignored if -G not used", default = 4096, type = int)
parser.add_argument("f", metavar = "<file>", help = "File to operate on")

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
	x, y = file_1.read(1), file_2.read(1)
	z = fopen(".shade.temp", "wb+")
	while x != b'':
		z.write(bytes([ord(x) ^ ord(y)]))
		x, y = file_1.read(1), file_2.read(1)
		if (y == b''):
			file_2.seek(0)
			y = file_2.read(1)
	return z

def xor_with_key(op, key):
	x = op.read(1)
	z = fopen(".shade.temp", "wb+")
	i = 0
	while x != b'':
		z.write(bytes([ord(x) ^ ord(key[i])]))
		x = op.read(1)
		i += 1
	return z

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

operand = fopen(args.f, "rb+")
keyfile = None
key = None
result = None

if args.p != None:
	key = args.p
elif args.F != None:
	keyfile = fopen(args.F, "rb+")
else: #if args.G
	keyfile = generate_key_file(args.G, args.s) 

if (key == None):
	if keyfile == None:
		terminate("Error: No valid key given")
	else:
		result = xor_with_file(operand, keyfile)
else:
	key = keystream(key, os.path.getsize(operand.name))
	result = xor_with_key(operand, key)
overwrite(result, operand)
os.remove(result.name)
terminate("Successful conversion")
