#!/usr/bin/env python

import os
import re
import math
import argparse
import logging

"""

unXOR
===========

This tool will search through an XOR-encoded file (binary, text-file, whatever) and use known-plaintext attacks to deduce the original keystream. Works on keys half as long as the known-plaintext, in linear complexity.

The code is pretty straightforward

For more details and a short explanation of the theory behind this, please refer to:

 - My original blogpost: http://tomchop
 - The insipiring post: http://playingwithothers.com/2012/12/20/decoding-xor-shellcode-without-a-key/

Related work:

 - Didier Steven's XORsearch : http://blog.didierstevens.com/programs/xorsearch/

Written by Thomas Chopitea (@tomchop_)

"""

# quick shannon-entropy calculation
def H(data):
  h = 0
	entropy = 0
	for x in range(256):
		p_x = float(data.count(chr(x)))/float(len(data))
		#print p_x
		if p_x > 0:
			entropy -= p_x * math.log(p_x,2)
	return entropy

# easier this way
def xor(plaintext,key):
	return "".join(chr(ord(p)^ord(k)) for p, k in zip(plaintext,key))


def iterative(crypt,search):
	
	norm_crypt = crypt
	norm_search = search
	i = 0
	find = False
	decryptions = []
	keys = []
	while len(norm_search) > 0:
		i += 1
		norm_crypt = xor(norm_crypt,crypt[i:])
		norm_search = xor(norm_search,search[i:])

		if i % 2 == 1 and len(norm_search) > 0:
			keylen = (i/2 + i%2)


			print "[*] Trying key length %s:" % keylen
			logging.info("================================================================")
			logging.info("Crypt:\t\t\t %s" % " ".join(a.encode('hex') for a in crypt))
			logging.info("Norm:\t\t\t %s" % " ".join(a.encode('hex') for a in norm_crypt)) 
			logging.info("Norm_search:\t %s" % " ".join(a.encode('hex') for a in norm_search))
			logging.info("================================================================")

			indexes = [m.start() for m in re.finditer(norm_search, norm_crypt)]

			# cycle through all search results
			if len(indexes) > 0:
				logging.info("[!] More than one occurence of the search string found. Some might be coincidence, some might not.")
				logging.info("[!] String found at %s" % ", ".join(str(a) for a in indexes))
				for index in indexes:
					logging.info("\n[*] Search term found at %s " % index)
					keystr = crypt[index:index+len(norm_search)]
					keystr_guess = "".join(chr(ord(a)^ord(b)) for a,b in zip(keystr,search))
					keystr_guess = keystr_guess[0:keylen]
					
					if len(norm_search) < keylen:
						logging.info("[.] Normalized search (%s) is shorter than key length (%s)" % (len(norm_search), keylen))
						logging.info("[.] This might be a false positive")
					print "[*] Keystream guess: %s" % keystr_guess.encode('hex')
					decrypt, key = recover_key(crypt,keystr_guess,keylen,index,search)
					find = True
					if key not in keys:
						keys.append(key)
						decryptions.append(decrypt)
			else:
				print "[!] Search term not found. Increasing norm level / key length."
	if find:
		return decryptions
	elif len(norm_search) == 0: 
		print "[!] Normalization level too high given the length of the known plaintext. Try again with a longer known plaintext."
			


def recover_key(crypt, keystr_guess, keylen, index, search):

	partial = False
	
	# this means we haven't found the whole key, some bytes are missing
	if len(keystr_guess) < keylen: partial = True

	decrypt = xor(crypt,(keystr_guess+"\0x00"))

	if len(keystr_guess) < keylen:
		logging.info("[?] Some bytes of the key are missing, taking a wild guess (assuming findings ~ search query)")
		logging.info("[?] If results don't make sense, try searching for something with less entropy (e.g. URLs)")
		logging.info("[?] Or use a longer search string")
	
	while len(keystr_guess) < keylen:
		# we take a wild guess, and suppose the keystream guess was found because of an occurrence of our search term
		findings = decrypt.find(search[:(index%len(keystr_guess))])
		keystr_guess += chr(ord(crypt[index+len(keystr_guess)])^ord(search[len(keystr_guess)]))

	# get the correct start of the keystream	
	key = keystr_guess[-(index % keylen):]
	key += keystr_guess[:-(index % keylen)]

	# repeat key as long as it's needed
	while len(key) < len(crypt):
		key += key

	print "[*] Recovered key: %s" % key[:keylen].encode('hex')

	decrypt = xor(crypt,key)
	
	return decrypt, key


# use for testing purposes
def genkey(keylen):
	key = os.urandom(keylen)
	repeat = ""
	while (len(repeat) < 200):
		repeat += key
	return repeat


if __name__ == '__main__':

	parser = argparse.ArgumentParser(description="Decode XOR-encoded files using known-plaintext attacks")
	parser.add_argument("file", help="The file to open")
	parser.add_argument("search", help="The known plaintext")
	parser.add_argument("--dump",help="Dump the decrypted data to file")
	parser.add_argument("-v", "--verbose", help="Verbose output", action="store_true")
	parser.add_argument("-x", "--hex", help="Search in hex", action="store_true")
	args = parser.parse_args()

	if args.verbose:
		logging.basicConfig(level=logging.INFO, format="%(message)s")

	with open(args.file, "r") as f:
		crypt = f.read()
	search = args.search

	# some quick statistics
	print "Stats ==================="
	print "Encrypted data length:\t%s" % len(crypt)
	print "Search string length:\t%s" % len(search)
	print "Encrypted data entropy:\t%s" % H(crypt)
	print "Search string entropy:\t%s" % H(search)
	print "=========================\n"

	decrypt = iterative(crypt,args.search)

	if args.dump:
		with open(args.dump, "w") as dump:
			for d in decrypt:
				dump.write("Decryption of file %s\n" % args.file)
				dump.write("===========================================================\n")
				dump.write(d)
				dump.write("\n===========================================================\n\n")
	else:
		for d in decrypt:
			print "\nDecryption of file %s found" % args.file
			print "==========================================================="
			print d
			print "===========================================================\n\n"
