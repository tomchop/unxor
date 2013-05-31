# Citadel config reader

from Crypto.Cipher import AES    
import struct
import argparse
import re
import unxor

# from SANS (Harshit Nayyar, harshit.nayyar@telus.com) 
# http://www.sans.org/reading_room/whitepapers/malicious/clash-titans-zeus-spyeye_33393

def getBit(pos, recordDataEncoded, fourBytes, count):
#Get the bit at position count. If count == 0, reinitialize count and move to #next decompression.
	if count == 0:
		count = 31
		fourBytes = struct.unpack('<L', recordDataEncoded[pos:pos+4])[0]
		#print 'Read Four Bytes: 0x%.8X at Pos: %d'%(fourBytes, pos)
		pos += 4
	else:
		count -= 1
	bit = ((fourBytes >> count ) & 1)
	return (bit, pos, fourBytes, count)


def nrv2b_decompress(recordDataEncoded):
	recordDataDecoded = ''
	sPos = 0
	dPos = 0
	lastMOff = 1
	shift = 0
	fourBytes = 0

	#Main Loop
	while True:
		if sPos >= len(recordDataEncoded):
			return recordDataDecoded
		#print 'first shift is: 0x%x'%(shift)
		(gb, sPos, fourBytes, shift) = getBit(sPos, recordDataEncoded, fourBytes, shift)
		while(gb != 0):
			recordDataDecoded += recordDataEncoded[sPos]
			sPos += 1
			if sPos > len(recordDataEncoded):
				#print 'Record Data Len Exceeded 1'
				return recordDataDecoded
			dPos += 1
			(gb, sPos, fourBytes, shift) = getBit(sPos, recordDataEncoded, fourBytes, shift)

		#mOff calculation
		if sPos >= len(recordDataEncoded):
			return recordDataDecoded
		(gb, sPos, fourBytes, shift) = getBit(sPos, recordDataEncoded, fourBytes, shift)

		mOff = 2+gb
		if sPos >= len(recordDataEncoded):
			return recordDataDecoded
		(gb, sPos, fourBytes, shift) = getBit(sPos, recordDataEncoded, fourBytes, shift)

		while(gb == 0):
			if sPos >= len(recordDataEncoded):
				return recordDataDecoded
			(gb, sPos, fourBytes, shift) = getBit(sPos, recordDataEncoded, fourBytes, shift)
			mOff = 2*mOff + gb
			if sPos >= len(recordDataEncoded):
				return recordDataDecoded
			(gb, sPos, fourBytes, shift) = getBit(sPos, recordDataEncoded, fourBytes, shift)

		if mOff == 2:
			mOff = lastMOff
		else:
			mOff = (mOff - 3) * 256 + ord(recordDataEncoded[sPos])
			sPos += 1
			if sPos > len(recordDataEncoded):
				#print 'Record Data Len Exceeded 2'
				return recordDataDecoded
		
			if int(mOff) == -1:
				break;
			else:
				mOff += 1
				lastMOff = mOff

		#mLen calculation
		if sPos >= len(recordDataEncoded):
			return recordDataDecoded
		(mLen, sPos, fourBytes, shift) = getBit(sPos, recordDataEncoded, fourBytes, shift)
		if sPos >= len(recordDataEncoded):
			return recordDataDecoded
		(gb, sPos, fourBytes, shift) = getBit(sPos, recordDataEncoded, fourBytes, shift)

		mLen = mLen*2 + gb
		if mLen == 0:
			mLen += 1
			if sPos >= len(recordDataEncoded):
				return recordDataDecoded
			(gb, sPos, fourBytes, shift) = getBit(sPos, recordDataEncoded, fourBytes, shift)
			mLen = 2*mLen + gb
			if sPos >= len(recordDataEncoded):
				return recordDataDecoded
			(gb, sPos, fourBytes, shift) = getBit(sPos, recordDataEncoded, fourBytes, shift)
			while (gb == 0):
				if sPos >= len(recordDataEncoded):
					return recordDataDecoded
				(gb, sPos, fourBytes, shift) = getBit(sPos, recordDataEncoded, fourBytes, shift)
				mLen = 2*mLen + gb
				(gb, sPos, fourBytes, shift) = getBit(sPos, recordDataEncoded, fourBytes, shift)
			mLen += 2
		#print 'mLen after loop is: 0x%.8X'%mLen

		mPos = dPos - mOff
		if mPos < 0:
			#print 'mPos is negative'
			#t = input()
			return recordDataDecoded
		if mPos > dPos:
			#print 'Oops mPos exceeds dPos'
			#t = input()
			return recordDataDecoded

		#Copy uncompressed data
		recordDataDecoded += recordDataDecoded[mPos]
		mPos += 1
		dPos += 1
		while mLen > 0:
			mLen -= 1
			recordDataDecoded += recordDataDecoded[mPos]
			dPos += 1
			mPos += 1

	return recordDataDecoded


def xor(a,b):
	return "".join(chr(ord(a)^ord(b)) for a, b in zip(a,b))

def enum(**enums):
    return type('Enum', (), enums)


class CitadelConfig(dict):

	BLOCK_TAGS = {	'214e0000': "Builder version", 
					"2a4e0000": "Host commands",
					"294e0000": "Web redirections",
					"224e0000": "Update URL for bot binary", 
					"234e0000": "Drop URL",
					"244e0000": "Update URL for the Configuration, web inject followed",
					"274e0000": "Target URLs for the browser html injection attack"}


	def __init__(self, config):
		self.cursor = 0
		self.data = config
		self.blocks = []

	def decode(self):
		self.random_bytes = self.getb(20)
		self.data_length = struct.unpack("<I",self.getb(4))[0]
		#print self.data_length
		self.unknown = self.getb(4)
		self.data_block_count = struct.unpack("<I",self.getb(4))[0]
		#print self.data_block_count
		self.hash = self.getb(16)

		
		for i in range(10):
			block = {}
			block['block_tag'] = self.getb(4).encode('hex')
			block['compress_tag'] = struct.unpack("<?",self.getb(4)[0])[0]
			#block['compress_tag'] = self.getb(4).encode('hex')
			block['compressed_data_length'] = struct.unpack("<I",self.getb(4))[0]
			block['original_data_length'] = struct.unpack("<I",self.getb(4))[0]
			data = self.getb(block['compressed_data_length'])
			if block['compress_tag']:
				data = nrv2b_decompress(data)
			block['data'] = data

			self.blocks.append(block)

		print "Finished decoding conf file : %s bytes decoded" % self.cursor
		
	def replchars_to_hex(self, match):
		    return r'\x{0:02x}'.format(ord(match.group()))

	def print_all(self):

		replchars = re.compile(r'[\x00-\xff]')

		injects = []
		injected_urls = []

		for block in self.blocks:
			if block['block_tag'] == "274e0000": # if we're dealing with sites concerned by webinjects
				self.data = block['data']
				self.cursor = 0
				while self.cursor < len(block['data']):
					mask = self.getb(2)
					length = ord(self.getb(1))
					url = self.getb(length-len(mask)-1)
					#print url
					injected_urls.append(url)
	
		print "Block count: %s" % self.data_block_count

		for (i, block) in enumerate(self.blocks):
			print "Block #%s ====================================" % i
			inject_id = None
			if block['block_tag'] in self.BLOCK_TAGS:
				#print block['block_tag'][:4], self.BLOCK_TAGS
				print "Block type: %s (%s)" % (str(block['block_tag']), self.BLOCK_TAGS[str(block['block_tag'])])
			else:
				
				# is the block an inject ? attempt to decode injectID
				try:
					inject_id = struct.unpack("<I", block['block_tag'].decode('hex'))[0]
					print "Block type: inject (ID: %s)" % inject_id
				except Exception, e:
					print "Block type: %s (unknown)" % str(block['block_tag'])
				
			print "Compressed: %s" % block['compress_tag']
			print "Data length: %s (compressed: %s)" %(block['original_data_length'], block['compressed_data_length'])
			print "Actual data length: %s" % (len(block['data']))
			print "Data:\n"
			if inject_id:
				inj = block['data']
				self.cursor = 0
				self.data = inj
				print "Target URL: %s\n" % injected_urls[inject_id-1]
				while self.cursor < len(inj):
					blocklen = struct.unpack("<I", self.getb(4))[0]
					print "DATA_BEFORE"
					if blocklen-4 > 0: print self.getb(blocklen-4) #print block content
					print "END_DATA_BEFORE\n"
					
					blocklen = struct.unpack("<I", self.getb(4))[0]
					print "DATA_AFTER"
					if blocklen-4 > 0: print self.getb(blocklen-4)
					print "END_DATA_AFTER\n"

					blocklen = struct.unpack("<I", self.getb(4))[0]
					print "INJECT"
					if blocklen-4 > 0: print self.getb(blocklen-4)
					print "END_INJECT\n"
				
			else:
				if block['block_tag'] == "294e0000":
					print "Data length: %s" % len(block['data'])
					#f = open('test2','w+')
					#f.write(block['data'])
					#f.close()
				if block['block_tag'] == "274e0000": # if we're dealing with sites concerned by webinjects
					
					self.data = block['data']
					self.cursor = 0
					while self.cursor < len(block['data']):
						mask = self.getb(2)
						length = ord(self.getb(1))
						url = self.getb(length-len(mask)-1)
						#print url
						print url
						injected_urls.append(url)
				else:	# regular / other data
					#block['data'] = block['data'].replace('\x00','\\x00')
					#block['data']= replchars.sub(self.replchars_to_hex, block['data'])
					#block['data']= block['data'].replace("d0",'\n').replace("\\x0d\\x0a","\n")
					print block['data'].replace('\x00','\n')

			print "\n"

			

	def getb(self, bytes, desc=""):
		#print "reading %s from %s to %s " % (desc, self.cursor, self.cursor+bytes)
		data = self.data[self.cursor:self.cursor+bytes]
		self.cursor = self.cursor + bytes
		return data
		
def visualDecrypt(cipher):
	cipher = [v for v in cipher]

	cipherlen = len(cipher)

	i = cipherlen-1
	while i > 0:
	  cipher[i] = chr(ord(cipher[i]) ^ ord(cipher[i-1]) )
	  i = i-1

	conf = "".join(cipher)

	return conf

def visualEncrypt(plaintext):
	plaintext = [p for p in plaintext]

	for x in range(len(plaintext)-1):
	    byte = chr(ord(plaintext[x]) ^ ord(plaintext[x+1]) )
	    plaintext[x+1] = byte

	return "".join(plaintext)



if __name__ == '__main__':

	parser = argparse.ArgumentParser(description='Decrypt Citadel v. 1.3.4.5 config file')

	parser.add_argument('file', help="Encrypted configuration file")
	parser.add_argument('key', help="AES key dumped with volatility (in hex: FF00FF00)")

	args = parser.parse_args()

	#secret = "FC2445EACE9D83B5BAD410411E2793F7".decode('hex')
	secret = args.key.decode('hex')

	ciphertext = ""
	try:
		f = open(args.file,'r')
		ciphertext = f.read()
		f.close()
	except Exception, e:
		print "Error opening file: %s" % e
	
	print "First bytes of key: %s" % secret.encode('hex')
	print "First bytes of ciphertext: %s" % ciphertext[:10].encode('hex')

	c = AES.new(secret,AES.MODE_ECB)
	aesdecrypt = c.decrypt(ciphertext)

	# try to break the extra xor using unxor.py
	search = "/0x0004/file.php|file=config.bin"
	#search = "/asdasdasdasdasdasdasdasdasd.bin"

	for a in range(256):
		vencrypt = visualEncrypt(chr(a)+search)
		decrypt, keys = unxor.decryption(aesdecrypt, vencrypt, "selective")
		if decrypt:
			print "====================== %s"% a
			for i, key in enumerate(keys):
				final = visualDecrypt(decrypt[i])
				index = final.find(search)
				if final.find(search) != -1 and len(key) == 16:
					print "YAY (where: %s, keylen: %s)" % (final.find(search), len(key))
					print final[index-20:index+len(search)+20]
					#print final

	print final

	exit()

	c=CitadelConfig(conf)
	c.decode()
	c.print_all()

	#print str(conf)


