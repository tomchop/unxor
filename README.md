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
