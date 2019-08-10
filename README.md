[![Build Status](https://travis-ci.com/tomchop/unxor.svg?branch=master)](https://travis-ci.com/tomchop/unxor)

# unXOR

This tool will search through an XOR-encoded file (binary, text-file, whatever) and use known-plaintext attacks to deduce the original keystream. Works on keys half as long as the known-plaintext, in linear complexity.

![demo](demo.gif)

## Usage (Golang)

This should work:

    $ go install github.com/tomchop/unxor
    $ $GOBIN/unxor -h
    Usage of /Users/tomchop/code/go/bin/unxor:
    -f string
            Filename to decrypt
    -g string
            Known plaintext (string)
    -gh string
            Known plaintext (hex encoded)

# Usage (Python)

Python sources are contained in the `pyunxor` directory.

    $ cd pyunxor
    $ python unxor.py
    usage: unxor.py [-h] (-g GUESS | -k KEY) [-m {iterative,selective}] [-x]
                    [-v {0,1,2}]
                    [infile] [outfile]
    unxor.py: error: one of the arguments -g/--guess -k/--key is required


## Related Work

unXOR is included in Lenny Zeltser's [REMnux](http://zeltser.com/remnux/), along with other great tools such as:

* [XORStrings](http://blog.didierstevens.com/2013/04/15/new-tool-xorstrings/)
* [ex_pe_xor](http://hooked-on-mnemonics.blogspot.com/2014/04/expexorpy.html)
* [XORSearch](http://blog.didierstevens.com/programs/xorsearch/)
* [brutexor/iheartxor](http://hooked-on-mnemonics.blogspot.com/p/iheartxor.html)
* [xortool](https://github.com/hellman/xortool)
* [NoMoreXOR](https://github.com/hiddenillusion/NoMoreXOR)
* [XORBruteForcer](http://eternal-todo.com/category/bruteforce)
* [Balbuzard](https://bitbucket.org/decalage/balbuzard/wiki/Home)
