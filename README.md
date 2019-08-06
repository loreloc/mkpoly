
# mkpoly

**mkpoly** is a simple program that can make any executable polymorphic.

## platform

The target platform is the Linux operating system.

## installation

```
git clone https://github.com/loreloc/mkpoly.git
cd mkpoly
make
sudo make install
```

Additionaly, build the example with:
```
nasm -f elf64 example.asm
gcc -no-pie example.o -o example
```

## usage

In order to use **mkpoly**, the target executable must contains a _DECRYPTOR_SECTION_ (see _mkpoly.inc_ and _example.asm_) that is a piece of code that contains the function used by the program to decrypt itself. Also, the section to encrypt must be aligned to 16 bytes and its size must be a multiple of 16. The macro _DECRYPTOR_SECTION_ defines two local labels: _.mkpoly_loop_ and _.mkpoly_func_ that are, respectively, the begin of the decryptor loop and the begin of the decryption function.  

**mkpoly** takes 4 input parameters (all in the hexadecimal format):
- The filename of the binary to make polymorphic
- The offset in the binary file of the section to encrypt
- The size of the section to encrypt
- The offset in the binary file where to place the decrypt function

When executed, the polymorphic engine randomly generates the encryption and the decryption functions. The encryption function is used to encrypt the section specified by the user. The decryption function is placed in the _DECRYPTOR_SECTION_ at the offset specified by the user. So, when the output binary is executed, it will decrypt parts of itself executing the _DECRYPTOR_SECTION_.

## example

Executing the following commands we know the offset of the section to encrypt (_hello_), the size of the section to encrypt (the difference between the offsets of the labels _hello.end_ and _hello_), and the offset in which to place the decrypt function (_decrypt.mkpoly_func_).

```
$ objdump -h example | grep -E ".text"
 12 .text         00000315  0000000000401060  0000000000401060  00001060  2**4
```

```
$ objdump -x example | grep -E "hello|decrypt"
000000000040115e l       .text	0000000000000000              decrypt
00000000004011b0 l       .text	0000000000000000              decrypt.mkpoly_loop
00000000004011bb l       .text	0000000000000000              decrypt.mkpoly_func
00000000004012f0 l       .text	0000000000000000              hello
0000000000401300 l       .text	0000000000000000              hello.end
```

This will create a random encrypted version of the program _example_ called _example.crypt_.

```
$ mkpoly example 12f0 10 11bb
```

