
# makepoly

**makepoly** is a simple program that can make any executable polymorphic.

## platform

The target platform is the Linux operating system.  
Furthermore, due to the _rdrand_ instruction, **makepoly** can be executed only on a x86-64 cpu that supports the _rdrand_ extension.

## installation

```
git clone https://github.com/loreloc/makepoly.git
cd makepoly
make makepoly
sudo make install
```

Additionaly, build the example with:
```
make example
```

## usage

In order to use **makepoly** , the target executable must contain a _DECRYPTOR_SECTION_ (see _makepoly.inc_ and _example.asm_) that is a piece of code that contains the function used by the program to decrypt itself. Also, the section to encrypt must be aligned to 16 bytes and its size must be a multiple of 16. The macro _DECRYPTOR_SECTION_ defines two local labels: _.makepoly_loop_ and _.makepoly_func_ that are, respectively, the begin of the decryptor loop and the begin of the decryption function.  

**makepoly** takes 4 input parameters:
- The filename of the executable to make polymorphic
- The offset in the executable file of the section to encrypt
- The size of the section to encrypt
- The offset in the executable file in which to place the decrypt function

Note: All the integer parameters must be passed in the hexadecimal format.  

When executed, **makepoly** randomly generates the encryption and the decryption functions. The encryption function is used to encrypt the section specified by the user. The decryption function is placed in the _DECRYPTOR_SECTION_ at the offset specified by the user. So, when the output executable is executed, it will decrypt parts of itself executing the _DECRYPTOR_SECTION_.

## example

Executing the following commands we know the offset of the section to encrypt (_hello_), the size of the section to encrypt (the difference between the offsets of the labels _hello.end_ and _hello_), and the offset in which to place the decrypt function (_decrypt.makepoly_func_).

```
$ objdump -h example | grep -E ".text"
 12 .text         00000311  0000000000400530  0000000000400530  00000530  2**4
```

```
$ objdump -x example | grep -E "hello|decrypt"
000000000040062b l       .text	0000000000000000              decrypt
000000000040067d l       .text	0000000000000000              decrypt.makepoly_loop
0000000000400688 l       .text	0000000000000000              decrypt.makepoly_func
00000000004007c0 l       .text	0000000000000000              hello
00000000004007d0 l       .text	0000000000000000              hello.end
```

This will create a random encrypted version of the program _example_ called _example.poly_.

```
$ makepoly example 7c0 10 688
```

