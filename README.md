
# makepoly

**makepoly** is a simple program that can make any executable polymorphic.

## platform

The target platform is the Linux operating system.  
Additionally due to the _rdrand_ instruction, **makepoly** can be executed only on a x86-64 cpu that supports the _rdrand_ extension.

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

## example

```
$ objdump -h example | grep -E ".text"
Idx Name          Size      VMA               LMA               File off  Algn
 12 .text         00000311  0000000000400530  0000000000400530  00000530  2**4
```

```
$ objdump -x example | grep -E "hello|decrypt"
SYMBOL TABLE:
000000000040062b l       .text	0000000000000000              decrypt
000000000040067d l       .text	0000000000000000              decrypt.dec_loop
0000000000400688 l       .text	0000000000000000              decrypt.dec_func
00000000004007c0 l       .text	0000000000000000              hello
00000000004007d0 l       .text	0000000000000000              hello.end
```

Executing the precedent commands we now know the offsets of the begin and the end of the section to encrypt (_hello_ and _hello.end_) and the offset of the section in which to place the decrypt function (_decrypt.dec_func_). Now we can make polymorphic the program _example_.

```
$ makepoly example 7c0 7d0 688
```

This will create an encrypted version of the program _example_ called _example.poly_.

