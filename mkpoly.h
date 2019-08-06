
#ifndef __MKPOLY_H__
#define __MKPOLY_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/**
 * Print an helpful message.
 */
void help();

/**
 * Execute the polymorphic engine.
 * @param coff The offset of the section to crypt.
 * @param csize The size of the section to crypt.
 * @param eoff The offset where to place the decryptor.
 * @return non-zero if an error occurred.
 */
extern int polyeng(uint8_t *bin, size_t coff, size_t csize, size_t eoff);

#endif // __MKPOLY_H__

