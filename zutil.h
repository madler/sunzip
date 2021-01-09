/* zutil.h -- minimal header to enable inflateBack9() compilation
 * Copyright (C) 2021 Mark Adler
 * For conditions of distribution and use, see copyright notice in sunzip.c.
 */

#include <stdio.h>
#include <string.h>
#include "zlib.h"
#define zcalloc sunalloc
#define zcfree sunfree
void *sunalloc(void *, unsigned, unsigned);
void sunfree(void *, void *);
#define ZALLOC(strm, items, size) \
           (*((strm)->zalloc))((strm)->opaque, (items), (size))
#define ZFREE(strm, addr)  (*((strm)->zfree))((strm)->opaque, (void *)(addr))
#define zmemcpy memcpy
#define Tracev(x)
#define Tracevv(x)
