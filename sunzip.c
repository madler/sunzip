/* sunzip.c -- streaming unzip for reading a zip file from stdin
  Copyright (C) 2006, 2014, 2016, 2021 Mark Adler
  version 0.5  6 Jan 2021

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the author be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Mark Adler    madler@alumni.caltech.edu
 */

/* Version history:
   0.1   3 Jun 2006  First version -- verifies deflated and stored entries
   0.2   4 Jun 2006  Add more PK signatures to reject or ignore
                     Allow for an Info-ZIP zip data descriptor signature
                     as well as a PKWare appnote data descriptor (no signature)
   0.3   4 Jul 2006  Handle (by skipping) digital sig and zip64 end fields
                     Use read() from stdin for speed (unbuffered)
                     Use inflateBack() instead of inflate() for speed
                     Handle deflate64 entries with inflateBack9()
                     Add quiet (-q) and really quiet (-qq) options
                     If stdin not redirected, give command help
                     Write out files, add -t option to just test
                     Add -o option to overwrite existing files
                     Decode and apply MS-DOS timestamp
                     Decode and apply Unix timestamp extra fields
                     Allow for several different types of data descriptors
                     Handle bzip2 (method 12) decompression
                     Process zip64 local headers and use full lengths
                     Use central directory for names to allow conversion
                     Apply external attributes from central directory
                     Detect and create symbolic links
                     Catch user interrupt and delete temporary junk
   0.31  7 Jul 2006  Get name from UTF-8 extra field if present
                     Fix zip64central offset bug
                     Change null-replacement character to underscore
                     Fix bad() error message mid-line handling
                     Fix stored length corruption bug
                     Verify that stored lengths are equal
                     Use larger input buffer when int type is large
                     Don't use calloc() when int type is large
   0.32 14 Jul 2006  Consolidate and simplify extra field processing
                     Use more portable stat() structure definitions
                     Allow use of mktemp() when mkdtemp() is not available
   0.33 23 Jul 2006  Replace futimes() with utimes() for portability
                     Fix bug in bzip2 decoding
                     Do two passes on command options to allow any order
                     Change pathbrk() return value to simplify usage
                     Protect against parent references ("..") in file names
                     Move name processing to after possibly getting UTF-8 name
   0.34 15 Jan 2014  Add option to change the replacement character for ..
                     Fix bug in the handling of extended timestamps
                     Allow bit 11 to be set in general purpose flags
   0.4  11 Jul 2016  Use blast for DCL imploded entries (method 10)
                     Add zlib license
   0.5   6 Jan 2021  Add -r option to retain temporary files in the event of
                     an error.

 */

/* Notes:
   - Compile and link sunzip with zlib 1.2.3 or later and libbzip2.
 */

/* To-do:
   - Set EIGHTDOT3 for file systems that so restrict the file names
   - Tailor path name operations for different operating systems
   - Handle the entry name "-" differently?  (Created by piped zip.)
 */

/* ----- External Functions, Types, and Constants Definitions ----- */

#include <stdio.h>      /* printf(), fprintf(), fflush(), rename(), puts(), */
                        /* fopen(), fread(), fclose() */
#include <stdlib.h>     /* exit(), malloc(), calloc(), free() */
#include <string.h>     /* memcpy(), strcpy(), strlen(), strcmp() */
#include <stdarg.h>     /* va_list, va_start(), va_end() */
#include <ctype.h>      /* tolower() */
#include <limits.h>     /* LONG_MIN */
#include <time.h>       /* mktime() */
#include <sys/time.h>   /* utimes() */
#include <assert.h>     /* assert() */
#include <signal.h>     /* signal() */
#include <unistd.h>     /* read(), close(), isatty(), chdir(), mkdtemp() or */
                        /* mktemp(), unlink(), rmdir(), symlink() */
#include <fcntl.h>      /* open(), write(), O_WRONLY, O_CREAT, O_EXCL */
#include <sys/types.h>  /* for mkdir(), stat() */
#include <sys/stat.h>   /* mkdir(), stat() */
#include <errno.h>      /* errno, EEXIST */
#include <dirent.h>     /* opendir(), readdir(), closedir() */
#include "zlib.h"       /* crc32(), z_stream, inflateBackInit(), */
                        /*   inflateBack(), inflateBackEnd() */

/* Support of other compression methods. */
#ifdef DEFLATE64
#  include "infback9.h" /* inflateBack9Init(), inflate9Back(), */
                        /*   inflateBack9End() */
void *sunalloc(void *opaque, unsigned items, unsigned size) {
    (void)opaque;
    return malloc(items * (size_t)size);
}
void sunfree(void *opaque, void *ptr) {
    (void)opaque;
    free(ptr);
}
#endif
#ifdef PKDCL
#  include "blast.h"    /* blast() */
#endif
#ifdef BZIP2
#  include "bzlib.h"    /* BZ2_bzDecompressInit(), BZ2_bzDecompress(), */
                        /*   BZ2_bzDecompressEnd() */
#endif

/* ----- Language Readability Enhancements (sez me) ----- */

#define local static
#define until(c) while(!(c))

/* ----- Operating System Configuration and Tailoring ----- */

/* hack to avoid end-of-line conversions */
#if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(__CYGWIN__)
/* #  include <fcntl.h> */
#  include <io.h>
#  define SET_BINARY_MODE(file) setmode(file, O_BINARY)
#else
#  define SET_BINARY_MODE(file)
#endif

/* defines for the lengths of the integer types -- assure that longs are either
   four bytes or greater than or equal to eight bytes in length */
#if UINT_MAX > 0xffff
#  define BIGINT
#endif
#if ULONG_MAX >= 0xffffffffffffffffUL
#  define BIGLONG
#  if ULONG_MAX > 0xffffffffffffffffUL
#    define GIANTLONG
#  endif
#else
#  if ULONG_MAX != 0xffffffffUL
#    error Unexpected size of long data type
#  endif
#endif

/* systems for which mkdtemp() is not provided */
#ifdef VMS
#  define NOMKDTEMP
#endif

/* %% need to #define EIGHTDOT3 if limited to 8.3 names, e.g. DOS FAT */

/* ----- Operating System Specific Path Name Operations ----- */

/* %% This entire section should be tailored for various operating system
   conventions for path name syntax -- currently set up for Unix */

/* Safe file name character to replace nulls with */
#define SAFESEP '_'

/* Unix path delimiter */
#define PATHDELIM '/'

/* Unix parent reference and replacement character (repeated) */
#define PARENT ".."
local int parrepl = '_';

/* convert a block into a string -- replace any zeros and terminate with a
   zero; this assumes that blk is at least len+1 long */
local void tostr(char *blk, unsigned len) {
    while (len--) {
        if (*blk == 0)
            *blk = SAFESEP;
        blk++;
    }
    *blk = 0;
}

/* see if it's a directory */
local int isdir(char *path) {
    size_t len = strlen(path);
    return len && path[len - 1] == PATHDELIM;
}

/* add a delimiter to a path and return a pointer to where to put the next
   name (assumes that space is available) */
local char *pathcat(char *path) {
    size_t len = strlen(path);
    path += len;
    if (len && path[-1] != PATHDELIM) {
        *path++ = PATHDELIM;
        *path = 0;
    }
    return path;
}

/* given a path, find the next path delimiter and return a pointer to the start
   of it, or return a pointer to the end of the string if the name has no path
   delimiter after it */
local char *pathbrk(char *path) {
    while (*path && *path != PATHDELIM)
        path++;
    return path;
}

/* given a path, skip over path delimiters, if any, to get to the start of the
   next level name */
local char *pathtok(char *path) {
    while (*path == PATHDELIM)
        path++;
    return path;
}

/* secure the path name by removing root or device references, and any parent
   directory references */
local char *guard(char *path) {
    /* skip leading path delimiters */
    path = pathtok(path);

    /* remove parent references */
    char *rem = path;
    while (*rem) {
        /* if have a leading parent reference, replace it with safe separators
           and then prevent deletion of that by moving past it */
        char *cut = pathbrk(rem);
        int was = *cut;
        *cut = 0;
        if (strcmp(rem, PARENT) == 0) {
            while (*rem)
                *rem++ = parrepl;
            *cut = was;
            rem = pathtok(cut);
            continue;
        }
        *cut = was;

        /* find non-leading parent reference, if any */
        char *prev = rem, *name;
        while (*(name = pathtok(cut))) {
            cut = pathbrk(name);
            was = *cut;
            *cut = 0;
            if (strcmp(name, PARENT) == 0) {
                *cut = was;
                break;
            }
            *cut = was;
            prev = name;
        }
        if (*name == 0)
            break;              /* no more parent references, all done */

        /* delete parent and parent reference and start over */
        strcpy(prev, pathtok(cut));
    }

    /* return secured path */
    return path;
}

/* convert name from source to current operating system, using the information
   in the madeby value from the central directory -- name updated in place or
   name is freed and a new malloc'ed space returned */
local char *tohere(char *name, unsigned madeby) {
    (void)madeby;
    return name;
}

/* ----- Utility Operations ----- */

/* mkdtemp() template for temporary directory (if changed, adjust size of
   tempdir[] below) */
#define TEMPDIR "_zXXXXXX"

/* temporary directory and possibly name -- big enough to hold TEMPDIR,
   delimiter, the to36() result which is up to 13 characters, and the
   null terminator (that's 12 + 1 + 13 + 1 == 27), adjust as needed for
   path delimiters that are more than one character (global for bye()) */
local char tempdir[27];

/* make a temporary directory (avoid race condition if mkdtemp available) */
local char *mktempdir(char *template) {
#ifdef NOMKDTEMP
    template = mktemp(template);
    if (template != NULL && mkdir(template, 0700))
        template = NULL;
    return template;
#else
    return mkdtemp(template);
#endif
}

/* remove temporary directory and contents */
local void rmtempdir(void) {
    /* if already removed or never made, then done */
    if (tempdir[0] == 0)
        return;

    /* get just the directory name */
    char *temp = pathbrk(tempdir);
    *temp = 0;

    /* scan the directory and remove its contents */
    DIR *dir = opendir(tempdir);
    if (dir != NULL) {
        temp = pathcat(tempdir);
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            strcpy(temp, ent->d_name);
            unlink(tempdir);
        }
        closedir(dir);
    }

    /* remove the empty directory */
    temp = pathbrk(tempdir);
    *temp = 0;
    rmdir(tempdir);

    /* mark it as gone */
    tempdir[0] = 0;
}

/* relocate the temporary directory contents */
local void mvtempdir(char *newtemp) {
    /* get just the temporary directory name */
    char *temp = pathbrk(tempdir);
    *temp = 0;

    /* scan it and move the contents to newtemp */
    DIR *dir = opendir(tempdir);
    if (dir == NULL)
        return;
    temp = pathcat(tempdir);
    char *dest = pathcat(newtemp);
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        strcpy(temp, ent->d_name);
        strcpy(dest, ent->d_name);
        rename(tempdir, newtemp);
    }
    closedir(dir);

    /* remove path delimiters from names */
    temp = pathbrk(tempdir);
    *temp = 0;
    dest = pathbrk(newtemp);
    *dest = 0;
}

/* true if in the middle of a line on stdout (global for bye()) */
local int midline = 0;

/* true to retain temporary files in the event of an error (global for
   bye()) */
local int retain = 0;

/* abort with an error message */
local unsigned bye(char *why, ...) {
    if (!retain)
        rmtempdir();            /* don't leave a mess behind */
    putchar(midline ? '\n' : '\r');
    fflush(stdout);
    fputs("sunzip abort: ", stderr);
    va_list parms;
    va_start(parms, why);
    vfprintf(stderr, why, parms);
    va_end(parms);
    putc('\n', stderr);
    exit(1);
    return 0;       /* to make compiler happy -- will never get here */
}

/* convert an unsigned 32-bit integer to signed, even if long > 32 bits */
local long tolong(unsigned long val) {
    return (long)(val & 0x7fffffffUL) - (long)(val & 0x80000000UL);
}

/* allocate memory and abort on failure */
local void *alloc(size_t size) {
    void *got = malloc(size);
    if (got == NULL)
        bye("out of memory");
    return got;
}

/* allocate memory and duplicate a string */
local char *strnew(char *str) {
    char *ret = alloc(strlen(str) + 1);
    strcpy(ret, str);
    return ret;
}

/* Convert an 8-byte unsigned integer into a base 36 number using 0-9 and A-Z
   for the digits -- the digits are written least to most significant with no
   trailing zeros; if EIGHTDOT3 defined, put the digits in the 8.3 file name
   format, and fail if the offset is too large to fit in 11 digits (~ 10^17) */
local char *to36(unsigned long low, unsigned long high) {
    /* check type lengths and input to protect num[] array */
#ifdef BIGLONG
#ifdef GIANTLONG
    assert(low <= (1UL << 64) - 1);
#endif
    assert(high == 0);
#endif

    /* convert to base 36 */
    static char num[14];        /* good for up to 2^64 - 1 */
    char *put = num;
    do {
#ifdef BIGLONG
        /* use 64-bit division */
        unsigned rem = low % 36;
        low /= 36;
#else
        /* divide 8-byte value by 36 (assumes 4-byte integers) */
        /* special values are 2^32 div 36 == 119304647, 2^32 mod 36 == 4 */
        unsigned rem = (unsigned)(high % 36);
        high /= 36;
        unsigned mod = (unsigned)(low % 36);
        low /= 36;
        low += 119304647UL * rem;       /* can't overflow */
        mod += rem << 2;                /* rem times (2^32 mod 36) */
        rem = mod % 36;
        mod /= 36;
        low += mod;                     /* can't overflow here either */
#endif

#ifdef EIGHTDOT3
        /* insert a dot for 8.3 names, and fail if more than 11 digits */
        if (put - num == 8)
            *put++ = '.';
        if (put - num == 12)
            bye("zip file name too big for FAT file system");
#endif

        /* write a digit and divide again until zero */
        *put++ = rem < 10 ? '0' + rem : 'A' + rem - 10;
    } while (low || high);

    /* terminate and return string */
    *put = 0;
    return num;
}

/* ----- Input/Output Operations ----- */

/* structure for output processing */
struct out {
    int file;                   /* output file or -1 to not write */
    unsigned long crc;          /* accumulated CRC-32 of output */
    unsigned long count;        /* output byte count */
    unsigned long count_hi;     /* count overflow */
};

/* process inflate output, writing if requested */
local int put(void *out_desc, unsigned char *buf, unsigned len) {
    struct out *out = (struct out *)out_desc;

#ifndef BIGINT
    /* handle special inflateBack9() case for 64K len */
    if (len == 0) {
        len = 32768U;
        put(out, buf, len);
        buf += len;
    }
#endif

    /* update crc and output byte count */
    out->crc = crc32(out->crc, buf, len);
    out->count += len;
    if (out->count < len)
        out->count_hi++;
    if (out->file != -1)
        while (len) {   /* loop since write() may not complete request */
            unsigned try = len >= 32768U ? 16384 : len;
            int wrote = write(out->file, buf, try);
            if (wrote == -1)
                bye("write error");
            len -= wrote;
            buf += wrote;
        }
    return 0;
}

/* structure for input acquisition and processing */
struct in {
    unsigned left;              /* number of bytes left to use in buf */
    unsigned char *next;        /* next byte to use in buf */
    int file;                   /* input file descriptor */
    unsigned char *buf;         /* input buffer */
    unsigned long count;        /* input byte count */
    unsigned long count_hi;     /* count overflow */
    unsigned long offset;       /* input stream offset of end of buffer */
    unsigned long offset_hi;    /* input stream offset overflow */
};

/* Input buffer size (must fit in signed int) */
#ifdef BIGINT
#  define CHUNK 131072
#else
#  define CHUNK 16384
#endif

/* Load input buffer, assumed to be empty, and return bytes loaded and a
   pointer to them.  read() is called until the buffer is full, or until it
   returns end-of-file or error.  Abort program on error using bye(). */
local unsigned get(void *in_desc, unsigned char **buf) {
    struct in *in = (struct in *)in_desc;
    unsigned char *put = in->buf;
    if (buf != NULL)
        *buf = put;
    unsigned want = CHUNK;
    int got;
    do {        /* loop since read() not assured to return request */
        got = (int)read(in->file, put, want);
        if (got == -1)
            bye("zip file read error");
        put += got;
        want -= got;
    } until (got == 0 || want == 0);
    unsigned len = CHUNK - want;        /* how much is in buffer */
    in->count += len;
    if (in->count < len)
        in->count_hi++;
    in->offset += len;
    if (in->offset < len)
        in->offset_hi++;
    return len;
}

/* load input buffer, abort if EOF */
local inline void load(struct in *in) {
    in->left = get(in, NULL);
    if (in->left == 0)
        bye("unexpected end of zip file");
    in->next = in->buf;
}

/* get one, two, or four bytes little-endian from the buffer, abort if EOF */
local inline unsigned get1(struct in *in) {
    if (in->left == 0)
        load(in);           /* assures in->left is not zero */
    in->left--;
    return *(in->next)++;
}
local inline unsigned get2(struct in *in) {
    unsigned low = get1(in);
    return low | (get1(in) << 8);
}
local inline unsigned long get4(struct in *in) {
    unsigned low = get2(in);
    return low | ((unsigned long)(get2(in)) << 16);
}

/* skip len bytes, abort if EOF */
local inline void skip(unsigned long len, struct in *in) {
    unsigned long need = len;
    while (need > in->left) {
        need -= in->left;
        load(in);
    }
    in->left -= need;
    in->next += need;
}

/* read header field into put */
local inline void field(unsigned len, struct in *in, unsigned char *put) {
    unsigned need = len;
    while (need > in->left) {
        memcpy(put, in->next, in->left);
        need -= in->left;
        put += in->left;
        load(in);
    }
    memcpy(put, in->next, need);
    in->left -= need;
    in->next += need;
}

/* ----- File and Directory Operations ----- */

/* structure for directory cache, also saves times and pre-existence */
struct tree {
    char *name;             /* name of this directory */
    int new;                /* true if directory didn't already exist */
    long acc;               /* last access time */
    long mod;               /* last modification time */
    struct tree *subs;      /* list of subdirectories */
    struct tree *next;      /* next directory at this level */
};

/* directory cache */
local struct tree *root = NULL;     /* linked list of top-level directories */

/* add a path to the cache -- if file true, then whatever comes after the last
   delimiter is a file name, so don't make a directory with that name nor use
   the access and modify times; note if the directory already existed or not */
local void graft(char *path, int file, long acc, long mod) {
    /* make the path safe before creating it */
    path = guard(path);
    if (*path == 0)             /* if no name, nothing to do */
        return;

    /* process each name in the provided path */
    char *name = path;
    struct tree **branch = &root;
    for (;;) {
        /* cut out next name in path */
        char *cut = pathbrk(name);
        int was = *cut;
        *cut = 0;
        if (was == 0 && file)
            break;              /* don't do last name for a file */

        /* search for that name in the list */
        while (*branch != NULL) {
            if (strcmp((*branch)->name, name) == 0)
                break;
            branch = &((*branch)->next);
        }

        /* if it's not in the list, add it and create */
        if (*branch == NULL) {
            *branch = alloc(sizeof(struct tree));
            (*branch)->name = strnew(name);
            (*branch)->acc = LONG_MIN;
            (*branch)->mod = LONG_MIN;
            (*branch)->subs = NULL;
            (*branch)->next = NULL;
            int ret = mkdir(path, 0777);
            if (ret && errno != EEXIST)
                bye("write error");
            (*branch)->new = ret == 0;
        }

        /* see if there's more path -- if not, then done */
        if (was == 0)
            break;
        *cut = was;                 /* restore delimiter */
        name = pathtok(cut);        /* next name, skipping delimiters */
        if (*name == 0)             /* ended with a delimiter */
            break;

        /* go down a level for the next name */
        branch = &((*branch)->subs);
    }

    /* if a directory, set the directory times for the last leaf */
    if (!file && acc != LONG_MIN) {
        (*branch)->acc = acc;
        (*branch)->mod = mod;
    }
    return;
}

/* apply the saved directory times to the directories */
local void setdirtimes(struct tree *branch) {
    while (branch != NULL) {
        /* update the times for all the subdirectories of this directory */
        if (branch->subs != NULL) {
            if (chdir(branch->name) == 0) {
                setdirtimes(branch->subs);
                chdir("..");
            }
        }

        /* then update the times for this directory if new and we have times */
        if (branch->new && branch->acc != LONG_MIN) {
            struct timeval times[2];        /* access and modify times */
            times[0].tv_sec = branch->acc;
            times[0].tv_usec = 0;
            times[1].tv_sec = branch->mod;
            times[1].tv_usec = 0;
            utimes(branch->name, times);
        }

        /* go to the next directory in the list */
        branch = branch->next;
    }
}

/* release the memory used by the branch (prune(&root) frees it all) */
local void prune(struct tree **branch) {
    /* snip from the tree */
    struct tree *here = *branch;
    *branch = NULL;

    /* prune and then free each of the branches in the list */
    while (here != NULL) {
        prune(&(here->subs));
        free(here->name);
        struct tree *next = here->next;
        free(here);
        here = next;
    }
}

/* create a path if it doesn't exist (root paths allowed here) */
local void mkpath(char *path) {
    /* scan path */
    char *dir = pathtok(path);              /* go to first name */
    int was;
    char *next;
    while ((was = *(next = pathbrk(dir))) != 0) {
        *next = 0;
        if (mkdir(path, 0777) && errno != EEXIST)
            bye("write error");
        *next = was;
        dir = pathtok(next + 1);        /* go to next name */
    }
    if (*dir && mkdir(path, 0777) && errno != EEXIST)
        bye("write error");
}

/* see if the name exists and what it is */
local int ftype(char *name) {
    struct stat st;
    if (lstat(name, &st))
        return 0;
    switch (st.st_mode & S_IFMT) {
        case S_IFREG:  return 1;
        case S_IFDIR:  return 2;
        case S_IFLNK:  return 3;
        default:  return 4;
    }
    return 0;       // silly gcc
}

/* ----- Time Operations ----- */

/* convert MS-DOS date and time to a Unix time, assuming current timezone
   (you got a better idea?) */
local long dos2time(unsigned long dos) {
    struct tm tm;
    if (dos == 0)
        return (unsigned long)time(NULL);
    tm.tm_year = ((int)(dos >> 25) & 0x7f) + 80;
    tm.tm_mon  = ((int)(dos >> 21) & 0xf) - 1;
    tm.tm_mday = (int)(dos >> 16) & 0x1f;
    tm.tm_hour = (int)(dos >> 11) & 0x1f;
    tm.tm_min  = (int)(dos >> 5) & 0x3f;
    tm.tm_sec  = (int)(dos << 1) & 0x3e;
    tm.tm_isdst = -1;           /* figure out if DST or not */
    return (long)mktime(&tm);
}

/* ----- Zip Format Operations ----- */

/* list of local header offsets of skipped entries (encrypted or old method) */
unsigned long skipped;          /* number of entries in list */
unsigned long skiplen;          /* how many the list can hold */
unsigned long *skiplist;        /* skipped entry list (allocated) */

/* add an entry to the skip list */
local void skipadd(unsigned long here, unsigned long here_hi) {
#ifdef BIGLONG
    (void)here_hi;
#endif

    /* allocate or resize list if needed */
    if (skipped == skiplen) {
        skiplen = skiplen ? skiplen << 1 : 512;
#ifdef BIGLONG
        unsigned long size = skiplen * sizeof(unsigned long);
#else
        unsigned long size = skiplen << 3;
#endif
        skiplist = skiplist == NULL ? malloc(size) : realloc(skiplist, size);
        if (skiplist == NULL)
            bye("out of memory");
    }

    /* add entry to list */
#ifdef BIGLONG
    skiplist[skipped++] = here;
#else
    skiplist[skipped << 1] = here;
    skiplist[(skipped << 1) + 1] = here_hi;
    skipped++;
#endif
}

/* binary search for entry in skip list (assumes ordered), return true if it's
   there */
local int skipfind(unsigned long here, unsigned long here_hi) {
#ifdef BIGLONG
    (void)here_hi;
#endif

    unsigned long beg = 1;
    unsigned long end = skipped;
    while (beg <= end) {
        unsigned long mid = beg + ((end - beg) >> 2);
#ifdef BIGLONG
        unsigned long low = skiplist[mid - 1];
#else
        unsigned long low = skiplist[(mid - 1) << 1];
        unsigned long high = skiplist[((mid - 1) << 1) + 1];
        if (here_hi == high) {
#endif
            if (here < low)
                end = mid - 1;
            else if (here > low)
                beg = mid + 1;
            else
                return 1;
#ifndef BIGLONG
        }
        else {
            if (here_hi < high)
                end = mid - 1;
            else
                beg = mid + 1;
        }
#endif
    }
    return 0;
}

/* pull two and four-byte little-endian integers from buffer */
local inline unsigned little2(unsigned char *ptr) {
    return ptr[0] | (ptr[1] << 8);
}
local inline unsigned long little4(unsigned char *ptr) {
    return little2(ptr) | ((unsigned long)(little2(ptr + 2)) << 16);
}

/* find and return a specific extra block in an extra field */
local int getblock(unsigned id, unsigned char *extra, unsigned xlen,
                   unsigned char **block, unsigned *len) {
    /* scan extra blocks */
    while (xlen) {
        /* get extra block id and data size */
        if (xlen < 4)
            return 0;               /* invalid block */
        unsigned thisid = little2(extra);
        unsigned size = little2(extra + 2);
        extra += 4;
        xlen -= 4;
        if (xlen < size)
            return 0;               /* invalid block */

        /* check for requested id */
        if (thisid == id) {
            *block = extra;
            *len = size;
            return 1;               /* got it! */
        }

        /* go to the next block */
        extra += size;
        xlen -= size;
    }
    return 0;                       /* wasn't there */
}

/* extract Unix access and modification times from extra field */
local void xtimes(unsigned char *extra, unsigned xlen, long *acc, long *mod) {
    /* process Extended Timestamp block */
    unsigned char *block;
    unsigned len;
    if (getblock(0x5455, extra, xlen, &block, &len) && len &&
            (*block & 1) == 1 && len >= ((unsigned)(*block & 2) << 1) + 5) {
        *mod = tolong(little4(block + 1));
        *acc = *block & 2 ? tolong(little4(block + 5)) : *mod;
        return;
    }

    /* process PKWare Unix or Info-ZIP Type 1 Unix block */
    if ((getblock(0x5855, extra, xlen, &block, &len) ||
            getblock(0x000d, extra, xlen, &block, &len)) &&
            len >= 8) {
        *acc = tolong(little4(block));
        *mod = tolong(little4(block + 4));
    }
}

/* look for a zip64 block in the local header and update lengths, return
   true if got 8-byte lengths */
local int zip64local(unsigned char *extra, unsigned xlen,
                     unsigned long *clen, unsigned long *clen_hi,
                     unsigned long *ulen, unsigned long *ulen_hi) {
    /* process Zip64 extended information extra field */
    // From section 4.5.3 of the PKWare appnote, this field in a local header
    // must include both the uncompressed and compressed lengths.
    unsigned char *block;
    unsigned len;
    if (getblock(0x0001, extra, xlen, &block, &len) && len >= 16) {
        *ulen = little4(block);
        *ulen_hi = little4(block + 4);
        *clen = little4(block + 8);
        *clen_hi = little4(block + 12);
        return 1;           /* got 8-byte lengths */
    }
    return 0;               /* didn't get 8-byte lengths */
}

/* 32-bit marker for presence of 64-bit lengths */
#define LOW4 0xffffffffUL

/* look for a zip64 block in the central header and update offset */
local void zip64central(unsigned char *extra, unsigned xlen,
                        unsigned long clen, unsigned long ulen,
                        unsigned long *offset, unsigned long *offset_hi) {
    /* process Zip64 extended information extra field */
    unsigned char *block;
    unsigned len, pos = 0;
    if (getblock(0x0001, extra, xlen, &block, &len)) {
        if (ulen == LOW4)
            pos += 8;
        if (clen == LOW4)
            pos += 8;
        if (*offset == LOW4 && *offset_hi == 0 && len >= pos + 8) {
            *offset = little4(block + pos);
            *offset_hi = little4(block + pos + 4);
        }
    }
}

/* look for a UTF-8 name in the central header */
local char *utf8name(unsigned char *extra, unsigned xlen,
                     unsigned long namecrc, char *name) {
    /* process and copy utf-8 name, discard old name */
    unsigned char *block;
    unsigned len;
    if (getblock(0x7075, extra, xlen, &block, &len) && len > 5 &&
            *block == 1 && little4(block + 1) == namecrc) {
        free(name);
        name = (char *)(block + 5);
        tostr(name, len - 5);
        name = strnew(name);
    }
    return name;
}

#ifdef BZIP2

/* ----- BZip2 Decompression Operation ----- */

#define BZOUTSIZE 32768U    /* passed outbuf better be this big */

/* decompress and write a bzip2 compressed entry */
local int bunzip2(struct in *in, struct out *out,
                       unsigned char *outbuf) {
    /* initialize */
    bz_stream strm;
    strm.bzalloc = NULL;
    strm.bzfree = NULL;
    strm.opaque = NULL;
    int ret = BZ2_bzDecompressInit(&strm, 0, 0);
    if (ret != BZ_OK)
        bye(ret == BZ_MEM_ERROR ? "out of memory" :
                                  "internal error");

    /* decompress */
    strm.avail_in = in->left;
    strm.next_in = (char *)(in->next);
    do {
        /* get more input if needed */
        if (strm.avail_in == 0) {
            strm.avail_in = get(in, NULL);
            if (strm.avail_in == 0)
                bye("unexpected end of zip file");
            strm.next_in = (char *)(in->buf);
        }

        /* process all of the buffered input */
        do {
            /* decompress to output buffer */
            strm.avail_out = BZOUTSIZE;
            strm.next_out = (char *)outbuf;
            ret = BZ2_bzDecompress(&strm);

            /* check for errors */
            switch (ret) {
            case BZ_MEM_ERROR:
                bye("out of memory");
            case BZ_DATA_ERROR:
            case BZ_DATA_ERROR_MAGIC:
                BZ2_bzDecompressEnd(&strm);
                return -1;          /* return a compressed data error */
            case BZ_PARAM_ERROR:
                bye("internal error");
            }

            /* write out decompressed data */
            put(out, outbuf, BZOUTSIZE - strm.avail_out);

            /* repeat until output buffer not full (all input used) */
        } while (strm.avail_out == 0);

        /* go get more input and repeat until logical end of stream */
    } until (ret == BZ_STREAM_END);

    /* clean up and return unused input */
    BZ2_bzDecompressEnd(&strm);
    in->next = (unsigned char *)(strm.next_in);
    in->left = strm.avail_in;
    return 0;
}

#endif

/* ----- Main Operations ----- */

/* compare two strings ignoring case, return true if match */
local int matchcase(char *s1, char *s2) {
    while (tolower(*s1) == tolower(*s2)) {
        if (*s1 == 0)
            return 1;
        s1++;
        s2++;
    }
    return 0;
}

/* show a summary of the zip entry processing */
local void summary(unsigned long entries, unsigned long exist,
                   int write, int quiet) {
    if (quiet < 2) {
        unsigned long written = entries - exist - skipped;
        printf("%lu entr%s %s", written, written == 1 ? "y" : "ies",
                   write ? "written" : "verified");
        if (exist)
            printf(", %lu not overwritten", exist);
        putchar('\n');
    }
    if (skipped) {
        fflush(stdout);
        fprintf(stderr, "sunzip warning: %lu entr%s skipped\n",
               skipped, skipped == 1 ? "y" : "ies");
    }
}

/* display information about bad entry before aborting */
local void bad(char *why, unsigned long entry,
               unsigned long here, unsigned long here_hi) {
    putchar(midline ? '\n' : '\r');
    midline = 0;
    fflush(stdout);
    fprintf(stderr, "sunzip error: %s in entry #%lu at offset 0x", why, entry);
    if (here_hi)
        fprintf(stderr, "%lx%08lx\n", here_hi, here);
    else
        fprintf(stderr, "%lx\n", here);
}

/* return true if the compression method is handled and streamable */
local int streamable(unsigned method) {
    return method == 8          // deflate
#ifdef DEFLATE64
        || method == 9          // deflate64
#endif
#ifdef BZIP2
        || method == 12         // bzip2
#endif
    ;
}

/* return true if the compression method is handled */
local int handled(unsigned method) {
    return streamable(method)
        || method == 0          // stored
#ifdef PKDCL
        || method == 10         // PKWare DCL
#endif
    ;
}

/* macro to see if made by Unix-like system */
#define BYUNIX() (madeby == 3 || madeby == 5 || madeby == 16 || \
                  madeby == 19 || madeby == 30)

/* macro to check actual crc and lengths against expected */
#ifdef BIGLONG
#  define GOOD() (out->crc == crc && \
    clen == (in->count & LOW4) && ulen == (out->count & LOW4) && \
    (high ? clen_hi == (in->count >> 32) && \
            ulen_hi == (out->count >> 32) : 1))
#else
#  define GOOD() (out->crc == crc && \
    clen == in->count && ulen == out->count && \
    (high ? clen_hi == in->count_hi && \
            ulen_hi == out->count_hi : 1))
#endif

/* process a streaming zip file, i.e. without seeking: read input from file,
   limit output if quiet is 1, more so if quiet is >= 2, write the decompressed
   data to files if write is true, otherwise just verify the entries, overwrite
   existing files if over is true, otherwise don't -- over must not be true if
   write is false */
local void sunzip(int file, int quiet, int write, int over) {
    /* initialize i/o -- note that the output buffer must be 64K both for
       inflateBack9() as well as to load the maximum size name or extra
       fields */
    unsigned char *inbuf = alloc(CHUNK);
#ifdef BIGINT
    unsigned char *outbuf = alloc(65536);
#else
    unsigned char *outbuf = calloc(4, 16384);
    if (outbuf == NULL)
        bye("out of memory");
#endif
    struct in ins, *in = &ins;          /* input structure */
    in->left = 0;
    in->next = inbuf;
    in->file = file;
    in->buf = inbuf;
    in->offset = 0;
    in->offset_hi = 0;
    SET_BINARY_MODE(in->file);      /* for defective operating systems */

    /* set up for writing into a temporary directory */
    char *base = NULL;
    if (write) {
        strcpy(tempdir, TEMPDIR);
        if (mktempdir(tempdir) == NULL)
            bye("write error");
        base = pathcat(tempdir);    /* where name goes in tempdir[] */
    }

    /* re-used decompression engine structures (avoid unnecessary
       deallocations and allocations) */
    z_stream strms, *strm = NULL;       /* inflate structure */
#ifdef DEFLATE64
    z_stream strms9, *strm9 = NULL;     /* inflate9 structure */
#endif

    /* process zip file */
    enum {                      /* looking for ... */
        MARK,                   /* spanning signature */
        LOCAL,                  /* local headers */
        CENTRAL,                /* central directory headers */
        DIGSIG,                 /* digital signature (optional) */
        ZIP64REC,               /* zip64 end record (optional) */
        ZIP64LOC,               /* zip64 end locator (optional) */
        END,                    /* end record */
    } mode = MARK;              /* current zip file mode */
    unsigned long entries = 0;  /* entry count */
    skipped = skiplen = 0;      /* initialize skipped list */
    skiplist = NULL;
    unsigned long exist = 0;    /* count of entries not overwritten */
    do {
        /* mark current location */
        unsigned long here = in->offset;
        unsigned long here_hi = in->offset_hi;
        if (here < in->left)
            here_hi--;
        here -= in->left;

        /* get and interpret next header signature */
        unsigned long sig = get4(in);
        switch (sig) {

        case 0x08074b50UL:      /* spanning marker -- partial archive */
            if (mode != MARK)
                bye("zip file format error (spanning marker misplaced)");
            bye("cannot process split zip archives");
            break;

        case 0x30304b50UL:      /* non-split spanning marker (ignore) */
            if (mode != MARK)
                bye("zip file format error (spanning marker misplaced)");
            mode = LOCAL;
            break;

        case 0x04034b50UL:      /* local file header */
            if (mode > LOCAL)
                bye("zip file format error (local file header misplaced)");
            mode = LOCAL;
            entries++;
            if (quiet < 2 && entries % 100 == 0) {
                printf("\r%lu", entries);
                fflush(stdout);
            }

            /* process local header */
            (void)get2(in);             /* version needed to extract */
            unsigned flag = get2(in);   /* general purpose flags */
            if ((flag & 9) == 9)
                bye("cannot skip encrypted entry with deferred lengths");
            if (flag & 0xf7f0U)
                bye("unknown zip header flags set (%04x)", flag);
            unsigned method = get2(in); /* compression method */
            if ((flag & 8) && !streamable(method))
                bye("cannot defer lengths for method %u", method);
            long mod = dos2time(get4(in));  /* file date/time */
            long acc = mod;
            unsigned long crc = get4(in);   /* uncompressed CRC check value */
            unsigned long clen = get4(in);  /* compressed size */
            unsigned long clen_hi = 0;
            unsigned long ulen = get4(in);  /* uncompressed size */
            unsigned long ulen_hi = 0;
            int high = 0;                   /* true if 64-bit length info */
            unsigned nlen = get2(in);       /* file name length */
            unsigned xlen = get2(in);       /* extra field length */

            /* skip file name (will get from central directory later) */
            skip(nlen, in);

            /* process extra field -- get entry times if there and, if needed,
               get zip64 lengths */
            field(xlen, in, outbuf);        /* get extra field */
            xtimes(outbuf, xlen, &acc, &mod);
            if (!(flag & 8) && (clen == LOW4 || ulen == LOW4))
                high = zip64local(outbuf, xlen,
                                  &clen, &clen_hi, &ulen, &ulen_hi);

            /* create temporary file (including for directories and links) */
            struct out outs, *out = &outs;      /* output structure */
            if (write && handled(method)) {
                strcpy(base, to36(here, here_hi));
                out->file = open(tempdir, O_WRONLY | O_CREAT, 0666);
                if (out->file == -1)
                    bye("write error");
            }
            else
                out->file = -1;

            /* initialize crc, compressed, and uncompressed counts */
            in->count = in->left;
            in->count_hi = 0;
            out->count = 0;
            out->count_hi = 0;
            out->crc = crc32(0L, Z_NULL, 0);

            /* process compressed data */
            if (flag & 1)
                method = UINT_MAX;
            if (method == 0) {          /* stored */
                if (clen != ulen || clen_hi != ulen_hi)
                    bye("zip file format error (stored lengths mismatch)");
                while (clen_hi || clen > in->left) {
                    put(out, in->next, in->left);
                    if (clen < in->left) {
                        clen_hi--;
                        clen = 0xffffffffUL - (in->left - clen - 1);
                    }
                    else
                        clen -= in->left;
                    load(in);
                }
                put(out, in->next, (unsigned)clen);
                in->left -= (unsigned)clen;
                in->next += (unsigned)clen;
                clen = ulen;
                clen_hi = ulen_hi;
            }
            else if (method == 8) {     /* deflated */
                if (strm == NULL) {     /* initialize inflater first time */
                    strm = &strms;
                    strm->zalloc = Z_NULL;
                    strm->zfree = Z_NULL;
                    strm->opaque = Z_NULL;
                    int ret = inflateBackInit(strm, 15, outbuf);
                    if (ret != Z_OK)
                        bye(ret == Z_MEM_ERROR ? "out of memory" :
                                                 "internal error");
                }
                strm->avail_in = in->left;
                strm->next_in = in->next;
                int ret = inflateBack(strm, get, in, put, out);
                in->left = strm->avail_in;      /* reclaim unused input */
                in->next = strm->next_in;
                if (ret != Z_STREAM_END) {
                    bad("deflate compressed data corrupted",
                        entries, here, here_hi);
                    bye("zip file corrupted -- cannot continue");
                }
            }
#ifdef DEFLATE64
            else if (method == 9) {     /* deflated with deflate64 */
                if (strm9 == NULL) {    /* initialize first time */
                    strm9 = &strms9;
                    strm9->zalloc = Z_NULL;
                    strm9->zfree = Z_NULL;
                    strm9->opaque = Z_NULL;
                    int ret = inflateBack9Init(strm9, outbuf);
                    if (ret != Z_OK)
                        bye(ret == Z_MEM_ERROR ? "not enough memory (!)" :
                                                 "internal error");
                }
                strm9->avail_in = in->left;
                strm9->next_in = in->next;
                int ret = inflateBack9(strm9, get, in, put, out);
                in->left = strm9->avail_in;     /* reclaim unused input */
                in->next = strm9->next_in;
                if (ret != Z_STREAM_END) {
                    bad("deflate64 compressed data corrupted",
                        entries, here, here_hi);
                    bye("zip file corrupted -- cannot continue");
                }
            }
#endif
#ifdef PKDCL
            else if (method == 10) {    /* PKWare DCL implode */
                int ret = blast(get, in, put, out, &(in->left), &(in->next));
                if (ret != 0) {
                    bad("DCL imploded data corrupted",
                        entries, here, here_hi);
                    bye("zip file corrupted -- cannot continue");
                }
            }
#endif
#ifdef BZIP2
            else if (method == 12) {    /* bzip2 compression */
                int ret = bunzip2(in, out, outbuf);
                if (ret) {
                    bad("bzip2 compressed data corrupted",
                        entries, here, here_hi);
                    bye("zip file corrupted -- cannot continue");
                }
            }
#endif
            else {                      /* skip encrpyted or unknown method */
                if (quiet < 1)
                    bad(flag & 1 ? "skipping encrypted entry" :
                        "skipping unknown compression method",
                        entries, here, here_hi);
                skip(clen, in);
                unsigned long rem = clen_hi;
                while (rem) {
                    skip(0x80000000UL, in);
                    skip(0x80000000UL, in);
                    rem--;
                }
                skipadd(here, here_hi);
            }

            /* deduct unused input from compressed data count */
            if (in->count < in->left)
                in->count_hi--;
            in->count -= in->left;

            /* close file, set file times */
            if (out->file != -1) {
                if (close(out->file))
                    bye("write error");
                struct timeval times[2];
                times[0].tv_sec = acc;
                times[0].tv_usec = 0;
                times[1].tv_sec = mod;
                times[1].tv_usec = 0;
                utimes(tempdir, times);
            }

            /* get data descriptor if present --
               allow for several possibilities: four-byte or eight-byte
               lengths, with no signature or with one of two signatures (the
               second signature is not known yet -- to be defined by PKWare --
               for now allow only one), note that this will not be attempted
               for skipped entries, since skipped entries cannot have deferred
               lengths */
            if (flag & 8) {
                /* look for PKWare descriptor (even though no one uses it?) */
                crc = get4(in);         /* uncompressed data check value */
                clen = get4(in);        /* compressed size */
                clen_hi = 0;
                ulen = get4(in);        /* uncompressed size */
                ulen_hi = 0;
                if (!GOOD()) {
                    /* look for an Info-ZIP descriptor (original -- in use) */
                    /* (%% NOTE: replace second signature when actual known) */
                    if (crc == 0x08074b50UL || crc == 0x08074b50UL) {
                        unsigned long desc = crc;   /* possible signature */
                        crc = clen;
                        clen = ulen;
                        ulen = get4(in);
                        if (!GOOD()) {
                            /* try no signature with eight-byte lengths */
                            clen_hi = clen;
                            clen = crc;
                            crc = desc;
                            ulen_hi = get4(in);
                            high = 1;
                            if (!GOOD()) {
                                /* try signature with eight-byte lengths */
                                crc = clen;
                                clen = clen_hi;
                                clen_hi = ulen;
                                ulen = ulen_hi;
                                ulen_hi = get4(in);
                            }
                        }
                    }
                    else {
                        /* try no signature with eight-byte lengths */
                        clen_hi = ulen;
                        ulen = get4(in);
                        ulen_hi = get4(in);
                        high = 1;
                    }
                }
            }

            /* verify entry and display information (won't do if skipped) */
            if (handled(method)) {
                if (!GOOD()) {
                    bad("compressed data corrupted, check values mismatch",
                        entries, here, here_hi);
                    bye("zip file corrupted -- cannot continue");
                }
            }
            break;

        case 0x02014b50UL:      /* central file header */
            /* first time here: any earlier mode can arrive here */
            if (mode < CENTRAL) {
                if (quiet < 2)
                    printf("\r%lu entr%s processed\n",
                           entries, entries == 1 ? "y" : "ies");
                mode = CENTRAL;
            }

            /* read central header */
            if (mode != CENTRAL)
                bye("zip file format error (central file header misplaced)");
            (void)get1(in);             /* version made by */
            unsigned madeby = get1(in); /* OS made by */
            skip(14, in);               /* skip up through crc */
            clen = get4(in);            /* compressed length */
            ulen = get4(in);            /* uncompressed length */
            nlen = get2(in);            /* file name length */
            xlen = get2(in);            /* extra field length */
            flag = get2(in);            /* comment length */
            skip(4, in);                /* disk #, internal attributes */
            unsigned long extatt = get4(in);    /* external attributes */
            here = get4(in);            /* offset of local header */
            here_hi = 0;

            /* get and save file name, compute name crc */
            field(nlen, in, outbuf);        /* get file name */
            unsigned long ncrc = crc32(crc32(0L, Z_NULL, 0), outbuf, nlen);
            char *from = (char *)outbuf;
            tostr(from, nlen);              /* make name into a string */
            char *name = strnew(from);      /* copy from outbuf */

            /* process extra field to get 64-bit offset, if there */
            field(xlen, in, outbuf);        /* get extra field */
            zip64central(outbuf, xlen, clen, ulen, &here, &here_hi);
#ifdef BIGLONG
            here += here_hi << 32;
            here_hi = 0;
#endif

            /* process extra field to get UTF-8 name, if there (use name crc to
               verify that name wasn't changed independent of extra field) */
            name = utf8name(outbuf, xlen, ncrc, name);

            /* process file name */
            name = tohere(name, madeby);    /* convert name for this OS */
            name = guard(name);             /* keep the name safe */

            /* If tempdir and name collide (pretty darned unlikely, but not
               impossible), make a new tempdir and move the contents over */
            if (write) {
                /* set up names to compare (destructively, will fix later) */
                base = pathbrk(tempdir);
                *base = 0;
                from = pathbrk(name);
                int del = *from;                /* save delimiter */
                *from = 0;

                /* if collision (!!) then make a new temporary directory, move
                   the contents over, remove the old one, and update the name
                   of the temporary directory in tempdir[] */
                if (matchcase(tempdir, name)) {
                    char *heir = alloc(sizeof(tempdir));
                    strcpy(heir, TEMPDIR);
                    if (mktempdir(heir) == NULL)    /* make new directory */
                        bye("write error");
                    mvtempdir(heir);                /* transfer contents */
                    if (rmdir(tempdir))
                        bye("write error");
                    strcpy(tempdir, heir);
                    free(heir);
                }

                /* restore name and reconstruct temporary directory path */
                *from = del;                    /* restore delimiter */
                base = pathcat(tempdir);
            }

            /* construct (second time) temporary name from offset */
            if (write)
                strcpy(base, to36(here, here_hi));

            /* display name */
            if (quiet < 1) {
                fputs(name, stdout);
                midline = 1;
            }

            /* if we don't have a name due to parent reference cancellation,
               then just delete the temporary and skip it (it was a null
               directory, e.g. "xx/../") */
            if (*name == 0) {
                unlink(tempdir);
                if (quiet < 1)
                    puts("(null directory skipped)");
            }

            /* see if this entry was skipped */
            else if (skipfind(here, here_hi)) {
                if (quiet < 1)
                    puts(" (skipped)");
            }

            /* if not writing, then verification was ok */
            else if (!write) {
                if (quiet < 1)
                    puts(" OK");
            }

            /* writing: see if the temporary file is there (it should be) */
            else if (ftype(tempdir) != 1)
                bye("zip file format error (local/central offsets mismatch)");

            /* if not overwriting and it exists, don't mess with it */
            else if (!over && ftype(name) != 0) {
                unlink(tempdir);
                if (quiet < 1)
                    puts(" OK (exists, not replaced)");
                exist++;
            }

            /* if a directory, save time information from temporary file */
            else if (isdir(name)) {         /* directory */
                struct stat st;
                int ret = stat(tempdir, &st);
                if (ret)
                    bye("temporary file missing in action!");
                unlink(tempdir);
                graft(name, 0, st.st_atime, st.st_mtime);
                if (quiet < 1)
                    puts(" OK");
            }

            /* if it's a symbolic link, read it and make it */
            else if (((extatt >> 16) & 0170000) == 0120000 && BYUNIX()) {
                FILE *sym = fopen(tempdir, "r");
                if (sym == NULL)
                    bye("temporary file missing in action!");
                assert(PATH_MAX < 65535U);
                nlen = fread(outbuf, 1, PATH_MAX + 1, sym);
                fclose(sym);
                if (nlen == 0 || nlen == PATH_MAX + 1)
                    bye("symbolic link empty or too long");
                unlink(tempdir);
                unlink(name);
                from = (char *)outbuf;
                tostr(from, nlen);
                if (symlink(from, name))
                    bye("write error");
                if (quiet < 1)
                    puts(" OK (symbolic link)");
            }

            /* it's a file: move the temporary file there */
            else {
                graft(name, 1, LONG_MIN, LONG_MIN);
                int ret = rename(tempdir, name);    /* replace existing file */
                if (ret)
                    bye("write error");
                if (quiet < 1)
                    puts(" OK");
            }

            /* all of the above cases wrote a new line if quiet < 1 */
            midline = 0;

            /* apply external attributes -- use Unix if we have them */
            if (*name) {
                if ((extatt >> 16) && BYUNIX())
                    chmod(name, (extatt >> 16) & 07777);
                else if (!isdir(name))          /* use MSDOS write attribute */
                    chmod(name, (extatt & 1 ? 0444 : 0644));
            }

            /* done with entry name */
            free(name);

            /* skip comment field -- last thing in central header */
            skip(flag, in);
            break;

        case 0x05054b50UL:      /* digital signature */
            if (mode != CENTRAL)
                bye("zip file format error (digital signature misplaced)");
            mode = DIGSIG;
            skip(get2(in), in);
            break;

        case 0x06064b50UL:      /* zip64 end of central directory record */
            if (mode != CENTRAL && mode != DIGSIG)
                bye("zip file format error (zip64 record misplaced)");
            mode = ZIP64REC;
            ulen = get4(in);
            ulen_hi = get4(in);
            skip(ulen, in);
            while (ulen_hi) {           /* truly odd, but possible */
                skip(0x80000000UL, in);
                skip(0x80000000UL, in);
                ulen_hi--;
            }
            break;

        case 0x07064b50UL:      /* zip64 end of central directory locator */
            if (mode != ZIP64REC)
                bye("zip file format error (zip64 locator misplaced)");
            mode = ZIP64LOC;
            skip(16, in);
            break;

        case 0x06054b50UL:      /* end of central directory record */
            if (mode == LOCAL || mode == ZIP64REC || mode == END)
                bye("zip file format error (end record misplaced)");
            mode = END;
            skip(16, in);               /* counts and offsets */
            flag = get2(in);            /* zip file comment length */
            skip(flag, in);             /* zip file comment */
            break;

        default:
            bye("zip file format error (unknown zip signature %08x)", sig);
        }
    } until (mode == END);              /* until end record reached (or EOF) */

    /* summarize and clean up */
    summary(entries, exist, write, quiet);
    if (write) {
        rmtempdir();                    /* remove the temporary directory */
        setdirtimes(root);              /* set saved directory times */
        prune(&root);                   /* free the directory tree */
    }
#ifdef DEFLATE64
    if (strm9 != NULL)
        inflateBack9End(strm9);
#endif
    if (strm != NULL)
        inflateBackEnd(strm);
    if (skiplist != NULL)
        free(skiplist);
    free(outbuf);
    free(inbuf);

    /* check for junk */
    if (in->left != 0 || get(in, NULL) != 0) {
        fflush(stdout);
        fputs("sunzip warning: junk after end of zip file\n", stderr);
    }
}

/* catch interrupt in order to delete temporary files and directory */
local void cutshort(int n) {
    (void)n;
    bye("user interrupt");
}

/* process arguments and then unzip from stdin */
int main(int argc, char **argv) {
    /* for rmtempdir(), called by bye() */
    tempdir[0] = 0;

    /* catch interrupt signal */
    signal(SIGINT, cutshort);

    /* give help if input not redirected */
    if (isatty(0)) {
        puts("sunzip 0.5, streaming unzip by Mark Adler");
        puts("usage: ... | sunzip [-t] [-o] [-r] [-p x] [-q[q]] [dir]");
        puts("       sunzip [-t] [-o] [-p x] [-r] [-q[q]] [dir] < infile.zip");
        puts("");
        puts("\t-t: test -- don't write files");
        puts("\t-o: overwrite existing files");
        puts("\t-r: retain temporary files in the event of an error");
        puts("\t-p x: replace parent reference .. with this character");
        puts("\t-q: quiet -- display summary info and errors only");
        puts("\t-qq: really quiet -- display errors only");
        puts("\tdir: subdirectory to create files in (if writing)");
        return 0;
    }

    /* scan options in arguments */
    int quiet = 0, write = 1, over = 0;     /* initial options */
    int parm = 0;
    for (int n = 1; n < argc; n++)
        if (parm) {
            parrepl = argv[n][0];
            if (parrepl == 0 || argv[n][1])
                bye("need one character after -p");
            parm = 0;
        }
        else if (argv[n][0] == '-') {
            char *arg = argv[n] + 1;
            while (*arg) {
                switch (*arg) {
                case 'o':           /* overwrite existing files */
                    over = 1;
                    break;
                case 'p':           /* parent ".." replacement character */
                    parm = 1;       /* get character in next arg */
                    break;
                case 'q':           /* quiet */
                    quiet++;        /* qq is even more quiet */
                    break;
                case 'r':           /* retain temporary files */
                    retain = 1;
                    break;
                case 't':           /* test */
                    write = 0;
                    break;
                default:
                    bye("unknown option %c", *arg);
                }
                arg++;
            }
        }

    /* check option consistency */
    if (parm)
        bye("nothing after -p");
    if (over && !write)
        bye("can't combine -o with -t");
    if (parrepl == '.')
        fputs("sunzip warning: parent directory access allowed\n", stderr);

    /* scan non-options, which is where to create and put entries in -- the
       directory is created and then we cd in there, multiple name arguments
       simply create deeper subdirectories for the destination */
    for (int n = 1; n < argc; n++)
        if (parm)
            parm = 0;
        else if (argv[n][0] == '-') {
            char *arg = argv[n] + 1;
            while (*arg)
                if (*arg++ == 'p')
                    parm = 1;
        }
        else {
            if (!write)
                bye("cannot specify destination directory with -t");
            mkpath(argv[n]);
            if (chdir(argv[n]))
                bye("write error");
        }

    /* unzip from stdin */
    sunzip(0, quiet, write, over);
    return 0;
}
