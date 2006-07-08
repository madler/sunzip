/* sunzip.c -- streaming unzip for reading a zip file from stdin
 * Copyright (C) 2006 Mark Adler, all rights reserved
 * Version 0.31  7 July 2006  Mark Adler
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
 */

/* Notes:
   - Link sunzip with zlib 1.2.3 or later, infback9.c and inftree9.c compiled
     (found in the zlib source distribution contrib/ directory), and libbzip2.
   - Much of the zip file decoding capability of sunzip has not been tested as
     of version 0.31, due to the difficulty of generating varied enough or
     large enough zip files.  The donation of test-case zip files is welcome.
     In particular: all compression methods, with and without data descriptors,
     various data descriptor styles, zip64 headers, and erroneous zip files.
 */

/* To-do:
   - Set EIGHTDOT3 for file systems that so restrict the file names
   - Tailor path name operations for different operating systems
   - Set the long data descriptor signature once it's specified by PKWare
   - Handle the entry name "-" differently?  (Created by piped zip.)
 */

/* ----- External Functions, Types, and Constants Definitions ----- */

#include <stdio.h>      /* printf(), fprintf(), fflush(), rename(), puts(), */
                        /* fopen(), fread(), fclose() */
#include <stdlib.h>     /* exit(), malloc(), calloc(), free() */
#include <string.h>     /* memcpy(), strcpy(), strlen(), strchr(), strcmp() */
#include <ctype.h>      /* tolower() */
#include <limits.h>     /* LONG_MIN */
#include <time.h>       /* mktime() */
#include <sys/time.h>   /* futimes(), utimes() */
#include <assert.h>     /* assert() */
#include <signal.h>     /* signal() */
#include <unistd.h>     /* read(), close(), isatty(), chdir(), mkdtemp(), */
                        /* unlink(), rmdir(), symlink() */
#include <fcntl.h>      /* open(), write(), O_WRONLY, O_CREAT, O_EXCL */
#include <sys/types.h>  /* for mkdir(), stat() */
#include <sys/stat.h>   /* mkdir(), stat() */
#include <errno.h>      /* errno, EEXIST */
#include <dirent.h>     /* opendir(), readdir(), closedir() */
#include "zlib.h"       /* crc32(), z_stream, inflateBackInit(), */
                        /*   inflateBack(), inflateBackEnd() */
#include "infback9.h"   /* inflateBack9Init(), inflate9Back(), */
                        /*   inflateBack9End() */
#include "bzlib.h"      /* BZ2_bzDecompressInit(), BZ2_bzDecompress(), */
                        /*   BZ2_bzDecompressEnd() */

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

/* defines for the lengths of the types */
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

/* %% need to #define EIGHTDOT3 if limited to 8.3 names, e.g. DOS FAT */

/* ----- Operating System Specific Path Name Operations ----- */

/* %% This entire section should be tailored for various operating system
   conventions for path name syntax -- currently set up for Unix */

/* Safe file name character to replace nulls with */
#define SAFESEP '_'

/* Unix path delimiter */
#define PATHDELIM '/'

/* convert a block into a string -- replace any zeros and terminate with a
   zero; this assumes that blk is at least len+1 long */
local void tostr(char *blk, unsigned len)
{
    while (len--) {
        if (*blk == 0)
            *blk = SAFESEP;
        blk++;
    }
    *blk = 0;
}

/* see if it's a directory */
local int isdir(char *path)
{
    unsigned len;

    len = strlen(path);
    return len && path[len - 1] == PATHDELIM;
}

/* add a delimiter to a path and return a pointer to where to put the next
   name (assumes that space is available) */
local char *pathcat(char *path)
{
    unsigned long len;

    len = strlen(path);
    path += len;
    if (len && path[-1] != PATHDELIM) {
        *path++ = PATHDELIM;
        *path = 0;
    }
    return path;
}

/* given a path, find the next path delimiter and return a pointer to the start
   of it, or return NULL if the name has no path delimiter after it */
local char *pathbrk(char *path)
{
    return strchr(path, PATHDELIM);
}

/* given a path, skip over path delimiters, if any, to get to the start of the
   next level name */
local char *pathtok(char *path)
{
    while (*path == PATHDELIM)
        path++;
    return path;
}

/* force path to be relative for security (remove devices, root reference) */
local char *deroot(char *path)
{
    return pathtok(path);       /* for Unix, skip leading path delimiters */
}

/* convert name from source to current operating system, using the information
   in the madeby value from the central directory -- name updated in place */
local void tohere(char *name, unsigned madeby)
{
    return;
}

/* ----- Utility Operations ----- */

/* mkdtemp() template for temporary directory (if changed, adjust size of
   tempdir[] below) */
#define TEMPDIR "_zXXXXXX"

/* temporary directory and possibly name -- big enough to hold TEMPDIR,
   delimiter, the to36() result which is up to 13 characters, and the
   null terminator (that's 12 + 1 + 13 + 1 == 27), adjust as needed for
   path delimiters that are more than one character */
local char tempdir[27];

/* remove temporary directory and contents */
local void rmtempdir(void)
{
    char *temp;
    DIR *dir;
    struct dirent *ent;

    /* if already removed or never made, then done */
    if (tempdir[0] == 0)
        return;

    /* get just the directory name */
    temp = pathbrk(tempdir);
    if (temp != NULL)
        *temp = 0;

    /* scan the directory and remove its contents */
    dir = opendir(tempdir);
    if (dir == NULL)
        return;
    temp = pathcat(tempdir);
    while ((ent = readdir(dir)) != NULL) {
        strcpy(temp, ent->d_name);
        unlink(tempdir);
    }
    closedir(dir);

    /* remove the empty directory */
    temp = pathbrk(tempdir);
    if (temp != NULL)
        *temp = 0;
    rmdir(tempdir);

    /* mark it as gone */
    tempdir[0] = 0;
}

/* relocate the temporary directory contents */
local void mvtempdir(char *newtemp)
{
    char *temp, *dest;
    DIR *dir;
    struct dirent *ent;

    /* get just the temporary directory name */
    temp = pathbrk(tempdir);
    if (temp != NULL)
        *temp = 0;

    /* scan it and move the contents to newtemp */
    dir = opendir(tempdir);
    if (dir == NULL)
        return;
    temp = pathcat(tempdir);
    dest = pathcat(newtemp);
    while ((ent = readdir(dir)) != NULL) {
        strcpy(temp, ent->d_name);
        strcpy(dest, ent->d_name);
        rename(tempdir, newtemp);
    }
    closedir(dir);

    /* remove path delimiters from names */
    temp = pathbrk(tempdir);
    if (temp != NULL)
        *temp = 0;
    dest = pathbrk(newtemp);
    if (dest != NULL)   
        *dest = 0;
}

/* true if in the middle of a line */
local int midline = 0;

/* abort with an error message */
local int bye(char *why)
{
    rmtempdir();
    putchar(midline ? '\n' : '\r');
    fflush(stdout);
    fprintf(stderr, "sunzip abort: %s\n", why);
    exit(1);
    return 0;       /* to make compiler happy -- will never get here */
}

/* convert an unsigned 32-bit integer to signed, even if long > 32 bits */
local long tolong(unsigned long val)
{
    return (long)(val & 0x7fffffffUL) - (long)(val & 0x80000000UL);
}

/* allocate memory and duplicate a string */
local char *strnew(char *str)
{
    char *ret;

    ret = malloc(strlen(str) + 1);
    if (ret == NULL)
        bye("out of memory");
    strcpy(ret, str);
    return ret;
}

/* Convert an 8-byte unsigned integer into a base 36 number using 0-9 and A-Z
   for the digits -- the digits are written least to most significant with no
   trailing zeros; if EIGHTDOT3 defined, put the digits in the 8.3 file name
   format, and fail if the offset is too large to fit in 11 digits (~ 10^17) */
local char *to36(unsigned long low, unsigned long high)
{
    unsigned rem, tmp;
    char *next;
    static char num[14];        /* good for up to 2^64 - 1 */

    /* check type lengths and input to protect num[] array */
#ifdef BIGLONG
#ifdef GIANTLONG
    assert(low <= (1UL << 64) - 1);
#endif
    assert(high == 0);
#endif

    /* convert to base 36 */
    next = num;
    do {
#ifdef BIGLONG
        /* use 64-bit division */
        rem = low % 36;
        low /= 36;
#else
        /* divide 8-byte value by 36 (assumes 4-byte integers) */
        /* special values are 2^32 div 36 == 119304647, 2^32 mod 36 == 4 */
        rem = (unsigned)(high % 36);
        high /= 36;
        tmp = (unsigned)(low % 36);
        low /= 36;
        low += 119304647UL * rem;       /* can't overflow */
        tmp += rem << 2;                /* rem times (2^32 mod 36) */
        rem = tmp % 36;
        tmp /= 36;
        low += tmp;                     /* can't overflow here either */
#endif

#ifdef EIGHTDOT3
        /* insert a dot for 8.3 names, and fail if more than 11 digits */
        if (next - num == 8)
            *next++ = '.';
        if (next - num == 12)
            bye("zip file too big for FAT file system names");
#endif

        /* write a digit and divide again until nothing left */
        *next++ = rem < 10 ? '0' + rem : 'A' + rem - 10;
    } while (low || high);

    /* terminate and return string */
    *next = 0;
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
local int put(void *out_desc, unsigned char *buf, unsigned len)
{
    int wrote;
    unsigned try;
    struct out *out = (struct out *)out_desc;

    /* handle special inflateBack9() case */
    if (sizeof(unsigned) == 2 && len == 0) {
        len = 32768U;
        put(out, buf, len);
        buf += len;
    }

    /* update crc and output byte count */
    out->crc = crc32(out->crc, buf, len);
    out->count += len;
    if (out->count < len)
        out->count_hi++;
    if (out->file != -1)
        while (len) {   /* loop since write() may not complete request */
            try = len >= 32768U ? 16384 : len;
            wrote = write(out->file, buf, try);
            if (wrote == -1)
                bye("write error");
            len -= wrote;
            buf += wrote;
        }
    return 0;
}

/* structure for input acquisition and processing */
struct in {
    int file;                   /* input file */
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
local unsigned get(void *in_desc, unsigned char **buf)
{
    int got;
    unsigned want, len;
    unsigned char *next;
    struct in *in = (struct in *)in_desc;

    next = in->buf;
    if (buf != NULL)
        *buf = next;
    want = CHUNK;
    do {        /* loop since read() not assured to return request */
        got = (int)read(in->file, next, want);
        if (got == -1)
            bye("zip file read error");
        next += got;
        want -= got;
    } until (got == 0 || want == 0);
    len = CHUNK - want;         /* how much is in buffer */
    in->count += len;
    if (in->count < len)
        in->count_hi++;
    in->offset += len;
    if (in->offset < len)
        in->offset_hi++;
    return len;
}

/* load input buffer, abort if EOF */
#define load(in) ((left = get(in, NULL)) == 0 ? \
    bye("unexpected end of zip file") : (next = in->buf, left))

/* get one, two, or four bytes little-endian from the buffer, abort if EOF */
#define get1(in) (left == 0 ? load(in) : 0, left--, *next++)
#define get2(in) (tmp2 = get1(in), tmp2 + (get1(in) << 8))
#define get4(in) (tmp4 = get2(in), tmp4 + ((unsigned long)get2(in) << 16))

/* skip len bytes, abort if EOF */
#define skip(len, in) \
    do { \
        tmp4 = len; \
        while (tmp4 > left) { \
            tmp4 -= left; \
            load(in); \
        } \
        left -= (unsigned)tmp4; \
        next += (unsigned)tmp4; \
    } while (0)

/* read header field into output buffer */
#define field(len, in) \
    do { \
        tmp2 = len; \
        tmpp = outbuf; \
        while (tmp2 > left) { \
            memcpy(tmpp, next, left); \
            tmp2 -= left; \
            tmpp += left; \
            load(in); \
        } \
        memcpy(tmpp, next, tmp2); \
        left -= tmp2; \
        next += tmp2; \
    } while (0)

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
local int graft(char *path, int file, long acc, long mod)
{
    int ret, was = 0;
    char *name, *cut;
    struct tree **branch;

    /* force path to be relative for security */
    path = deroot(path);
    if (*path == 0)             /* if no name, nothing to do */
        return -1;

    /* process each name in the provided path */
    name = path;
    branch = &root;
    for (;;) {
        /* cut out next name in path */
        cut = pathbrk(name);
        if (cut != NULL) {
            was = *cut;
            *cut = 0;
        }
        else if (file)
            break;              /* don't do last name for a file */

        /* search for that name in the list */
        while (*branch != NULL) {
            if (strcmp((*branch)->name, name) == 0)
                break;
            branch = &((*branch)->next);
        }

        /* if it's not in the list, add it and create */
        if (*branch == NULL) {
            *branch = malloc(sizeof(struct tree));
            if (*branch == NULL)
                bye("out of memory");
            (*branch)->name = strnew(name);
            (*branch)->acc = LONG_MIN;
            (*branch)->mod = LONG_MIN;
            (*branch)->subs = NULL;
            (*branch)->next = NULL;
            ret = mkdir(path, 0777);
            if (ret && errno != EEXIST)
                bye("write error");
            (*branch)->new = ret == 0;
        }

        /* see if there's more path -- if not, then done */
        if (cut == NULL)
            break;
        *cut = was;                 /* restore delimiter */
        name = pathtok(cut + 1);    /* next name, skipping extra delimiters */
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
    return -1;
}

/* apply the saved directory times to the directories */
local void setdirtimes(struct tree *branch)
{
    struct timeval times[2];            /* access and modify times */

    while (branch != NULL) {
        /* update the times for all the subdirectories of this directory */
        if (branch->subs != NULL) {
            chdir(branch->name);
            setdirtimes(branch->subs);
            chdir("..");
        }

        /* then update the times for this directory if new and we have times */
        if (branch->new && branch->acc != LONG_MIN) {
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
local void prune(struct tree **branch)
{
    struct tree *here, *next;

    /* snip from the tree */
    here = *branch;
    *branch = NULL;

    /* prune and then free each of the branches in the list */
    while (here != NULL) {
        prune(&(here->subs));
        free(here->name);
        next = here->next;
        free(here);
        here = next;
    }
}

/* create a path if it doesn't exist (root paths allowed here) */
local void mkpath(char *path)
{
    int was;
    char *dir, *next;

    /* scan path */
    dir = deroot(path);                 /* go to first name */
    while ((next = pathbrk(dir)) != NULL) {
        was = *next;
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
local int ftype(char *name)
{
    struct stat st;

    if (lstat(name, &st))
        return 0;
    switch (st.st_mode & S_IFMT) {
        case S_IFREG:  return 1;
        case S_IFDIR:  return 2;
        case S_IFLNK:  return 3;
        default:  return 4;
    }
}

/* ----- Time Operations ----- */

/* convert MS-DOS date and time to a Unix time, assuming current timezone
   (you got a better idea?) */
local long dos2time(unsigned long dos)
{
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
local void skipadd(unsigned long here, unsigned long here_hi)
{
    unsigned long size;

    /* allocate or resize list if needed */
    if (skipped == skiplen) {
        skiplen = skiplen ? skiplen << 1 : 512;
#ifdef BIGLONG
        size = skiplen * sizeof(unsigned long);
#else
        size = skiplen << 3;
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

/* binary search for entry in skip list (assumes ordered) */
local int skipfind(unsigned long here, unsigned long here_hi)
{
    unsigned long left, right, mid, low;
#ifndef BIGLONG
    unsigned long high;
#endif

    left = 1;
    right = skipped;
    while (left <= right) {
        mid = left + ((right - left) >> 2);
#ifdef BIGLONG
        low = skiplist[mid - 1];
#else
        low = skiplist[(mid - 1) << 1];
        high = skiplist[((mid - 1) << 1) + 1];
        if (here_hi == high) {
#endif
            if (here < low)
                right = mid - 1;
            else if (here > low)
                left = mid + 1;
            else
                return 1;
#ifndef BIGLONG
        }
        else {
            if (here_hi < high)
                right = mid - 1;
            else
                left = mid + 1;
        }
#endif
    }
    return 0;
}

/* Largest four-byte unsigned integer value */
#define LOW4 0xffffffffUL

/* pull two and four-byte little-endian integers from buffer */
#define little2(ptr) ((ptr)[0] + ((ptr)[1] << 8))
#define little4(ptr) (little2(ptr) + ((unsigned long)(little2(ptr + 2)) << 16))

/* extract Unix access and modification times from extra field */
local void xtimes(unsigned char *data, unsigned len, long *acc, long *mod)
{
    unsigned off;           /* current offset in extra field */
    unsigned id, size;      /* block information (id reused for flags) */

    /* scan extra blocks to find time information */
    off = 0;
    do {
        /* check that at least four bytes remain */
        if (off + 4 < 4 || len < off + 4)
            return;                 /* invalid block */

        /* get extra block id and data size */
        id = little2(data + off);
        size = little2(data + off + 2);
        off += 4;
        if (off + size < size || len < off + size)
            return;                 /* invalid block */

        /* process relevant blocks */
        switch (id) {
        case 0x5455:    /* Extended Timestamp extra block */
            if (size < 1)
                return;             /* invalid block */
            id = data[off];         /* flags */
            if ((id & 1) == 0)
                break;              /* if no modify time, don't use */
            if (size < ((id & 2) << 1) + 5)
                return;             /* invalid block */
            *mod = tolong(little4(data + off + 1));
            *acc = id & 2 ?
                       tolong(little4(data + off + 5)) :
                       *mod;
            return;                 /* good enough -- return times */
        case 0x000d:    /* PKWare Unix extra field */
        case 0x5855:    /* Info-ZIP Type 1 Unix extra field */
            if (size < 8)
                return;             /* invalid block */
            *acc = tolong(little4(data + off));
            *mod = tolong(little4(data + off + 4));
            /* got something, but keep looking for an extended timestamp */
        }

        /* go to the next block */
        off += size;
    } while (off < len);
}

/* look for a zip64 block in the local header and update lengths, return
   true if got 8-byte lengths */
local int zip64local(unsigned char *data, unsigned len,
    unsigned long *clen, unsigned long *clen_hi,
    unsigned long *ulen, unsigned long *ulen_hi)
{
    unsigned off;           /* current offset in extra field */
    unsigned id, size;      /* block information (id reused for flags) */

    /* scan extra blocks to find time information */
    off = 0;
    do {
        /* check that at least four bytes remain */
        if (off + 4 < 4 || len < off + 4)
            return 0;               /* invalid block */

        /* get extra block id and data size */
        id = little2(data + off);
        size = little2(data + off + 2);
        off += 4;
        if (off + size < size || len < off + size)
            return 0;               /* invalid block */

        /* process zip64 block */
        if (id == 0x0001) {     /* zip64 Extended Information extra block */
            if (size < 16)
                return 0;           /* invalid block */
            *ulen = little4(data + off);
            *ulen_hi = little4(data + off + 4);
            *clen = little4(data + off + 8);
            *clen_hi = little4(data + off + 12);
            return 1;       /* got 8-byte lengths */
        }

        /* go to the next block */
        off += size;
    } while (off < len);
    return 0;               /* didn't get 8-byte lengths */
}

/* look for a zip64 block in the central header and update offset */
local void zip64central(unsigned char *data, unsigned len,
    unsigned long clen, unsigned long ulen,
    unsigned long *offset, unsigned long *offset_hi)
{
    unsigned off;           /* current offset in extra field */
    unsigned loc;           /* where local offset info is */
    unsigned id, size;      /* block information (id reused for flags) */

    /* scan extra blocks to find time information */
    off = 0;
    do {
        /* check that at least four bytes remain */
        if (off + 4 < 4 || len < off + 4)
            return;                 /* invalid block */

        /* get extra block id and data size */
        id = little2(data + off);
        size = little2(data + off + 2);
        off += 4;
        if (off + size < size || len < off + size)
            return;                 /* invalid block */

        /* process zip64 block */
        if (id == 0x0001) {     /* zip64 Extended Information extra block */
            loc = off;
            if (ulen == LOW4)
                loc += 8;
            if (clen == LOW4)
                loc += 8;
            if (size < loc + 8)
                return;
            *offset = little4(data + loc);
            *offset_hi = little4(data + loc + 4);
            return;
        }

        /* go to the next block */
        off += size;
    } while (off < len);
    return;
}

/* look for a UTF-8 name in the central header */
local char *utf8name(unsigned char *data, unsigned len,
                     unsigned long namecrc, char *name)
{
    unsigned off;           /* current offset in extra field */
    unsigned id, size;      /* block information (id reused for flags) */

    /* scan extra blocks to find time information */
    off = 0;
    do {
        /* check that at least four bytes remain */
        if (off + 4 < 4 || len < off + 4)
            return name;            /* invalid block */

        /* get extra block id and data size */
        id = little2(data + off);
        size = little2(data + off + 2);
        off += 4;
        if (off + size < size || len < off + size)
            return name;            /* invalid block */

        /* process and copy utf-8 name, discard old name */
        if (id == 0x7075) {         /* utf-8 extra block */
            if (size > 5 && data[off] == 1 &&
                little4(data + off + 1) == namecrc) {
                tostr((char *)(data + off + 5), size - 5);
                free(name);
                name = strnew((char *)(data + off + 5));
            }
            return name;
        }

        /* go to the next block */
        off += size;
    } while (off < len);
    return name;
}

/* ----- BZip2 Decompression Operation ----- */

#define BZOUTSIZE 32768U    /* passed outbuf better be this big */

/* decompress and write a bzip2 compressed entry */
local unsigned bunzip2(unsigned char *next, unsigned left,
                       struct in *in, struct out *out,
                       unsigned char *outbuf, unsigned char **back)
{
    int ret;
    bz_stream strm;

    /* initialize */
    strm.bzalloc = NULL;
    strm.bzfree = NULL;
    strm.opaque = NULL;
    ret = BZ2_bzDecompressInit(&strm, 0, 0);
    if (ret != BZ_OK)
        bye(ret == BZ_MEM_ERROR ? "out of memory" :
                                  "internal error");

    /* decompress */
    strm.avail_in = left;
    strm.next_in = (char *)next;
    {
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
                break;
            case BZ_DATA_ERROR:
            case BZ_DATA_ERROR_MAGIC:
                *back = NULL;           /* return a compressed data error */
                return 0;
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
    *back = (unsigned char *)(strm.next_in);
    return strm.avail_in;
}

/* ----- Main Operations ----- */

/* compare two strings ignoring case, return true if match */
local int matchcase(char *s1, char *s2)
{
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
                   int write, int quiet)
{
    unsigned long written;

    if (quiet < 2) {
        written = entries - exist - skipped;
        printf("%lu entr%s %s", written, written == 1 ? "y" : "ies",
                   write ? "written" : "verified");
        if (exist)
            printf(", %lu not overwritten", exist);
        putchar('\n');
        fflush(stdout);
    }
    if (skipped)
        fprintf(stderr, "sunzip warning: %lu entr%s skipped\n",
               skipped, skipped == 1 ? "y" : "ies");
}

/* display information about bad entry before aborting */
local void bad(char *why, unsigned long entry,
               unsigned long here, unsigned long here_hi)
{
    putchar(midline ? '\n' : '\r');
    midline = 0;
    fflush(stdout);
    fprintf(stderr, "sunzip error: %s in entry #%lu at offset 0x", why, entry);
    if (here_hi)
        fprintf(stderr, "%lx%08lx\n", here_hi, here);
    else
        fprintf(stderr, "%lx\n", here);
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
local void sunzip(int file, int quiet, int write, int over)
{
    enum {                      /* looking for ... */
        MARK,                   /* spanning signature (optional) */
        LOCAL,                  /* local headers */
        CENTRAL,                /* central directory headers */
        DIGSIG,                 /* digital signature (optional) */
        ZIP64REC,               /* zip64 end record (optional) */
        ZIP64LOC,               /* zip64 end locator (optional) */
        END,                    /* end record */
    } mode;                 /* current zip file mode */
    int ret = 0;            /* return value from zlib functions */
    int high;               /* true if have eight-byte length information */
    unsigned left;          /* bytes left in input buffer */
    unsigned long entries;  /* number of entries seen */
    unsigned long exist;    /* how many already there so not written */
    unsigned flag;          /* general purpose flags from zip header */
    unsigned method;        /* compression method */
    unsigned nlen;          /* length of file name */
    unsigned xlen;          /* length of extra field */
    unsigned madeby;        /* version and OS made by (in central directory) */
    unsigned tmp2;          /* temporary for get2() macro */
    unsigned long tmp4;     /* temporary for get4() and skip() macros */
    unsigned long here;     /* offset of this block */
    unsigned long here_hi;  /* high part of offset */
    unsigned long tmp;      /* temporary long */
    unsigned long crc;      /* cyclic redundancy check from header */
    unsigned long clen;     /* compressed length from header */
    unsigned long clen_hi;  /* high part of eight-byte compressed length */
    unsigned long ulen;     /* uncompressed length from header */
    unsigned long ulen_hi;  /* high part of eight-byte uncompressed length */
    unsigned long extatt;   /* external file attributes */
    long acc;               /* last access time for entry */
    long mod;               /* last modified time for entry */
    unsigned char *tmpp;    /* temporary for field() macro */
    unsigned char *next;    /* pointer to next byte in input buffer */
    unsigned char *back;    /* returned next pointer */
    unsigned char *inbuf;   /* input buffer */
    unsigned char *outbuf;  /* output buffer and inflate window */
    char *from, *name;      /* file name start, save area */
    char *temp = NULL;      /* where to put temporary file name in tempdir[] */
    struct timeval times[2];            /* access and modify times */
    struct stat st;                     /* for retrieving times */
    FILE *sym;                          /* for reading symbolic link file */
    struct in ins, *in = &ins;          /* input structure */
    struct out outs, *out = &outs;      /* output structure */
    z_stream strms, *strm = NULL;       /* inflate structure */
    z_stream strms9, *strm9 = NULL;     /* inflate9 structure */

    /* initialize i/o -- note that output buffer must be 64K both for
       inflateBack9() as well as to load the maximum name or extra
       fields */
    inbuf = malloc(CHUNK);
#ifdef BIGINT
    outbuf = malloc(65536);
#else
    outbuf = calloc(4, 16384);
#endif
    if (inbuf == NULL || outbuf == NULL)
        bye("out of memory");
    left = 0;
    next = inbuf;
    in->file = file;
    in->buf = inbuf;
    in->offset = 0;
    in->offset_hi = 0;
    SET_BINARY_MODE(in->file);      /* for defective operating systems */

    /* set up for writing */
    if (write) {
        strcpy(tempdir, TEMPDIR);
        if (mkdtemp(tempdir) == NULL)
            bye("write error");
        temp = pathcat(tempdir);
    }

    /* process zip file */
    mode = MARK;                /* start of zip file signature sequence */
    entries = 0;                /* entry count */
    skipped = skiplen = 0;      /* initialize skipped list */
    skiplist = NULL;
    exist = 0;                  /* count of entries not overwritten */
    do {
        /* mark current location */
        here = in->offset;
        here_hi = in->offset_hi;
        if (here < left)
            here_hi--;
        here -= left;

        /* get and interpret next header signature */
        switch (get4(in)) {

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
            get2(in);                   /* version needed to extract */
            flag = get2(in);            /* general purpose flags */
            if ((flag & 9) == 9)
                bye("cannot skip encrypted entry with deferred lengths");
            if (flag & 0xfff0U)
                bye("unknown zip header flags set");
            method = get2(in);          /* compression method */
            if ((flag & 8) && method != 8 && method != 9 && method != 12)
                bye("cannot handle deferred lengths for pre-deflate methods");
            acc = mod = dos2time(get4(in));     /* file date/time */
            crc = get4(in);             /* uncompressed CRC check value */
            clen = get4(in);            /* compressed size */
            clen_hi = 0;
            ulen = get4(in);            /* uncompressed size */
            ulen_hi = 0;
            high = 0;
            nlen = get2(in);            /* file name length */
            xlen = get2(in);            /* extra field length */

            /* skip file name (will get from central directory later) */
            skip(nlen, in);

            /* process extra field -- get entry times if there and, if needed,
               get zip64 lengths */
            field(xlen, in);            /* get extra field into outbuf */
            xtimes(outbuf, xlen, &acc, &mod);
            if (!(flag & 8) && (clen == LOW4 || ulen == LOW4))
                high = zip64local(outbuf, xlen,
                                  &clen, &clen_hi, &ulen, &ulen_hi);

            /* create temporary file (including for directories and links) */
            if (write && (method == 0 || method == 8 || method == 9 ||
                          method == 12)) {
                strcpy(temp, to36(here, here_hi));
                out->file = open(tempdir, O_WRONLY | O_CREAT, 0666);
                if (out->file == -1)
                    bye("write error");
            }
            else
                out->file = -1;

            /* initialize crc, compressed, and uncompressed counts */
            in->count = left;
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
                while (clen_hi || clen > left) {
                    put(out, next, left);
                    if (clen < left) {
                        clen_hi--;
                        clen = LOW4 - (left - clen - 1);
                    }
                    else
                        clen -= left;
                    load(in);
                }
                put(out, next, (unsigned)clen);
                left -= (unsigned)clen;
                next += (unsigned)clen;
                clen = ulen;
                clen_hi = ulen_hi;
            }
            else if (method == 8) {     /* deflated */
                if (strm == NULL) {     /* initialize inflater first time */
                    strm = &strms;
                    strm->zalloc = Z_NULL;
                    strm->zfree = Z_NULL;
                    strm->opaque = Z_NULL;
                    ret = inflateBackInit(strm, 15, outbuf);
                    if (ret != Z_OK)
                        bye(ret == Z_MEM_ERROR ? "out of memory" :
                                                 "internal error");
                }
                strm->avail_in = left;
                strm->next_in = next;
                ret = inflateBack(strm, get, in, put, out);
                left = strm->avail_in;      /* reclaim unused input */
                next = strm->next_in;
                if (ret != Z_STREAM_END) {
                    bad("deflate compressed data corrupted",
                        entries, here, here_hi);
                    bye("zip file corrupted -- cannot continue");
                }
            }
            else if (method == 9) {     /* deflated with deflate64 */
                if (strm9 == NULL) {    /* initialize first time */
                    strm9 = &strms9;
                    strm9->zalloc = Z_NULL;
                    strm9->zfree = Z_NULL;
                    strm9->opaque = Z_NULL;
                    ret = inflateBack9Init(strm9, outbuf);
                    if (ret != Z_OK)
                        bye(ret == Z_MEM_ERROR ? "not enough memory (!)" :
                                                 "internal error");
                }
                strm9->avail_in = left;
                strm9->next_in = next;
                ret = inflateBack9(strm9, get, in, put, out);
                left = strm9->avail_in;      /* reclaim unused input */
                next = strm9->next_in;
                if (ret != Z_STREAM_END) {
                    bad("deflate64 compressed data corrupted",
                        entries, here, here_hi);
                    bye("zip file corrupted -- cannot continue");
                }
            }
            else if (method == 12) {    /* bzip2 compression */
                left = bunzip2(next, left, in, out, outbuf, &back);
                if (back == NULL) {
                    bad("bzip2 compressed data corrupted",
                        entries, here, here_hi);
                    bye("zip file corrupted -- cannot continue");
                }
                next = back;
            }
            else {                      /* skip encrpyted or unknown method */
                if (quiet < 1)
                    bad(method == UINT_MAX ? "skipping encrypted entry" :
                        "skipping unknown compression method",
                        entries, here, here_hi);
                skip(clen, in);
                tmp = clen_hi;
                if (high) {             /* big one! this could take a while */
                    while (tmp--) {
                        skip(0x80000000UL, in);
                        skip(0x80000000UL, in);
                    }
                }
                skipadd(here, here_hi);
            }

            /* deduct unused input from compressed data count */
            if (in->count < left)
                in->count_hi--;
            in->count -= left;

            /* set file times, close file */
            if (out->file != -1) {
                /* set times just before closing */
                times[0].tv_sec = acc;
                times[0].tv_usec = 0;
                times[1].tv_sec = mod;
                times[1].tv_usec = 0;
                futimes(out->file, times);
                if (close(out->file))
                    bye("write error");
            }

            /* get data descriptor if present --
               allow for several possibilities: four-byte or eight-byte
               lengths, with no signature or with one of two signatures
               (the second signature is not known yet -- to be defined
               by PKWare -- for now allow only one) */
            if (flag & 8) {
                /* look for PKWare descriptor (even though no one uses it) */
                crc = get4(in);         /* uncompressed data check value */
                clen = get4(in);        /* compressed size */
                clen_hi = 0;
                ulen = get4(in);        /* uncompressed size */
                ulen_hi = 0;
                if (!GOOD()) {
                    /* look for an Info-ZIP descriptor (original -- in use) */
                    /* (%% NOTE: replace second signature when actual known) */
                    if (crc == 0x08074b50UL || crc == 0x08074b50UL) {
                        tmp = crc;      /* temporary hold for signature */
                        crc = clen;
                        clen = ulen;
                        ulen = get4(in);
                        if (!GOOD()) {
                            /* try no signature with eight-byte lengths */
                            clen_hi = clen;
                            clen = crc;
                            crc = tmp;
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

            /* verify entry and display information */
            if (method == 0 || method == 8 || method == 9 || method == 12) {
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
            get1(in);                   /* version made by */
            madeby = get1(in);          /* OS made by */
            skip(14, in);               /* skip up through crc */
            clen = get4(in);            /* compressed length */
            ulen = get4(in);            /* uncompressed length */
            nlen = get2(in);            /* file name length */
            xlen = get2(in);            /* extra field length */
            flag = get2(in);            /* comment length */
            skip(4, in);                /* disk #, internal attributes */
            extatt = get4(in);          /* external attributes */
            here = get4(in);            /* offset of local header */
            here_hi = 0;

            /* get and process file name */
            field(nlen, in);                /* get file name */
            tmp = crc32(crc32(0L, Z_NULL, 0), outbuf, nlen);
            from = (char *)outbuf;
            tostr(from, nlen);              /* make name into a string */
            tohere(from, madeby);           /* convert name for this OS */
            from = deroot(from);            /* force relative */
            name = strnew(from);            /* copy name */

            /* process extra field to get 64-bit offset, if there */
            field(xlen, in);                /* get extra field */
            zip64central(outbuf, xlen, clen, ulen, &here, &here_hi);
#ifdef BIGLONG
            here += here_hi << 32;
            here_hi = 0;
#endif

            /* process extra field to get UTF-8 name, if there */
            name = utf8name(outbuf, xlen, tmp, name);

            /* If tempdir and name collide (pretty unlikely), rename tempdir */
            if (write) {
                /* set up names to compare (destructively) */
                temp = pathbrk(tempdir);
                if (temp != NULL)
                    *temp = 0;
                from = pathbrk(name);
                if (from != NULL) {
                    ret = *from;
                    *from = 0;
                }

                /* if collision (!!) then make a new temporary directory, move
                   the contents over, remove the old one, and update the name
                   of the temporary directory in tempdir[] */
                if (matchcase(tempdir, name)) {
                    temp = malloc(sizeof(tempdir));
                    if (temp == NULL)
                        bye("out of memory");
                    strcpy(temp, TEMPDIR);
                    if (mkdtemp(temp) == NULL)
                        bye("write error");
                    mvtempdir(temp);
                    if (rmdir(tempdir))
                        bye("write error");
                    strcpy(tempdir, temp);
                    free(temp);
                }

                /* restore name and reconstruct temporary directory path */
                if (from != NULL)
                    *from = ret;
                temp = pathcat(tempdir);
            }

            /* construct (again) temporary name from offset */
            if (write)
                strcpy(temp, to36(here, here_hi));

            /* display name */
            if (quiet < 1) {
                fputs(name, stdout);
                midline = 1;
            }

            /* see if this entry was skipped */
            if (skipfind(here, here_hi)) {
                if (quiet < 1)
                    puts(" (skipped)");
            }

            /* if not writing, then verification was ok */
            else if (!write) {
                if (quiet < 1)
                    puts(" OK");
            }

            /* writing: see if the temporary file is there */
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
                ret = stat(tempdir, &st);
                if (ret)
                    bye("temporary file missing in action!");
                unlink(tempdir);
                graft(name, 0, st.st_atimespec.tv_sec,
                               st.st_mtimespec.tv_sec);
                if (quiet < 1)
                    puts(" OK");
            }

            /* if it's a symbolic link, read it and make it */
            else if (((extatt >> 16) & 0170000) == 0120000 && BYUNIX()) {
                sym = fopen(tempdir, "r");
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
                ret = rename(tempdir, name);    /* replaces existing file */
                if (ret)
                    bye("write error");
                if (quiet < 1)
                    puts(" OK");
            }
            midline = 0;

            /* apply external attributes -- use Unix if we have them */
            if ((extatt >> 16) && BYUNIX())
                chmod(name, (extatt >> 16) & 07777);
            else if (!isdir(name))
                chmod(name, (extatt & 1 ? 0444 : 0644));

            /* done with name */
            free(name);

            /* skip comment field */
            skip(flag, in);             /* skip comment */
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
            while (ulen_hi) {
                skip(0x80000000UL, in);
                skip(0x80000000UL, in);
                ulen_hi--;
            }
            skip(ulen, in);
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
            summary(entries, exist, write, quiet);
            skip(16, in);               /* counts and offsets */
            flag = get2(in);            /* zip file comment length */
            skip(flag, in);             /* zip file comment */
            break;

        default:
            bye("zip file format error (unknown zip signature)");
        }
    } until (mode == END);              /* until end record reached (or EOF) */

    /* clean up */
    if (write) {
        rmtempdir();                    /* remove the temporary directory */
        setdirtimes(root);              /* set saved directory times */
        prune(&root);                   /* free the directory tree */
    }
    if (strm9 != NULL)
        inflateBack9End(strm9);
    if (strm != NULL)
        inflateBackEnd(strm);
    if (skiplist != NULL)
        free(skiplist);
    free(outbuf);
    free(inbuf);

    /* check for junk */
    if (left != 0 || get(in, NULL) != 0)
        fputs("sunzip warning: junk after end of zip file\n", stderr);
}

/* catch interrupt in order to delete temporary files and directory */
local void cutshort(int n)
{
    bye("user interrupt");
}

/* process arguments and then unzip from stdin */
int main(int argc, char **argv)
{
    int opts, sub;
    int quiet = 0, write = 1, over = 0;
    char *arg;

    /* for rmtempdir(), called by bye() */
    tempdir[0] = 0;

    /* catch interrupt signal */
    signal(SIGINT, cutshort);

    /* give help if input not redirected */
    if (isatty(0)) {
        puts("sunzip 0.31, streaming unzip by Mark Adler");
        puts("usage: ... | sunzip [-t] [-o] [-q[q]] [dir]");
        puts("       sunzip [-q[q]] [dir] < infile.zip");
        puts("");
        puts("\t-t: test -- don't write files");
        puts("\t-o: overwrite existing files");
        puts("\t-q: quiet -- display summary info and errors only");
        puts("\t-qq: really quiet -- display errors only");
        puts("\tdir: subdirectory to create files in (if writing)");
        return 0;
    }

    /* process arguments */
    opts = 1;                   /* in options */
    sub = 0;                    /* no subdirectory yet */
    while (argv++, --argc) {
        if (opts && **argv == '-') {
            if (sub)
                bye("cannot put options after subdirectory");
            arg = *argv + 1;
            if (*arg == 0)
                opts = 0;
            else do {
                switch (*arg) {
                case 'o':           /* overwrite existing files */
                    over = 1;
                    break;
                case 'q':           /* quiet */
                    quiet++;
                    break;
                case 't':           /* test */
                    write = 0;
                    break;
                default:
                    bye("unknown option");
                }
            } while (*++arg);
        }
        else {                      /* subdirectory to put files in */
            sub = 1;                /* don't process options after this */
            if (write) {            /* ignore subdirectory if not writing */
                mkpath(*argv);
                if (chdir(*argv))
                    bye("write error");
            }
        }
    }

    /* check option consistency */
    if (over && !write)
        bye("can't combine -o with -t");

    /* unzip from stdin */
    sunzip(0, quiet, write, over);
    return 0;
}
