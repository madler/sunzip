Synopsis
--------

_sunzip_ is a streaming unzip utility. It will read a .zip file from stdin and
decompress its contents into the current directory. Command line options allow
specifying a different destination directory, overwriting existing files
(normally prevented), and testing or listing the contents of .zip file instead
of writing the decompressed files.

_sunzip_ can decompress methods 0 (stored), 8 (deflated), 9 (Deflate64), 10
(DCL imploded), and 12 (bzip2). _sunzip_ handles Zip64 .zip files. It does not
handle encrypted .zip files.

Motivation
----------

Most unzip utilities require random access to the .zip file, since they first
read the central directory at the end, and then use that to access the entries
in the .zip file. Those utilities cannot accept a .zip file on a pipe. _sunzip_
reads and processes the .zip file contents sequentially. The entry information
in the central directory is applied to the already decompressed files when the
central directory is read.

Installation
------------

Compile and link with zlib, infback9.c and inftree9.c (found in zlib's contrib
directory), blast.c (also in contrib), and libbz2. blast.c from zlib 1.2.9 or
later must be used.



Usage
-----

    cat any.zip | sunzip

For help, run `sunzip` without arguments on a terminal:

```
sunzip 0.4, streaming unzip by Mark Adler
usage: ... | sunzip [-t] [-o] [-p x] [-q[q]] [dir]
       sunzip [-t] [-o] [-p x] [-q[q]] [dir] < infile.zip

	-t: test -- don't write files
	-l: list zip filenames -- don't write files
	-o: overwrite existing files
	-p x: replace parent reference .. with this character
	-q: quiet -- display summary info and errors only
	-qq: really quiet -- display errors only
	dir: subdirectory to create files in (if writing)
```

`sunzip` will decompress to the current directory unless `dir` is specified.

The `sunzip -t` option will test decompression and verify crc checksums
without writing any files to disk.

The `sunzip -l` option is equivalent to `-t -q -q`, but instead
of testing decompression will only print the file and directory
names as they are encountered in the stream. Note that file
names from the local file headers are less reliable than the
end-of-file TOC that would otherwise be used, and may
include duplicates, deleted and encrypted files.



License
-------

This code is under the [zlib license](sunzip.c), permitting free commercial use.
