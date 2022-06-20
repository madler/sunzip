Synopsis
--------

_sunzip_ is a streaming unzip utility. It will read a .zip file from stdin and
decompress its contents into the current directory. Command line options allow
specifying a different destination directory; overwriting existing files
(normally prevented); streaming each file to specified program and saving its
stdout instead of original file; testing the contents of .zip file instead 
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

Test
----

`cat any.zip | sunzip`

License
-------

This code is under the zlib license, permitting free commercial use.
