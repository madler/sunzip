Synopsis
--------

_sunzip_ is a streaming unzip utility. It will read a .zip file from stdin and
decompress its contents into the current directory. Command line options allow
specifying a different destination directory, overwriting existing files
(normally prevented), and testing the contents of .zip file instead of writing
the decompressed files.

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


### Example: Debian/Ubuntu

The below example compiles a recent [zlib](https://github.com/madler/zlib) that is 
installed to `/usr/local/lib` - then `contrib/blast` and `contrib/infback9`
before finally downloading and compiling `sunzip.c`. 

Modify the URLs below to use different versions.

```bash
apt-get -y install build-essential libbz2-dev curl ca-certificates
cd /tmp

curl -L -o zlib.tar.gz https://github.com/madler/zlib/archive/v1.2.11.tar.gz
tar zxfv zlib.tar.gz
mv zlib-* zlib && cd zlib
./configure && make
sudo make install

cd contrib/blast
gcc -O3 -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN  -I .  -I ../../ -c -Wall -Werror -fpic blast.c
cd ../infback9
gcc  -O3 -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN  -I .  -I ../../ -c -Wall -Werror -fpic infback9.c inftree9.c

cd /tmp
curl -L -o sunzip.tar.gz https://github.com/madler/sunzip/archive/v0.4.tar.gz
tar zxfv sunzip.tar.gz
cd sunzip-*
gcc  -O3 -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN \
  -I ../zlib/contrib/infback9 \
  -I ../zlib/contrib/blast \
  -I ../zlib/contrib/bz \
  -I /usr/local/include \
  -L /usr/local/lib \
  -Wl,-rpath=/usr/local/lib \
  -o sunzip \
  ../zlib/zutil.o \
  ../zlib/contrib/blast/blast.o \
  ../zlib/contrib/infback9/infback9.o  \
  ../zlib/contrib/infback9/inftree9.o  \
  sunzip.c -lbz2 -lz

sudo cp sunzip /usr/local/bin
sunzip
```

Usage
-----

    cat any.zip | sunzip

For help, run `sunzip` without arguments on a terminal:

```
sunzip 0.4, streaming unzip by Mark Adler
usage: ... | sunzip [-t] [-o] [-p x] [-q[q]] [dir]
       sunzip [-t] [-o] [-p x] [-q[q]] [dir] < infile.zip

	-t: test -- don't write files
	-o: overwrite existing files
	-p x: replace parent reference .. with this character
	-q: quiet -- display summary info and errors only
	-qq: really quiet -- display errors only
	dir: subdirectory to create files in (if writing)
```

Docker
------

If you have [Docker](https://www.docker.com/), you can build a 
Debian-compatible binary using:

    docker build -t madler/sunzip .

The docker image has the `/data` volume as default working 
directory where files will be extracted. 

The below example extract from a ZIP URL and extracts it into
the host `/tmp/1` exposed as `/data`. 


    URL=https://github.com/madler/sunzip/archive/master.zip
    curl --fail -L $URL | docker run -i -v /tmp/1:/data madler/sunzip

**Tip**: To avoid extracted files owned by `root` make sure the mapped 
directory exists and specify the Docker option `--user` with your UID:

```bash
    mkdir /tmp/5
    URL=https://github.com/madler/sunzip/archive/master.zip
    curl --fail -L $URL | docker run --user `id -u` -i -v /tmp/5:/data madler/sunzip
    ls -al /tmp/5
```

License
-------

This code is under the [zlib license](sunzip.c), permitting free commercial use.
