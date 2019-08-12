FROM debian:9

# To update, see https://github.com/madler/zlib/releases
ENV ZLIB_SRC https://github.com/madler/zlib/archive/v1.2.11.tar.gz
ENV ZLIB_SHA512 104c62ed1228b5f1199bc037081861576900eb0697a226cafa62a35c4c890b5cb46622e399f9aad82ee5dfb475bae26ae75e2bd6da3d261361b1c8b996970faf


RUN apt-get -qq update && \
  apt-get -y --no-install-recommends install build-essential libbz2-dev curl ca-certificates
WORKDIR /usr/src

RUN echo "$ZLIB_SHA512  zlib.tar.gz" > zlib.tar.gz.sha512
RUN curl -sS -L --fail $ZLIB_SRC > zlib.tar.gz && \
    sha512sum -c zlib.tar.gz.sha512 && \
    tar zxfv zlib.tar.gz && \
    mv zlib-* zlib

# Compile zlib and install to /usr/local

WORKDIR /usr/src/zlib
RUN ./configure && make && make install

# We'll need the *.o from blast and infback9 later
WORKDIR /usr/src/zlib/contrib/blast
RUN gcc -O3 -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN  -I .  -I ../../ -c -Wall -Werror -fpic blast.c
WORKDIR /usr/src/zlib/contrib/infback9
# gcc -O3 -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN  -c -o 
RUN gcc  -O3 -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN  -I .  -I ../../ -c -Wall -Werror -fpic infback9.c inftree9.c


WORKDIR /usr/src/

####
# Add sunzip source code (modify below if additional files needed)
COPY sunzip.c  /usr/src/sunzip/
###
# OR - uncomment below to use latest sunzip release:
# To update, see https://github.com/madler/sunzip/releases
#ENV SUNZIP_SRC https://github.com/madler/sunzip/archive/v0.4.tar.gz
#ENV SUNZIP_SHA512 85331549755181704592a74e9533ec74f474017fe8891801df0416865323e8bc5b3540e2b0b276e50037b7e57e70bb6b702741136e0aae4c6658c7ca1a3e27a6
#RUN echo "$SUNZIP_SHA512  sunzip.tar.gz" > sunzip.tar.gz.sha512
#RUN curl -sS -L --fail $SUNZIP_SRC > sunzip.tar.gz && \
#    sha512sum -c sunzip.tar.gz.sha512 && \
#    tar zxfv sunzip.tar.gz && \
#    mv sunzip-* sunzip
####

# Compile sunzip binary
WORKDIR /usr/src/sunzip
RUN gcc  -O3 -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN \
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

# Test it actually works
RUN curl -L https://github.com/madler/sunzip/archive/master.zip | ./sunzip -t
# We'll "install"
RUN cp sunzip /usr/local/bin


# Make a smaller base image to only
# include our binaries
FROM debian:9
COPY --from=0 /usr/local/ /usr/local/

WORKDIR /data
VOLUME /data
CMD ["/usr/local/bin/sunzip"]