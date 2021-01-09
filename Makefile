CFLAGS=-O3 -Wall -Wextra -pedantic -Wcast-qual
sunzip: sunzip.o infback9.o inftree9.o blast.o
	cc -o $@ $^ -lbz2 -lz
sunzip.o: sunzip.c
	cc $(CFLAGS) -DDEFLATE64 -DPKDCL -DBZIP2 -c $<
infback9.o: infback9.c zutil.h infback9.h inftree9.h inflate9.h
inftree9.o: inftree9.c zutil.h inftree9.h
blast.o: blast.c blast.h
clean:
	@rm -f *.o
	@rm -f sunzip
