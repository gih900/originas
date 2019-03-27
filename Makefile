CC = cc
CFLAGS  = -g
COMPILE  = $(CC) $(CFLAGS)

all:	originas

libavl.o: libavl.c libavl.h
	$(COMPILE) -g -c libavl.c

originas: originas.c libavl.o
	$(COMPILE) -o originas originas.c libavl.o -lz


clean:
	rm -f libavl.o
	rm -f originas

install: all
	install -c originas /usr/local/bin

