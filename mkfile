<$MKROOT/$objtype/mkfile

LIB=libeezo.a

OFILES=\
	term.$O\
	bcl.$O\
	jomplement.$O\

HFILES=\
	types.h\
	term.h\
	bcl.h\
	jomplement.h\

CFLAGS=-g -O2 -Wall -I.

<$MKROOT/proto/mklib
