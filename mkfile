<$MKROOT/$objtype/mkfile

LIB=libeezo.a

OFILES=\
	term.$O\
	res.$O\
	bn.$O\
	bcl.$O\
	jomplement.$O\
	x86.$O\
	native.$O\

HFILES=\
	types.h\
	term.h\
	res.h\
	bn.h\
	bcl.h\
	jomplement.h\
	x86.h\
	native.h\

CFLAGS=-g -O2 -Wall -I.

<$MKROOT/proto/mklib
