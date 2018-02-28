AUTOMAKE_OPTIONS=foreign

noinst_PROGRAMS=sign
sign_SOURCES=sign.c common.h common.c HashType.h HashType.c

INCLUDES=-I/usr/i586-mingw32msvc/libc/usr/include

LIBS+= -lnettle -lhogweed
#LIBS+= -L/usr/i586-mingw32msvc/libc/usr/lib -lnettle -lhogweed