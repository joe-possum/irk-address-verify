LIBS = -lmbedtls -lmbedcrypto
LDFLAGS =
CFLAGS = -Wall -O3

CC = gcc
BINARY = verify-address

${BINARY} : verify-address.o
	${CC} -o $@ $^ ${LDFLAGS} ${LIBS}

%.o : %.c
	${CC} ${CFLAGS} -c $^
