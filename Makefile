CC=gcc
CFLAGS=-Wall -Werror

wicap: *.c *.h
	$(CC) $(CFLAGS) -pthread -o $@ *.c

.PHONY: clean

clean:
	rm -f *.o
	rm -f wicap
