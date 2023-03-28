CC = g++
CFLAGS = -g3 -fsanitize=address -O2 -Wall -char
LDFLAGS = -lcrypto

all: main
run:
	# run your tests here...
	# to zrovna
main: main.o
	$(CC) -o $@ $< $(LDFLAGS)
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

