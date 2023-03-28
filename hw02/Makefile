CC = g++
CFLAGS = -g3 -fsanitize=address -O2 -Wall -pedantic
LDFLAGS = -lcrypto

all: main
run:
	# run your tests here...
	# to zrovna
main: main.o
	$(CC) -o $@ $< $(LDFLAGS)
%.o: %.cpp
	$(CC) -c -o $@ $< $(CFLAGS)

