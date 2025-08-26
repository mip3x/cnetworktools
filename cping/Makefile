CC = gcc
CFLAGS = -Iinclude -Wall -Wextra -g

TARGET = ping

all: $(TARGET)

ping: ping.o
	$(CC) $(CFLAGS) -o $@ $^

ping.o: ping.c ping.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -rf $(TARGET) *.o

.PHONY: all clean
