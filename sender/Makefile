TARGET = sender
CC = gcc
CFLAGS = -Wall -I./core -I./payload -I./protocols

SOURCES := $(wildcard core/*.c) $(wildcard payload/*.c) $(wildcard protocols/*.c)
OBJECTS := $(addprefix build/,$(notdir $(SOURCES:.c=.o)))

VPATH = core:payload:protocols

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET)

build/%.o: %.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build:
	mkdir -p build

clean:
	rm -rf build $(TARGET)

.PHONY: all clean build
