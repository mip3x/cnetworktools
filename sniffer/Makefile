OBJECTS = sniffer.o
TARGET = sniffer
CC = gcc

default: $(TARGET)

%.o: %.c 
	$(CC) -c $< -o $@

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@

clean:
	-rm -f $(OBJECTS)
	-rm -f $(TARGET)
