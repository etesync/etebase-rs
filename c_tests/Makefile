TARGET = tests
LIBS = -L. -l:../target/debug/libetesync.so
CC = gcc
CFLAGS = -g -Wall

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -Wall -fsanitize=address -fno-omit-frame-pointer $(LIBS) -o $@

check: $(TARGET)
	./tests

clean:
	-rm -f *.o
	-rm -f $(TARGET)
