CC := gcc

CFLAGS := -Wall -Wextra -O2
LDFLAGS :=
LDLIBS := -lmodbus -lpthread

TARGET := modbus
SOURCE := modbus.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(TARGET) *.o

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/$(TARGET)
