CC = gcc
CFLAGS = -Wall -g -D_FILE_OFFSET_BITS=64 `pkg-config fuse --cflags`
LDFLAGS = `pkg-config fuse --libs` -lcrypto
TARGET = mirror_fs
SOURCES = mirror_fs.c


all: $(TARGET)

$(TARGET): $(SOURCES) 
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean