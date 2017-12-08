CC = gcc
CFLAGS = -std=c89 -pedantic -Wextra -Wall -g
SOURCES = sniffer.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = sniffer 
all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS)  -o $@
.o:
	$(CC) $(CFLAGS) $< -c $@

clean:
	rm $(EXECUTABLE) *.o 
