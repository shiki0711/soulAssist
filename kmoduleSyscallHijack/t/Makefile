SRCS = fake/rbtree.c jsonTest.c ../src/json.c

OBJS = $(SRCS:.c=.o)

TARGET = jsonTest

CC = gcc

CFLAGS += -Ifake -I../src -D__UT__

%.o: *%.c
	$(CC) -g -c -Wall $(CFLAGS) $<

$(TARGET): $(OBJS)
	$(CC)  -o $(TARGET) *.o

.PHONY: all clean

all: $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET) *.o
