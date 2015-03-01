CFLAGS=$(shell pkg-config --cflags libsodium) -std=c11
LDFLAGS=$(shell pkg-config --libs libsodium) -std=c11
	
SRCS=main.c
OBJS=$(subst .c,.o,$(SRCS))

all: cryptid

cryptid: $(OBJS)
	$(CC) $(LDFLAGS) -o cryptid $(OBJS) $(LDLIBS) 

depend: .depend

.depend: $(SRCS)
	rm -f ./.depend
	$(CC) $(CFLAGS) -MM $^>>./.depend;

clean:
	$(RM) $(OBJS)

dist-clean: clean
	$(RM) *~ .depend

include .depend

