CC = g++
CFLAGS = -Wall
LDLIBS = -lpcap

all: deauth

mac.o : mac.h mac.cpp

main.o: deauthdr.h main.cpp

deauth: main.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f deauth *.o