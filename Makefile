CXX = c++
CXXFLAGS = -Wall -pedantic -ansi -Wno-long-long -O2
LDFLAGS = -lmilter -lpthread -lcrypto
PREFIX = /usr/local

OBJFILES = address.o config.o prvs.o openssl-threads.o batv-milter.o

all: batv-milter

batv-milter: $(OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o batv-milter

install:
	install -m 755 batv-milter $(PREFIX)/sbin/

.PHONY: all clean install
