CXX = c++
CXXFLAGS = -Wall -pedantic -ansi -Wno-long-long -O2
LDFLAGS = -L/usr/lib/libmilter -lmilter -lpthread -lcrypto
PREFIX = /usr/local

COMMON_OBJFILES = address.o common.o key.o prvs.o
MILTER_OBJFILES = $(COMMON_OBJFILES) config.o openssl-threads.o batv-milter.o

all: batv-milter

batv-milter: $(MILTER_OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o batv-milter

install:
	install -m 755 batv-milter $(PREFIX)/sbin/

.PHONY: all clean install
