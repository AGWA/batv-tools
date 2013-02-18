CXX = c++
CXXFLAGS = -Wall -pedantic -ansi -Wno-long-long -O2
LDFLAGS = -L/usr/lib/libmilter -lmilter -lpthread -lcrypto
PREFIX = /usr/local

PROGRAMS = batv-milter batv-filter
COMMON_OBJFILES = address.o common.o key.o prvs.o
MILTER_OBJFILES = $(COMMON_OBJFILES) config.o openssl-threads.o batv-milter.o
FILTER_OBJFILES = $(COMMON_OBJFILES) batv-filter.o

all: $(PROGRAMS)

batv-milter: $(MILTER_OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

batv-filter: $(FILTER_OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o $(PROGRAMS)

install:
	install -m 755 batv-milter $(PREFIX)/sbin/
	install -m 755 batv-filter $(PREFIX)/bin/

.PHONY: all clean install
