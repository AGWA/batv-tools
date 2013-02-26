CXX = c++
CXXFLAGS = -Wall -pedantic -ansi -Wno-long-long -O2
LDFLAGS = -lcrypto
LIBMILTER_LDFLAGS = -L/usr/lib/libmilter -lmilter -lpthread
PREFIX = /usr/local

MILTER_PROGRAMS = batv-milter
TOOLS_PROGRAMS = batv-validate batv-sign
PROGRAMS = $(TOOLS_PROGRAMS) $(MILTER_PROGRAMS)

COMMON_OBJFILES = address.o common.o key.o prvs.o
MILTER_OBJFILES = config.o openssl-threads.o

all: all-tools all-milter

all-tools: $(TOOLS_PROGRAMS)

all-milter: $(MILTER_PROGRAMS)

batv-milter: $(COMMON_OBJFILES) $(MILTER_OBJFILES) batv-milter.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBMILTER_LDFLAGS)

batv-validate: $(COMMON_OBJFILES) batv-validate.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

batv-sign: $(COMMON_OBJFILES) batv-sign.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o $(PROGRAMS)

install: install-tools install-milter

install-tools:
	install -m 755 batv-validate $(PREFIX)/bin/
	install -m 755 batv-sign $(PREFIX)/bin/
	install -m 755 batv-sendmail $(PREFIX)/bin/

install-milter:
	install -m 755 batv-milter $(PREFIX)/sbin/

.PHONY: all all-tools all-milter clean install install-tools install-milter
