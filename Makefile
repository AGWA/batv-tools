CXX = c++
CXXFLAGS ?= -Wall -pedantic -O2
CXXFLAGS += -Wno-long-long
LDFLAGS += -lcrypto
LIBMILTER_LDFLAGS = -L/usr/lib/libmilter -lmilter -lpthread
PREFIX = /usr/local

MILTER_PROGRAMS = batv-milter
TOOLS_PROGRAMS = batv-validate batv-sign
PROGRAMS = $(TOOLS_PROGRAMS) $(MILTER_PROGRAMS)

COMMON_OBJFILES = address.o common.o config.o key.o prvs.o verify.o
MILTER_OBJFILES = config-milter.o openssl-threads.o

all: all-tools all-milter

all-tools: $(TOOLS_PROGRAMS)

all-milter: $(MILTER_PROGRAMS)

batv-milter: $(COMMON_OBJFILES) $(MILTER_OBJFILES) batv-milter.o
	$(CXX) $(CXXFLAGS) -o $@ $(COMMON_OBJFILES) $(MILTER_OBJFILES) batv-milter.o $(LDFLAGS) $(LIBMILTER_LDFLAGS)

batv-validate: $(COMMON_OBJFILES) batv-validate.o
	$(CXX) $(CXXFLAGS) -o $@ $(COMMON_OBJFILES) batv-validate.o $(LDFLAGS)

batv-sign: $(COMMON_OBJFILES) batv-sign.o
	$(CXX) $(CXXFLAGS) -o $@ $(COMMON_OBJFILES) batv-sign.o $(LDFLAGS)

clean:
	rm -f *.o $(PROGRAMS)

install: install-tools install-milter

install-tools:
	install -m 755 batv-validate $(DESTDIR)$(PREFIX)/bin/
	install -m 755 batv-sign $(DESTDIR)$(PREFIX)/bin/
	install -m 755 batv-sendmail $(DESTDIR)$(PREFIX)/bin/

install-milter:
	install -m 755 batv-milter $(DESTDIR)$(PREFIX)/sbin/

.PHONY: all all-tools all-milter clean install install-tools install-milter
