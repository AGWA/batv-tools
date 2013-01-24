CXX := g++
CXXFLAGS := -Wall -pedantic -ansi -Wno-long-long -O2
LDFLAGS := -lmilter -lpthread -Wl,-Bstatic -lcrypto -Wl,-Bdynamic

OBJFILES = address.o config.o prvs.o openssl-threads.o batv-milter.o

all: batv-milter

batv-milter: $(OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o batv-milter

.PHONY: all clean
