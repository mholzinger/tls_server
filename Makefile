ARCHTYPE = $(shell uname -m)
CC = gcc

FIPS_MAJ=2.0

OPENSSLDIR    = /usr/local/ssl
FIPS_INCLUDE  = $(OPENSSLDIR)/include
FIPSMODULE    = $(OPENSSLDIR)/lib/fipscanister.o
LIBCRYPTO     = $(OPENSSLDIR)/lib/libcrypto.a
PROG = tls_server
OBJS = $(PROG).o

CFLAGS = -I$(FIPS_INCLUDE) $(PLATFORM) -std=c99 -pedantic -Wall $(DEBUG_FLAGS) $(CXXFLAGS)

RM = rm -rf

OS = $(shell uname -s)
OUTPUT_OPTION = -o $@

vpath %.c src

ifeq ($(OS),Darwin)
	CXXFLAGS   = -D_DARWIN_C_SOURCE
	PLATFORM   := -DTOSDARWIN
else
	ifeq ($(OS),Linux)
		PLATFORM   := -DTOSLINUX
	endif
endif

ifdef TDEBUG
	DEBUG_FLAGS = -DTDEBUG -g -ggdb
else
	DEBUG_FLAGS =
endif

all: clean $(PROG)

.PHONY: clean
clean:
	@echo 'clean'
	$(RM) *.o $(PROG) *._* *~
	@echo ' '

$(PROG): $(OBJS)
	@echo 'Building target: $@'
	env FIPSLD_CC=$(CC) $(OPENSSLDIR)/fips-$(FIPS_MAJ)/bin/fipsld \
		-o $(PROG) $(OBJS) $(LIBCRYPTO) -lssl -ldl
	@echo 'Finished building target: $@'
	@echo ' '

$(PROG).o: src/$(PROG).c
	@echo 'Building target: $@'
	$(CC) $(CFLAGS) -c $(OUTPUT_OPTION) src/$(PROG).c
	@echo 'Finished building target: $@'
	@echo ' '
