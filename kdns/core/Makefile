ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

DEPDIR = $(SRCDIR)/../deps

INCLUDE += -I$(DEPDIR)/libjansson/src

# Default target, can be overriden by command line or environment
include $(RTE_SDK)/mk/rte.vars.mk

# binary name
LIB = libkdns.a

# all source are stored in SRCS-y
SRCS-y := dns.c \
domain_store.c \
packet.c \
query.c \
radtree.c \
util.c \
view.c \
zone.c 
SYMLINK-y-include += buffer.h \
dns.h \
domain_store.h \
kdns.h\
packet.h \
query.h \
radtree.h \
util.h \
view.h \
zone.h 

CFLAGS += $(INCLUDE)

CFLAGS += $(WERROR_FLAGS) -g -O2 -Wno-cast-qual

include $(RTE_SDK)/mk/rte.extlib.mk
