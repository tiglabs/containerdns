ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

DEPDIR = $(SRCDIR)/../deps

INCLUDE += -I$(DEPDIR)/libmicrohttpd/src/include
STATIC_LIBS += $(DEPDIR)/libmicrohttpd/src/microhttpd/.libs/libmicrohttpd.a


INCLUDE += -I$(DEPDIR)/libjansson/src
STATIC_LIBS += $(DEPDIR)/libjansson/src/.libs/libjansson.a

# binary name
APP = kdns

KDNS_FWD_METRICS = true
KDNS_METRICS = true
# all source are stored in SRCS-y
SRCS-y := main.c\
dns-conf.c \
parser.c \
netdev.c \
forward.c \
db_update.c \
webserver.c \
domain_update.c \
view_update.c \
kdns-adap.c \
tcp_process.c \
local_udp_process.c \
process.c\
hashMap.c\
metrics.c\
rate_limit.c\
ctrl_msg.c

ifdef KDNS_METRICS
CFLAGS += -DENABLE_KDNS_METRICS
endif
ifdef KDNS_FWD_METRICS
CFLAGS += -DENABLE_KDNS_FWD_METRICS
endif

CFLAGS += $(INCLUDE)

CFLAGS += $(WERROR_FLAGS) -g -O2 -Wno-cast-qual

CFLAGS += -I$(SRCDIR)/../core/$(RTE_TARGET)/include

LDLIBS += -L$(SRCDIR)/../core/$(RTE_TARGET)/lib/ -lkdns -lrt -lpthread

LDLIBS += $(STATIC_LIBS)
include $(RTE_SDK)/mk/rte.extapp.mk
