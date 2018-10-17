

DEPDIR = ./
all:
	cd $(DEPDIR)/libmicrohttpd && chmod +x configure && ./configure && autoreconf -ivf && make -j 4
	cd $(DEPDIR)/libjansson && chmod +x configure && ./configure && autoreconf -ivf && make -j 4
clean:
	cd $(DEPDIR)/libmicrohttpd &&  make distclean
	cd $(DEPDIR)/libjansson &&  make distclean