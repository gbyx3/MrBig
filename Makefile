
PACKAGE=MrBig

VERSION=0.26.7

COMPANY=Axians AB
COPYRIGHT=Axians AB
DESCRIPTION=MrBig client for Xymon
PRODUCT=MrBig client for Xymon
INTERNAL=MrBig client for Xymon
COMMENTS=MrBig client for Xymon

VER_RC=winver.rc
VER_RES=winver.res

CFLAGS=-Wall -Werror -O2 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -g -ggdb -DPACKAGE=\"$(PACKAGE)\" -DVERSION=\"$(VERSION)\"
DOCS=INSTALL EVENTS ChangeLog DEVELOPMENT TODO EXT LARRD logs.cmd testfile.txt TLS.md
SRCS=cfg.c cpu.c disk.c memory.c msgs.c ntpskew.c procs.c svcs.c mrbig.c \
	service.c readperf.c readlog.c ext_test.c \
	strlcpy.c disphelper.c wmi.c tls.c tls_endpoint.c
HDRS=mrbig.h disphelper.h tls.h tls_endpoint.h
OBJS=cfg.o cpu.o disk.o memory.o msgs.o ntpskew.o procs.o svcs.o mrbig.o \
	service.o readperf.o readlog.o ext_test.o \
	strlcpy.o disphelper.o wmi.o tls.o tls_endpoint.o
NTOBJS=cfg.o cpu.o disk.o memory.o msgs.o ntpskew.o procsnt.o svcs.o mrbig.o \
	service.o readperf.o readlog.o ext_test.o tls.o tls_endpoint.o
CLIENTLOGOBJS=applications.o certificates.o clientversion.o clock.o cpuinfo.o bios.o date.o diskinfo.o domain.o \
	eventlog.o ipconfig.o kbs.o osversion.o processes.o reboots.o registry.o runningservices.o startargs.o tcpconnections.o \
	who.o winmemory.o winports.o winroute.o winuptime.o arena.o utils.o clientlog.o
CLIENTLOGOBJS_32=$(patsubst %,../clientlog/build_x86/%,$(CLIENTLOGOBJS))
CLIENTLOGOBJS_64=$(patsubst %,../clientlog/build_x64/%,$(CLIENTLOGOBJS))
CFG=mrbig.cfg
DISTCFG=mrbig.cfg.dist mrbig.cfg.minicfg
DISTDIR=$(PACKAGE)-$(VERSION)
EXTRA_DIST=minicfg.c minibbd.c
DISTFILES=$(CFG) $(DISTCFG) $(SRCS) $(HDRS) $(DOCS) Makefile $(EXTRA_DIST)
ZIPFILES=$(DISTCFG) $(DOCS)
EXEFILES=X86/mrbig.exe X64/mrbig64.exe
BUILD_DATE=$(shell date +%y%m%d%H%M)
GIT_HASH=$(shell git rev-parse --short HEAD)
GIT_DIRTY=$(shell git diff --quiet || echo -dirty)
BRANCH := $(shell echo $${GITHUB_HEAD_REF:-$${GITHUB_REF_NAME:-$$(git rev-parse --abbrev-ref HEAD)}})


FILEVER_COMMA = $(shell echo $(VERSION) | sed 's/-.*//' | awk -F. '{printf "%s,%s,%s,0", $$1,$$2,$$3}')

# -----------------------------
# Version string logic
# -----------------------------
ifeq ($(DEV),1)
# Dev/Beta: 1.2.3.4-betaYYMMDDHHMM+HASH[-dirty]
	FILEVER_STR := $(VERSION)-dev\ \($(BRANCH)@$(GIT_HASH)$(GIT_DIRTY)\)
	CFLAGS=-Wall -O -g -DDEBUG -ggdb -DPACKAGE=\"$(PACKAGE)\" -DVERSION=\"$(FILEVER_STR)\"
else ifeq ($(PR),1)
# PR
	FILEVER_STR := $(VERSION)-pr\ \($(BRANCH)@$(GIT_HASH)$(GIT_DIRTY)\)
else
# Release: 1.2.3
	FILEVER_STR := $(VERSION)
endif


ifneq ($(strip $(ARCH)),)
ORIG_EXE := mrbig$(ARCH).exe
else
ORIG_EXE := mrbig.exe
endif

all:
	$(MAKE) -C X86 mrbig.exe
	$(MAKE) -C X64 mrbig64.exe
.PHONY: $(VER_RC) $(VER_RES)

$(VER_RC): version.rc.template
	sed -e 's/@COMPANY@/$(COMPANY)/g' \
	    -e 's/@PRODUCT@/$(PRODUCT)/g' \
	    -e 's/@PACKAGE@/$(PACKAGE)/g' \
		-e 's/@FILEVER@/$(FILEVER_STR)/g' \
		-e 's/@FILEVER_COMMA@/$(FILEVER_COMMA)/g' \
		-e 's/@COPYRIGHT@/$(COPYRIGHT)/g' \
		-e 's/@DESCRIPTION@/$(DESCRIPTION)/g' \
		-e 's/@ORIGINALFILENAME@/$(ORIG_EXE)/g' \
		-e 's/@INTERNAL@/$(INTERNAL)/g' \
		-e 's/@COMMENTS@/$(COMMENTS)/g' \
		-e 's/@GIT_HASH@/$(GIT_HASH)/g' \
		-e 's/@GIT_DIRTY@/$(GIT_DIRTY)/g' \
	    $< > $@
# Build the version resource. WINDRES must be set by the arch specific Makefile
# (X86/Makefile or X64/Makefile) so that the correct prefixed windres tool is used.
$(VER_RES): $(VER_RC)
	$(WINDRES) -O coff $(VER_RC) -o $(VER_RES)


mrwmi:
	$(MAKE) -C X86 mrwmi.exe
	$(MAKE) -C X64 mrwmi.exe

mrwmi.exe: $(OBJS) wmi.o disphelper.o
	$(CC) -o mrwmi.exe $(OBJS) wmi.o disphelper.o -lws2_32 -lpsapi -lole32 -loleaut32 -luuid -lcrypt32 -lwevtapi -lpdh -lwtsapi32 -lsecur32 -lncrypt

mrbig.exe: $(OBJS) clientlog.o $(VER_RES)
	@echo "Building mrbig.exe"
	$(CC) -o mrbig.exe $(OBJS) $(CLIENTLOGOBJS_32)  $(VER_RES) -lws2_32 -lpsapi -lole32 -loleaut32 -luuid -liphlpapi -lcrypt32 -lwevtapi -lpdh -lwtsapi32 -lnetapi32 -lsecur32 -lncrypt

mrbig64.exe: $(OBJS) clientlog.o $(VER_RES)
	@echo "Building mrbig64.exe"
	$(CC) -o mrbig64.exe $(OBJS) $(CLIENTLOGOBJS_64)  $(VER_RES) -lws2_32 -lpsapi -lole32 -loleaut32 -luuid -liphlpapi -lcrypt32 -lwevtapi -lpdh -lwtsapi32 -lnetapi32 -lsecur32 -lncrypt

mrbignt.exe: $(NTOBJS)
	$(CC) -o mrbignt.exe $(NTOBJS) -lws2_32 -lpsapi -lsecur32 -lcrypt32 -lncrypt

clientlog.o:
	$(MAKE) -C ../clientlog objectfile PACKAGE="$(PACKAGE)" VERSION="$(FILEVER_STR)"

# evilbbd.exe: evilbbd.c
#	$(CC) $(CFLAGS) -o evilbbd.exe evilbbd.c -lws2_32

minibbd.exe: minibbd.c
	$(CC) $(CFLAGS) -o minibbd.exe minibbd.c -lws2_32

minicfg.exe: minicfg.c
	$(CC) $(CFLAGS) -o minicfg.exe minicfg.c -lws2_32

# version.exe: version.c
#	$(CC) $(CFLAGS) -o version.exe version.c -lws2_32

# mrconnect.exe: mrconnect.c
#	$(CC) $(CFLAGS) -DDEBUG -o mrconnect.exe mrconnect.c -lws2_32

# proclist.exe: proclist.c
#	$(CC) $(CFLAGS) -o proclist.exe proclist.c -lws2_32

# svcscfg.exe: svcscfg.c
#	$(CC) $(CFLAGS) -o svcscfg.exe svcscfg.c -lws2_32

procs.exe: procs.c
	$(CC) -DTESTING $(CFLAGS) -o procs.exe procs.c -lws2_32

# procs2.exe: procs2.c
#	$(CC) $(CFLAGS) -o procs2.exe procs2.c -lws2_32 -lpsapi

# enumproc.exe: enumproc.c readperf.c
#	$(CC) $(CFLAGS) -o $@ enumproc.c readperf.c -lws2_32

# pdhtest.exe: pdhtest.c
#	$(CC) $(CFLAGS) -o $@ pdhtest.c -lpdh

$(OBJS): $(HDRS)

procsnt.o: procs.c
	$(CC) -DMrBigNT $(CFLAGS) -c -o procsnt.o procs.c

stop:
	net stop mrbig

start:
	net start mrbig

clean:
	make -C X86 .clean
	make -C X64 .clean
	make .clean
	make -C clientlog clean

.clean:
	rm -f *.o *.exe *~ *.stackdump *.res *.rc

#zip: $(ZIPFILES)
#	strip mrbig.exe
#	zip $(PACKAGE)-$(VERSION).zip $(ZIPFILES)
#
zip: $(ZIPFILES) all
	zip $(PACKAGE)-$(VERSION).zip $(ZIPFILES) $(EXEFILES)

dist: $(DISTFILES)
	rm -rf $(DISTDIR)
	mkdir $(DISTDIR) $(DISTDIR)/X86 $(DISTDIR)/X64
	cp $(DISTFILES) $(DISTDIR)
	cp X86/Makefile $(DISTDIR)/X86
	cp X64/Makefile $(DISTDIR)/X64
	tar cf $(DISTDIR).tar $(DISTDIR)
	gzip -f $(DISTDIR).tar
	rm -rf $(DISTDIR)

dev:
	# shows build date and short hash in the product version string
	$(MAKE) DEV=1 all

pr: # Only change is the product version string used in the build. This is for building pull requests.
	# Shows branch name and short hash
	$(MAKE) PR=1 all
