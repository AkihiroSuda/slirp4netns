bin_PROGRAMS = slirp4netns

AM_CFLAGS = -I $(abs_top_srcdir)/rd235_libslirp/include -I$(abs_top_srcdir)/rd235_libslirp/src -I$(abs_top_srcdir)/qemu/include -I$(abs_top_srcdir)/qemu/slirp -I$(abs_top_srcdir)/parson

noinst_LIBRARIES = libqemu_slirp.a libslirp.a libparson.a

AM_TESTS_ENVIRONMENT = PATH="$(abs_top_builddir):$(PATH)"
TESTS = tests/test-slirp4netns.sh tests/test-slirp4netns-configure.sh tests/test-slirp4netns-exit-fd.sh tests/test-slirp4netns-ready-fd.sh tests/test-slirp4netns-api-socket.sh 

EXTRA_DIST = \
	slirp4netns.1.md \
	slirp4netns.1 \
	$(TESTS) \
	tests/common.sh \
	slirp4netns.h \
	qemu/include/qemu/queue.h \
	qemu/slirp/slirp.h \
	qemu/slirp/tcp_var.h \
	qemu/slirp/ip6.h \
	qemu/slirp/bootp.h \
	qemu/slirp/tcp.h \
	qemu/slirp/ip_icmp.h \
	qemu/slirp/main.h \
	qemu/slirp/udp.h \
	qemu/slirp/tcp_timer.h \
	qemu/slirp/socket.h \
	qemu/slirp/sbuf.h \
	qemu/slirp/slirp_config.h \
	qemu/slirp/misc.h \
	qemu/slirp/if.h \
	qemu/slirp/dhcpv6.h \
	qemu/slirp/mbuf.h \
	qemu/slirp/debug.h \
	qemu/slirp/libslirp.h \
	qemu/slirp/ip.h \
	qemu/slirp/ip6_icmp.h \
	qemu/slirp/tcpip.h \
	rd235_libslirp/include/qemu/osdep.h \
	rd235_libslirp/src/qemu2libslirp.h \
	parson/parson.h

libqemu_slirp_a_SOURCES = \
			qemu/slirp/arp_table.c \
			qemu/slirp/bootp.c \
			qemu/slirp/cksum.c \
			qemu/slirp/dhcpv6.c \
			qemu/slirp/dnssearch.c \
			qemu/slirp/if.c \
			qemu/slirp/ip6_icmp.c \
			qemu/slirp/ip6_input.c \
			qemu/slirp/ip6_output.c \
			qemu/slirp/ip_icmp.c \
			qemu/slirp/ip_input.c \
			qemu/slirp/ip_output.c \
			qemu/slirp/mbuf.c \
			qemu/slirp/misc.c \
			qemu/slirp/ndp_table.c \
			qemu/slirp/sbuf.c \
			qemu/slirp/slirp.c \
			qemu/slirp/socket.c \
			qemu/slirp/tcp_input.c \
			qemu/slirp/tcp_output.c \
			qemu/slirp/tcp_subr.c \
			qemu/slirp/tcp_timer.c \
			qemu/slirp/udp6.c \
			qemu/slirp/udp.c

libslirp_a_SOURCES = rd235_libslirp/src/qemu2libslirp.c

libparson_a_SOURCES = parson/parson.c

slirp4netns_SOURCES = main.c slirp4netns.c
slirp4netns_LDADD = libslirp.a libqemu_slirp.a libparson.a
man1_MANS = slirp4netns.1

generate-man:
	go-md2man -in slirp4netns.1.md -out slirp4netns.1

CLANGTIDY = clang-tidy -warnings-as-errors='*'

lint:
	$(CLANGTIDY) $(slirp4netns_SOURCES) -- $(AM_CFLAGS)

lint-full:
	$(CLANGTIDY) $(slirp4netns_SOURCES) $(libqemu_slirp_a_SOURCES) $(libparson_a_SOURCES) -- $(AM_CFLAGS)

indent:
# indent(1): "You must use the ‘-T’ option to tell indent the name of all the typenames in your program that are defined by typedef."
	indent -linux -l120 -T ssize_t -T pid_t -T SLIRP -T JSON_Object -T JSON_Value $(slirp4netns_SOURCES)
	$(RM) *.c~

benchmark:
	benchmarks/benchmark-iperf3.sh
	benchmarks/benchmark-iperf3-reverse.sh

ci:
	$(MAKE) indent
	test -z "$(git diff)"
	$(MAKE) lint
	$(MAKE) -j $(shell nproc) distcheck
	PATH=$(shell pwd):$$PATH $(MAKE) benchmark MTU=1500
	PATH=$(shell pwd):$$PATH $(MAKE) benchmark MTU=65520

.PHONY: generate-man lint lint-full indent benchmark ci
