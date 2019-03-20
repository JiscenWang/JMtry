#
# $Id$
#

noinst_LIBRARIES = libgateway.a

bin_PROGRAMS = JMtry 
 
AM_CPPFLAGS = \
	-I${top_srcdir}/libhttpd/ \
	-DSYSCONFDIR='"$(sysconfdir)"' \
	-Wall \
	-Wextra \
	-Wno-unused-parameter
JMtry_LDADD = libgateway.a $(top_builddir)/libhttpd/libhttpd.la

JMtry_SOURCES = main.c

libgateway_a_SOURCES = jconfig.c \
	debug.c \
	jgateway.c \
	jhttp.c \
	client_list.c \
	util.c \
	ping_thread.c \
	safe.c \
	simple_http.c \
	pstring.c \
	wd_util.c \
	jdhcp.c \
	jmodule.c \
	jnet.c

noinst_HEADERS = common.h \
	jconfig.h \
	debug.h \
	jgateway.h \
	jhttp.h \
	client_list.h \
	util.h \
	ping_thread.h \
	safe.h \
	simple_http.h \
	pstring.h \
	wd_util.h \
	jdhcp.h \
	jmodule.h \
	jnet.h

wdctl_LDADD = libgateway.a
