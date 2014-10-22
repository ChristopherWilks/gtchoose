################################################################################
#
# Copyright 2011 Annai Systems, Inc.   All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    1. Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#
#    2. Redistributions in binary form must reproduce the above copyright notice,
#       this list of conditions and the following disclaimer in the documentation
#       and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY ANNAI SYSTEMS ''AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies,
# either expressed or implied, of Annai Systems, Inc.
#
# Created under contract by Cardinal Peak, LLC.   www.cardinalpeak.com
#
################################################################################

GTresourcedir = $(pkgdatadir)
BUILD_NUMBER ?= undefined
BUILD_TYPE ?= undefined
BUILD_TARGET ?= undefined
EXTRA_CXXFLAGS =
EXTRA_CPPFLAGS = -DGT_RESOURCEDIR=\"$(GTresourcedir)\" \
                 -DGT_BUILD_NUMBER=\"$(BUILD_NUMBER)\" \
                 -DGT_BUILD_TYPE=\"$(BUILD_TYPE)\" \
                 -DGT_BUILD_TARGET=\"$(BUILD_TARGET)\"

if DARWIN
EXTRA_CXXFLAGS += -Wno-deprecated-declarations -Wno-parentheses-equality
endif

noinst_HEADERS = \
   gt_scm_rev.h \
   accumulator.hpp \
   geneTorrentUtils.h \
   gtBase.h \
   gtBaseOpts.h \
   gtOptStrings.h \
   gtDefs.h \
   gtDownload.h \
   gtDownloadOpts.h \
   gtLog.h \
   gtServer.h \
   gtServerOpts.h \
   gtUpload.h \
   gtUploadOpts.h \
   gtUtils.h \
   gtNullStorage.h \
   gtZeroStorage.h \
   loggingmask.h \
   stringTokenizer.h

boost_LIBS = $(BOOST_SYSTEM_LIB) \
             $(BOOST_FILESYSTEM_LIB) \
             $(BOOST_REGEX_LIB) \
             $(BOOST_PROGRAM_OPTIONS_LIB)

if SOLARIS
torrentrasterbar_CXXFLAGS:sh =  /usr/bin/pkg-config --cflags ../libtorrent/libtorrent-rasterbar.pc
torrentrasterbar_only_l:sh = /usr/bin/pkg-config --libs-only-l ../libtorrent/libtorrent-rasterbar.pc
else
torrentrasterbar_CXXFLAGS =  $(shell $(PKG_CONFIG) --cflags ../libtorrent/libtorrent-rasterbar.pc)
torrentrasterbar_only_l = $(shell $(PKG_CONFIG) --libs-only-l ../libtorrent/libtorrent-rasterbar.pc)
endif

torrentrasterbar_LIBS = $(torrentrasterbar_only_l) -L../libtorrent/src/.libs

lib_LTLIBRARIES = libgenetorrent.la

libgenetorrent_la_SOURCES = gtBase.cpp \
                            gtBaseOpts.cpp \
                            gtDownload.cpp \
                            gtDownloadOpts.cpp \
                            gtUtils.cpp \
                            gtLog.cpp \
                            gtAlerts.cpp \
                            geneTorrentUtils.cpp \
                            stringTokenizer.cpp \
                            gtNullStorage.cpp \
                            gtZeroStorage.cpp

libgenetorrent_la_CPPFLAGS = $(BOOST_CPPFLAGS) \
                             $(LIBCURL_CPPFLAGS) \
                             $(OPENSSL_INCLUDES) \
                             $(XQILLA_INCLUDES) \
                             $(XERCES_CPPFLAGS) \
                             $(EXTRA_CPPFLAGS)

libgenetorrent_la_CXXFLAGS = $(torrentrasterbar_CXXFLAGS) \
                             -I$(top_srcdir)/libtorrent/include \
                             $(EXTRA_CXXFLAGS)

libgenetorrent_la_LDFLAGS = -version-info 0:0:0 \
                            -shared \
                            -no-undefined \
                            $(torrentrasterbar_LIBS) \
                            -L../libtorrent/src/.libs \
                            $(BOOST_LDFLAGS) \
                            $(OPENSSL_LDFLAGS) \
                            $(XQILLA_LDFLAGS) \
                            $(XERCES_LDFLAGS)

libgenetorrent_la_LIBADD = $(boost_LIBS) \
                           $(PTHREAD_LIBS) \
                           $(LIBCURL) \
                           $(OPENSSL_LIBS) \
                           $(XQILLA_LIBS) \
                           $(XERCES_LIBS)

bin_SCRIPTS = 

bin_PROGRAMS = gtupload \
               gtdownload \
               gtserver

gtupload_SOURCES = gtMain.cpp \
                   gtUpload.cpp \
                   gtUploadOpts.cpp

gtdownload_SOURCES = gtMain.cpp

gtserver_SOURCES = gtMain.cpp \
                   gtServer.cpp \
                   gtServerOpts.cpp

dist_GTresource_DATA = dhparam.pem

common_ldflags     = $(torrentrasterbar_LIBS) \
                      -Wl,-rpath,$(libdir)/GeneTorrent \
                      $(BOOST_LDFLAGS) \
                      $(OPENSSL_LDFLAGS) \
                      $(XQILLA_LDFLAGS) \
                      $(XERCES_LDFLAGS)

common_ldadd      =  $(boost_LIBS) \
                     $(PTHREAD_LIBS) \
                     -lssl \
                     -lcrypto \
                     libgenetorrent.la \
                     $(XQILLA_LIBS) \
                     $(XERCES_LIBS)

gtupload_CPPFLAGS = $(BOOST_CPPFLAGS) \
                    $(OPENSSL_INCLUDES) \
                    $(XQILLA_INCLUDES) \
                    $(XERCES_CPPFLAGS) \
                    $(EXTRA_CPPFLAGS)

gtupload_CXXFLAGS = $(torrentrasterbar_CXXFLAGS) \
                    -I$(top_srcdir)/libtorrent/include \
                    $(EXTRA_CXXFLAGS) \
                    -DGENETORRENT_UPLOAD

gtupload_LDFLAGS = $(common_ldflags)

gtupload_LDADD = $(common_ldadd) \
                 $(LIBCURL)

gtdownload_CPPFLAGS = $(BOOST_CPPFLAGS) \
                      $(OPENSSL_INCLUDES) \
                      $(XQILLA_INCLUDES) \
                      $(XERCES_CPPFLAGS) \
                      $(EXTRA_CPPFLAGS)

gtdownload_CXXFLAGS = $(torrentrasterbar_CXXFLAGS) \
                      -I$(top_srcdir)/libtorrent/include \
                      $(EXTRA_CXXFLAGS) \
                      -DGENETORRENT_DOWNLOAD

gtdownload_LDFLAGS = $(common_ldflags)

gtdownload_LDADD = $(common_ldadd) \
                   $(LIBCURL)

gtserver_CPPFLAGS = $(BOOST_CPPFLAGS) \
                    $(OPENSSL_INCLUDES) \
                    $(XQILLA_INCLUDES) \
                    $(XERCES_CPPFLAGS) \
                    $(EXTRA_CPPFLAGS)

gtserver_CXXFLAGS = $(torrentrasterbar_CXXFLAGS) \
                    -I$(top_srcdir)/libtorrent/include \
                    $(EXTRA_CXXFLAGS) \
                    -DGENETORRENT_SERVER

gtserver_LDFLAGS = $(common_ldflags)

gtserver_LDADD = $(common_ldadd) \
                 $(LIBCURL)

dist_man_MANS = gtdownload.1 \
                gtserver.1 \
                gtupload.1

EXTRA_DIST = man_gtcommon.1 \
             man_gtdownload.1 \
             man_gtserver.1 \
             man_gtupload.1 \
             cacert.pem

CLEANFILES = gtdownload.1 \
             gtserver.1 \
             gtupload.1 \
             gtdownload_manual.txt \
             gtserver_manual.txt \
             gtupload_manual.txt

DISTCLEANFILES = GeneTorrent

gtdownload.1: $(srcdir)/man_gtdownload.1 $(srcdir)/man_gtcommon.1
	cat $^ > $@
if CYGWIN
	MANWIDTH=80 man -P cat ./$@ | col -b | unix2dos > gtdownload_manual.txt
endif

gtserver.1: $(srcdir)/man_gtserver.1 $(srcdir)/man_gtcommon.1
	cat $^ > $@
if CYGWIN
	MANWIDTH=80 man -P cat ./$@ | col -b | unix2dos > gtserver_manual.txt
endif

gtupload.1: $(srcdir)/man_gtupload.1 $(srcdir)/man_gtcommon.1
	cat $^ > $@
if CYGWIN
	MANWIDTH=80 man -P cat ./$@ | col -b | unix2dos > gtupload_manual.txt
endif

GeneTorrent.1: man_GeneTorrent.1
	cat $^ > $@
if CYGWIN
	MANWIDTH=80 man -P cat ./$@ | col -b | unix2dos > GeneTorrent_manual.txt
endif

.PHONY: mkdir_darwin_rpath
mkdir_darwin_rpath:
if DARWIN
	@echo "  MKDIR  $(libdir)/GeneTorrent"
	$(MKDIR_P) $(libdir)/GeneTorrent
endif

all: mkdir_darwin_rpath
