# run some tests on libvex
include $(top_srcdir)/Makefile.tool-tests.am

check_PROGRAMS = multiarch_test
LDADD = \
	../libvexmultiarch-@VGCONF_ARCH_PRI@-@VGCONF_OS@.a \
	../libvex-@VGCONF_ARCH_PRI@-@VGCONF_OS@.a @LIB_UBSAN@
