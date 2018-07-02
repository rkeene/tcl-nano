dnl Define ourselves
AC_INIT(tcl-nano, 0)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_GNU_SOURCE

dnl Determine system information
DC_CHK_OS_INFO

dnl Look for appropriate headers
AC_CHECK_HEADERS(stdint.h limits.h unistd.h stdlib.h string.h sys/stat.h sys/types.h fcntl.h sys/random.h)

dnl Perform Tcl Extension required stuff
TCLEXT_INIT

if test "$TCLEXT_BUILD" != 'static'; then
	dnl Determine how to make shared objects
	DC_GET_SHOBJFLAGS

	EXTENSION_TARGET="nano.${SHOBJEXT}"
else
	AC_CHECK_TOOL([AR], [ar], [false])
	AC_CHECK_TOOL([RANLIB], [ranlib], [:])

	EXTENSION_TARGET="nano.${AREXT}"
fi
AC_SUBST(EXTENSION_TARGET)
AC_SUBST(TCLEXT_BUILD)

dnl Enable support for a debugging build
tcl_nano_debug='false'
AC_ARG_ENABLE([debug], AS_HELP_STRING([--enable-debug], [enable debugging parameters]), [
	if test "$enableval" = "yes"; then
		tcl_nano_debug='true'
	fi
])
if test "$tcl_nano_debug" = 'true'; then
	AC_DEFINE(TCLEXT_TCL_NANO_DEBUG, [1], [Enable debugging build])
	AX_CHECK_COMPILE_FLAG([-fcheck-pointer-bounds], [CFLAGS="$CFLAGS -fcheck-pointer-bounds"])
	AX_CHECK_COMPILE_FLAG([-g3], [CFLAGS="$CFLAGS -g3"])
	AX_CHECK_COMPILE_FLAG([-ggdb3], [CFLAGS="$CFLAGS -ggdb3"])
else
	dnl If we are not doing debugging disable some of the more annoying warnings
	AX_CHECK_COMPILE_FLAG([-Wno-unused-value], [CFLAGS="$CFLAGS -Wno-unused-value"])
	AX_CHECK_COMPILE_FLAG([-Wno-unused-parameter], [CFLAGS="$CFLAGS -Wno-unused-parameter"])
	AX_CHECK_COMPILE_FLAG([-Wno-deprecated-declarations], [CFLAGS="$CFLAGS -Wno-deprecated-declarations"])
fi
AX_CHECK_COMPILE_FLAG([-Wno-sign-compare], [CFLAGS="$CFLAGS -Wno-sign-compare"])

dnl Enable compiler warnings
AX_CHECK_COMPILE_FLAG([-Wall], [CFLAGS="-Wall $CFLAGS"])
AX_CHECK_COMPILE_FLAG([-W], [
	CFLAGS="-W $CFLAGS"
	AX_CHECK_COMPILE_FLAG([-Wno-self-assign], [CFLAGS="$CFLAGS -Wno-self-assign"])
])

dnl Enable hardening
AX_CHECK_COMPILE_FLAG([-fstack-protector-all], [CFLAGS="$CFLAGS -fstack-protector-all"])
AX_CHECK_COMPILE_FLAG([-fno-strict-overflow], [CFLAGS="$CFLAGS -fno-strict-overflow"])
AC_DEFINE([_FORTIFY_SOURCE], [2], [Enable fortification])

dnl Sync the RPATH if requested
if test "$TCLEXT_BUILD" != 'static'; then
	if test "$TCLEXT_TLS_STATIC_SSL" = 'yes'; then
		DC_SYNC_RPATH([no])
	else
		DC_SYNC_RPATH([yes])
	fi
fi

dnl Setup a stable ABI
DC_SETUP_STABLE_API([${srcdir}/nano.vers], nano.syms)
if test "$tcl_nano_debug" = 'true'; then
	WEAKENSYMS=':'
	REMOVESYMS=':'
fi

dnl Produce output
AC_OUTPUT(Makefile pkgIndex.tcl nano.syms)
