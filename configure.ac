dnl Define ourselves
AC_INIT(tcl-nano, 1.3)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_GNU_SOURCE

dnl Monocypher requires C99
if test "$ac_cv_prog_cc_c99" = no; then
	AC_ERROR([C99 compiler required])
fi

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

dnl Enable support for a code coverage build
tcl_nano_coverage='false'
AC_ARG_ENABLE([coverage], AS_HELP_STRING([--enable-coverage], [enable code coverage build (requires debug)]), [
	if test "$enableval" = "yes"; then
		tcl_nano_coverage='true'
		tcl_nano_debug='true'
	fi
])

dnl If we are building a debug release, enable debugging flags
if test "$tcl_nano_debug" = 'true'; then
	AC_DEFINE(TCLEXT_TCL_NANO_DEBUG, [1], [Enable debugging build])
	AX_CHECK_COMPILE_FLAG([-mmpx -fcheck-pointer-bounds], [CFLAGS="$CFLAGS -mmpx -fcheck-pointer-bounds"])
	AX_CHECK_COMPILE_FLAG([-g3], [CFLAGS="$CFLAGS -g3"])
	AX_CHECK_COMPILE_FLAG([-ggdb3], [CFLAGS="$CFLAGS -ggdb3"])
else
	dnl If we are not doing debugging disable some of the more annoying warnings
	AX_CHECK_COMPILE_FLAG([-Wno-unused-value], [CFLAGS="$CFLAGS -Wno-unused-value"])
	AX_CHECK_COMPILE_FLAG([-Wno-unused-parameter], [CFLAGS="$CFLAGS -Wno-unused-parameter"])
	AX_CHECK_COMPILE_FLAG([-Wno-deprecated-declarations], [CFLAGS="$CFLAGS -Wno-deprecated-declarations"])
fi
AX_CHECK_COMPILE_FLAG([-Wno-sign-compare], [CFLAGS="$CFLAGS -Wno-sign-compare"])

dnl If enabled, do code coverage
if test "$tcl_nano_coverage" = 'true'; then
	ENABLE_COVERAGE='true'
	AC_SUBST(ENABLE_COVERAGE)
	AX_CHECK_COMPILE_FLAG([-coverage], [
		CFLAGS="$CFLAGS -coverage"
		LDFLAGS="$LDFLAGS -coverage"
	])
fi

dnl Enable compiler warnings
AX_CHECK_COMPILE_FLAG([-Wall], [CFLAGS="-Wall $CFLAGS"])
AX_CHECK_COMPILE_FLAG([-W], [
	CFLAGS="-W $CFLAGS"
	AX_CHECK_COMPILE_FLAG([-Wno-self-assign], [CFLAGS="$CFLAGS -Wno-self-assign"])
	AX_CHECK_COMPILE_FLAG([-Wno-tautological-constant-out-of-range-compare], [CFLAGS="$CFLAGS -Wno-tautological-constant-out-of-range-compare"])
])

dnl Enable hardening
AX_CHECK_COMPILE_FLAG([-fstack-protector-all], [CFLAGS="$CFLAGS -fstack-protector-all"])
AX_CHECK_COMPILE_FLAG([-fno-strict-overflow], [CFLAGS="$CFLAGS -fno-strict-overflow"])
AC_DEFINE([_FORTIFY_SOURCE], [2], [Enable fortification])

dnl Enable OpenMP, if available
tcl_nano_openmp=''
AX_CHECK_COMPILE_FLAG([-fopenmp], [
	tcl_nano_openmp='-fopenmp'
], [
	AX_CHECK_COMPILE_FLAG([-xopenmp], [
		tcl_nano_openmp='-xopenmp'
	], [
		AX_CHECK_COMPILE_FLAG([-openmp], [
			tcl_nano_openmp='-openmp'
		], [
			AX_CHECK_COMPILE_FLAG([/openmp], [
				tcl_nano_openmp='/openmp'
			])
		])
	])
])

if test -n "${tcl_nano_openmp}"; then
	CFLAGS="$CFLAGS ${tcl_nano_openmp}"

	AC_DEFINE([NANO_TCL_HAVE_OPENMP], [1], [Define if you have support for OpenMP])
fi

dnl Random number generation mechanisms
AC_CHECK_FUNCS(getrandom,, [
	AC_CHECK_FUNCS(getentropy,, [
		AC_CHECK_FUNCS(CryptGenRandom)
	])
])

dnl Check for name resolution capabilities
AC_CHECK_FUNCS(getaddrinfo, [
	AC_CHECK_FUNCS(getnameinfo, [
		AC_CHECK_HEADERS(sys/types.h sys/socket.h netdb.h)
	])
])

dnl Handle specifying where TCLLIB is, for testing
AC_SUBST(TCLLIB_PATH)
TCLLIB_PATH='/dev/null'
AC_ARG_WITH([tcllib-path], AS_HELP_STRING([--with-tcllib-path], [Specify a path to Tcllib for the test suite]), [
	if test "$withval" != "no" -a "$withval" != "yes"; then
		TCLLIB_PATH="${withval}"
	fi
])

dnl Sync the RPATH if requested
if test "$TCLEXT_BUILD" != 'static'; then
	DC_SYNC_RPATH([yes])
fi

dnl Setup a stable ABI
DC_SETUP_STABLE_API([${srcdir}/nano.vers], nano.syms)
if test "$tcl_nano_debug" = 'true'; then
	WEAKENSYMS=':'
	REMOVESYMS=':'
fi

dnl Default to using the amalgamation for static, not using it for shared
if test "$TCLEXT_BUILD" != 'static'; then
	tcl_nano_amalgamation='false'
else
	tcl_nano_amalgamation='true'
fi

AC_ARG_ENABLE([amalgamation], AS_HELP_STRING([--enable-amalgamation], [enable compiling the whole program as a single translation unit (default: disabled for shared, enabled for static)]), [
	if test "$enableval" = 'yes'; then
		tcl_nano_amalgamation='true'
	elif test "$enableval" = 'no'; then
		tcl_nano_amalgamation='false'
	else
		AC_ERROR([Unknown value for --enable-amalgamation])
	fi
])
if test "$tcl_nano_amalgamation" = 'true'; then
	TCL_NANO_AMALGAMATION='1'
else
	TCL_NANO_AMALGAMATION='0'
fi
AC_SUBST(TCL_NANO_AMALGAMATION)

dnl Produce output
AC_OUTPUT(Makefile pkgIndex.tcl-${TCLEXT_BUILD} nano.syms)
