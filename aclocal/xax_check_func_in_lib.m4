dnl XAX_CHECK_FUNC_IN_LIB(headers..., libraries..., function, [, ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]])
AC_DEFUN([XAX_CHECK_FUNC_IN_LIB], [
	m4_define([CACHE_VARIABLE], [xax_cv_func_]$3[_in])
	AC_CACHE_CHECK([for $3 in $2], CACHE_VARIABLE, [
		save_LIBS="${LIBS}"
		LIBS="${save_LIBS} $2"
		m4_define([HEADERS], [])
		m4_foreach_w([HEADER], [$1], [
			m4_append([HEADERS], [#include <]HEADER[>
])
		])
		AC_LINK_IFELSE([AC_LANG_PROGRAM([HEADERS], [[
			$3;
		]])], [
			CACHE_VARIABLE='yes'
		], [
			CACHE_VARIABLE='no'
		])
		LIBS="${save_LIBS}"
	])
	if test "x$CACHE_VARIABLE" = 'xyes'; then
		LIBS="${LIBS} $2"
		AC_DEFINE(AS_TR_CPP([HAVE_$3]), [1], [Define if we have $3])
		m4_foreach_w([HEADER], [$1], [
			AC_DEFINE(AS_TR_CPP([HAVE_]HEADER), [1], [Define if we have <]HEADER[>])
		])
		m4_default([$4], :)
	else
		m4_default([$5], :)
	fi
])
