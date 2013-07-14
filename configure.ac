dnl Process this file with autoconf to produce a configure script.
AC_INIT(hawkc C library for Hawk authentication scheme, 0.1.00, algermissen@acm.org, hawk)
AC_PREREQ(2.50)
AC_CONFIG_SRCDIR(hawkc/parser.c)
AC_CONFIG_SRCDIR(hawk/hawk.c)
AC_CONFIG_HEADER(hawkc/config.h)

dnl Checks for programs.
AC_PROG_CC

dnl Checks for libraries.

AC_CHECK_LIB(m, ceil)
dnl 
dnl Configure libcrypto (part of OpenSSL).
dnl 
have_libcrypto="1"
AC_CHECK_HEADERS([openssl/evp.h], , [have_libcrypto="0"])
AC_CHECK_LIB([crypto], [OpenSSL_add_all_ciphers], , [have_libcrypto="0"])
if test "x${have_libcrypto}" = "x0" ; then
  AC_MSG_ERROR([Cannot build without libcrypto (OpenSSL)])
fi

#dnl Checks for header files.
#AC_HEADER_STDC

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

dnl Checks for library functions.
AC_FUNC_MEMCMP
AC_FUNC_VPRINTF
AC_CHECK_FUNCS(snprintf vsnprintf bzero)

AC_TRY_RUN([main() { char buf[10]; unsigned int n; n = snprintf(buf,10,"%s","1234567890"); if(n == 10) return (0); return (1);}],
             worked=yes, worked=no, worked=no)
if test $worked = yes; then
  echo "have C99 snprintf"
else
  echo "we need C99 snprintf" 
  exit 1
fi

AC_OUTPUT([Makefile])


