AC_PREREQ([2.69])
AC_INIT([slirp4netns], [1.1.7], [https://github.com/rootless-containers/slirp4netns/issues])
AC_CONFIG_SRCDIR([main.c])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_RANLIB

AM_INIT_AUTOMAKE([1.11.2 foreign subdir-objects])
AM_PROG_AR

AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/mount.h sys/socket.h sys/timeb.h unistd.h getopt.h])

AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AC_FUNC_ALLOCA
AC_FUNC_STRTOD
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([atexit clock_gettime dup2 getopt_long inet_ntoa memmove memset mkdir regcomp rmdir socket strcasecmp strchr strdup strerror strstr strtol strtoul])

PKG_CHECK_MODULES(GLIB, glib-2.0)
PKG_CHECK_MODULES(SLIRP, slirp >= 4.1.0)
PKG_CHECK_MODULES(LIBCAP, libcap)
PKG_CHECK_MODULES(LIBSECCOMP, libseccomp)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
