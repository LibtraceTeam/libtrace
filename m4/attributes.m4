dnl Macros for checking if various gcc compiler attributes are present
dnl
dnl Written by Shane Alcock <salcock@waikato.ac.nz>, but some credit
dnl should be given to Diego Pettenò <flameeyes@gmail.com> whose 
dnl macros were very useful in helping me figure out how to write my
dnl own.
dnl
dnl

AC_DEFUN([check_WERROR], 
[
  AC_REQUIRE([AC_PROG_CC])
  AC_CACHE_CHECK(
    [if -Werror flag is supported by compiler],
    [lt_cv_werror_flag],
    [saved="$CFLAGS"
     CFLAGS="$CFLAGS -Werror"
     AC_COMPILE_IFELSE([AC_LANG_SOURCE([int a;])],
       [eval lt_cv_werror_flag='yes'],
       [eval lt_cv_werror_flag='no'])
     CFLAGS="$saved"

    ])
])  

AC_DEFUN([gcc_PACKED],
[
  AC_REQUIRE([check_WERROR])
  HAVE_ATTRIBUTE_PACKED=0
  if test -n "$CC"; then
    AS_IF([eval test x$lt_cv_werror_flag = xyes], [errflag=-Werror], [])
    AC_CACHE_CHECK([if compiler supports __attribute__((packed))],
      [lt_cv_attribute_packed], 
      [saved="$CFLAGS"
       CFLAGS="$CFLAGS $errflag"
       AC_COMPILE_IFELSE([AC_LANG_SOURCE(
         [struct s { char a; char b; int val; long val2; void *ptr;} __attribute__((packed));])],
         [lt_cv_attribute_packed=yes],
         [lt_cv_attribute_packed=no]
       )
       CFLAGS="$saved"
      ])
    if test x$lt_cv_attribute_packed = xyes; then
      HAVE_ATTRIBUTE_PACKED=1
    fi
  fi
  AC_SUBST([HAVE_ATTRIBUTE_PACKED])
  AC_DEFINE_UNQUOTED([HAVE_ATTRIBUTE_PACKED], [$HAVE_ATTRIBUTE_PACKED],
    [Define to 1 or 0, depending on whether the compiler supports the gcc packed attribute.])
])

AC_DEFUN([gcc_UNUSED],
[
  AC_REQUIRE([check_WERROR])
  HAVE_ATTRIBUTE_UNUSED=0
  if test -n "$CC"; then
    AS_IF([eval test x$lt_cv_werror_flag = xyes], [errflag=-Werror], [])
    AC_CACHE_CHECK([if compiler supports __attribute__((unused))],
      [lt_cv_attribute_unused], 
      [saved="$CFLAGS"
       CFLAGS="$CFLAGS $errflag"
       AC_COMPILE_IFELSE([AC_LANG_SOURCE(
         [void func(int a, __attribute__((unused)) int b);])],
         [lt_cv_attribute_unused=yes],
         [lt_cv_attribute_unused=no]
       )
       CFLAGS="$saved"
      ])
    if test x$lt_cv_attribute_unused = xyes; then
      HAVE_ATTRIBUTE_UNUSED=1
    fi
  fi
  AC_SUBST([HAVE_ATTRIBUTE_UNUSED])
  AC_DEFINE_UNQUOTED([HAVE_ATTRIBUTE_UNUSED], [$HAVE_ATTRIBUTE_UNUSED],
    [Define to 1 or 0, depending on whether the compiler supports the gcc unused attribute.])
])

AC_DEFUN([gcc_DEPRECATED],
[
  AC_REQUIRE([check_WERROR])
  HAVE_ATTRIBUTE_DEPRECATED=0
  if test -n "$CC"; then
    AS_IF([eval test x$lt_cv_werror_flag = xyes], [errflag=-Werror], [])
    AC_CACHE_CHECK([if compiler supports __attribute__((deprecated))],
      [lt_cv_attribute_deprecated], 
      [saved="$CFLAGS"
       CFLAGS="$CFLAGS $errflag"
       AC_COMPILE_IFELSE([AC_LANG_SOURCE(
         [void func(int a, int b) __attribute__((deprecated));])],
         [lt_cv_attribute_deprecated=yes],
         [lt_cv_attribute_deprecated=no]
       )
       CFLAGS="$saved"
      ])
    if test x$lt_cv_attribute_deprecated = xyes; then
      HAVE_ATTRIBUTE_DEPRECATED=1
    fi
  fi
  AC_SUBST([HAVE_ATTRIBUTE_DEPRECATED])
  AC_DEFINE_UNQUOTED([HAVE_ATTRIBUTE_DEPRECATED], [$HAVE_ATTRIBUTE_DEPRECATED],
    [Define to 1 or 0, depending on whether the compiler supports the gcc deprecated attribute.])
])

AC_DEFUN([gcc_FORMAT],
[
  AC_REQUIRE([check_WERROR])
  HAVE_ATTRIBUTE_FORMAT=0
  if test -n "$CC"; then
    AS_IF([eval test x$lt_cv_werror_flag = xyes], [errflag=-Werror], [])
    AC_CACHE_CHECK([if compiler supports __attribute__((format(printf)))],
      [lt_cv_attribute_format], 
      [saved="$CFLAGS"
       CFLAGS="$CFLAGS $errflag"
       AC_COMPILE_IFELSE([AC_LANG_SOURCE(
         [void __attribute__((format(printf, 1, 2))) foo(const char *fmt, ...);])],
         [lt_cv_attribute_format=yes],
         [lt_cv_attribute_format=no]
       )
       CFLAGS="$saved"
      ])
    if test x$lt_cv_attribute_format = xyes; then
      HAVE_ATTRIBUTE_FORMAT=1
    fi
  fi
  AC_SUBST([HAVE_ATTRIBUTE_FORMAT])
  AC_DEFINE_UNQUOTED([HAVE_ATTRIBUTE_FORMAT], [$HAVE_ATTRIBUTE_FORMAT],
    [Define to 1 or 0, depending on whether the compiler supports the format(printf) attribute.])
])

AC_DEFUN([gcc_PURE],
[
  AC_REQUIRE([check_WERROR])
  HAVE_ATTRIBUTE_PURE=0
  if test -n "$CC"; then
    AS_IF([eval test x$lt_cv_werror_flag = xyes], [errflag=-Werror], [])
    AC_CACHE_CHECK([if compiler supports __attribute__((pure))],
      [lt_cv_attribute_pure], 
      [saved="$CFLAGS"
       CFLAGS="$CFLAGS $errflag"
       AC_COMPILE_IFELSE([AC_LANG_SOURCE(
         [void func(int a, int b) __attribute__((pure));])],
         [lt_cv_attribute_pure=yes],
         [lt_cv_attribute_pure=no]
       )
       CFLAGS="$saved"
      ])
    if test x$lt_cv_attribute_pure = xyes; then
      HAVE_ATTRIBUTE_PURE=1
    fi
  fi
  AC_SUBST([HAVE_ATTRIBUTE_PURE])
  AC_DEFINE_UNQUOTED([HAVE_ATTRIBUTE_PURE], [$HAVE_ATTRIBUTE_PURE],
    [Define to 1 or 0, depending on whether the compiler supports the pure attribute.])
])


