
AC_DEFUN([CUSTOM_M4_SETUP],
[
  YARA_INC="-I$YARA_HOME/libyara/include"
  YARA_LIB="$YARA_HOME/.libs/libyara.a"

  dnl Update the compiler/linker flags to add yara to the build path
  CFLAGS="$CFLAGS $YARA_INC"
  CXXFLAGS="$CXXFLAGS $YARA_INC"
  LDFLAGS="$LDFLAGS $YARA_LIB"
  AC_SUBST(CFLAGS)
  AC_SUBST(CXXFLAGS)
  AC_SUBST(LDFLAGS)
])
