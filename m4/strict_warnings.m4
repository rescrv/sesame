# Copyright (c) 2012-2013, Robert Escriva
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of this project nor the names of its contributors may
#       be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# This macro enables many compiler warnings for C++ that generally catch bugs in
# code.  It offers the "--enable-strict-warnings" option which defaults to "no".

AC_DEFUN([STRICT_WARNINGS],
    [WSTRICT_CFLAGS=""
    WSTRICT_CXXFLAGS=""
    WSTRICT_CFLAGS_ONLY=""
    AC_ARG_ENABLE([strict-warnings],
              [AS_HELP_STRING([--enable-strict-warnings], [enable many warnings @<:@default: no@:>@])],
              [strict_warnings=${enableval}], [strict_warnings=no])
    if test x"${strict_warnings}" = xyes; then
        AX_CHECK_COMPILE_FLAG([-pedantic],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -pedantic"],,)
        AX_CHECK_COMPILE_FLAG([-Wabi],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wabi"],,)
        AX_CHECK_COMPILE_FLAG([-Waddress],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Waddress"],,)
        AX_CHECK_COMPILE_FLAG([-Wall],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wall"],,)
        AX_CHECK_COMPILE_FLAG([-Warray-bounds],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Warray-bounds"],,)
        AX_CHECK_COMPILE_FLAG([-Wc++0x-compat],[WSTRICT_CXXFLAGS="${WSTRICT_CXXFLAGS} -Wc++0x-compat"],,)
        AX_CHECK_COMPILE_FLAG([-Wcast-align],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wcast-align"],,)
        AX_CHECK_COMPILE_FLAG([-Wcast-qual],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wcast-qual"],,)
        AX_CHECK_COMPILE_FLAG([-Wchar-subscripts],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wchar-subscripts"],,)
        AX_CHECK_COMPILE_FLAG([-Wclobbered],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wclobbered"],,)
        AX_CHECK_COMPILE_FLAG([-Wcomment],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wcomment"],,)
        #AX_CHECK_COMPILE_FLAG([-Wconversion],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wconversion"],,)
        AX_CHECK_COMPILE_FLAG([-Wctor-dtor-privacy],[WSTRICT_CXXFLAGS="${WSTRICT_CXXFLAGS} -Wctor-dtor-privacy"],,)
        AX_CHECK_COMPILE_FLAG([-Wdisabled-optimization],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wdisabled-optimization"],,)
        AX_CHECK_COMPILE_FLAG([-Weffc++],[WSTRICT_CXXFLAGS="${WSTRICT_CXXFLAGS} -Weffc++"],,)
        AX_CHECK_COMPILE_FLAG([-Wempty-body],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wempty-body"],,)
        AX_CHECK_COMPILE_FLAG([-Wenum-compare],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wenum-compare"],,)
        AX_CHECK_COMPILE_FLAG([-Wextra],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wextra"],,)
        AX_CHECK_COMPILE_FLAG([-Wfloat-equal],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wfloat-equal"],,)
        AX_CHECK_COMPILE_FLAG([-Wformat=2],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wformat=2"],,)
        AX_CHECK_COMPILE_FLAG([-Wformat-nonliteral],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wformat-nonliteral"],,)
        AX_CHECK_COMPILE_FLAG([-Wformat-security],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wformat-security"],,)
        AX_CHECK_COMPILE_FLAG([-Wformat],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wformat"],,)
        AX_CHECK_COMPILE_FLAG([-Wformat-y2k],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wformat-y2k"],,)
        AX_CHECK_COMPILE_FLAG([-Wignored-qualifiers],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wignored-qualifiers"],,)
        AX_CHECK_COMPILE_FLAG([-Wimplicit],[WSTRICT_CFLAGS_ONLY="${WSTRICT_CFLAGS} -Wimplicit"],,)
        AX_CHECK_COMPILE_FLAG([-Winit-self],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Winit-self"],,)
        AX_CHECK_COMPILE_FLAG([-Winline],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Winline"],,)
        AX_CHECK_COMPILE_FLAG([-Wlarger-than=4096],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wlarger-than=4096"],,)
        AX_CHECK_COMPILE_FLAG([-Wlogical-op],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wlogical-op"],,)
        AX_CHECK_COMPILE_FLAG([-Wmain],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wmain"],,)
        AX_CHECK_COMPILE_FLAG([-Wmissing-braces],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wmissing-braces"],,)
        AX_CHECK_COMPILE_FLAG([-Wmissing-field-initializers],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wmissing-field-initializers"],,)
        AX_CHECK_COMPILE_FLAG([-Wmissing-format-attribute],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wmissing-format-attribute"],,)
        AX_CHECK_COMPILE_FLAG([-Wmissing-include-dirs],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wmissing-include-dirs"],,)
        AX_CHECK_COMPILE_FLAG([-Wno-long-long],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wno-long-long"],,)
        AX_CHECK_COMPILE_FLAG([-Wnon-virtual-dtor],[WSTRICT_CXXFLAGS="${WSTRICT_CXXFLAGS} -Wnon-virtual-dtor"],,)
        AX_CHECK_COMPILE_FLAG([-Woverlength-strings],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Woverlength-strings"],,)
        AX_CHECK_COMPILE_FLAG([-Woverloaded-virtual],[WSTRICT_CXXFLAGS="${WSTRICT_CXXFLAGS} -Woverloaded-virtual"],,)
        AX_CHECK_COMPILE_FLAG([-Wpacked-bitfield-compat],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wpacked-bitfield-compat"],,)
        AX_CHECK_COMPILE_FLAG([-Wpacked],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wpacked"],,)
        #AX_CHECK_COMPILE_FLAG([-Wpadded],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wpadded"],,)
        AX_CHECK_COMPILE_FLAG([-Wparentheses],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wparentheses"],,)
        AX_CHECK_COMPILE_FLAG([-Wpointer-arith],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wpointer-arith"],,)
        AX_CHECK_COMPILE_FLAG([-Wredundant-decls],[WSTRICT_CXXFLAGS="${WSTRICT_CXXFLAGS} -Wredundant-decls"],,)
        AX_CHECK_COMPILE_FLAG([-Wreorder],[WSTRICT_CXXFLAGS="${WSTRICT_CXXFLAGS} -Wreorder"],,)
        AX_CHECK_COMPILE_FLAG([-Wreturn-type],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wreturn-type"],,)
        AX_CHECK_COMPILE_FLAG([-Wsequence-point],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wsequence-point"],,)
        AX_CHECK_COMPILE_FLAG([-Wshadow],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wshadow"],,)
        AX_CHECK_COMPILE_FLAG([-Wsign-compare],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wsign-compare"],,)
        #AX_CHECK_COMPILE_FLAG([-Wsign-conversion],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wsign-conversion"],,)
        AX_CHECK_COMPILE_FLAG([-Wsign-promo],[WSTRICT_CXXFLAGS="${WSTRICT_CXXFLAGS} -Wsign-promo"],,)
        AX_CHECK_COMPILE_FLAG([-Wstack-protector],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wstack-protector"],,)
        AX_CHECK_COMPILE_FLAG([-Wstrict-aliasing=3],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wstrict-aliasing=3"],,)
        AX_CHECK_COMPILE_FLAG([-Wstrict-aliasing],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wstrict-aliasing"],,)
        AX_CHECK_COMPILE_FLAG([-Wstrict-null-sentinel],[WSTRICT_CXXFLAGS="${WSTRICT_CXXFLAGS} -Wstrict-null-sentinel"],,)
        #AX_CHECK_COMPILE_FLAG([-Wstrict-overflow=4],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wstrict-overflow=4"],,)
        #AX_CHECK_COMPILE_FLAG([-Wstrict-overflow],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wstrict-overflow"],,)
        AX_CHECK_COMPILE_FLAG([-Wswitch-default],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wswitch-default"],,)
        AX_CHECK_COMPILE_FLAG([-Wswitch-enum],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wswitch-enum"],,)
        AX_CHECK_COMPILE_FLAG([-Wswitch],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wswitch"],,)
        AX_CHECK_COMPILE_FLAG([-Wtrigraphs],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wtrigraphs"],,)
        AX_CHECK_COMPILE_FLAG([-Wtype-limits],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wtype-limits"],,)
        AX_CHECK_COMPILE_FLAG([-Wundef],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wundef"],,)
        AX_CHECK_COMPILE_FLAG([-Wuninitialized],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wuninitialized"],,)
        AX_CHECK_COMPILE_FLAG([-Wunsafe-loop-optimizations],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wunsafe-loop-optimizations"],,)
        AX_CHECK_COMPILE_FLAG([-Wunused-function],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wunused-function"],,)
        AX_CHECK_COMPILE_FLAG([-Wunused-label],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wunused-label"],,)
        AX_CHECK_COMPILE_FLAG([-Wunused-parameter],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wunused-parameter"],,)
        AX_CHECK_COMPILE_FLAG([-Wunused-value],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wunused-value"],,)
        AX_CHECK_COMPILE_FLAG([-Wunused-variable],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wunused-variable"],,)
        AX_CHECK_COMPILE_FLAG([-Wunused],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wunused"],,)
        AX_CHECK_COMPILE_FLAG([-Wvolatile-register-var],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wvolatile-register-var"],,)
        AX_CHECK_COMPILE_FLAG([-Wwrite-strings],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wwrite-strings"],,)
        AX_CHECK_COMPILE_FLAG([-Qunused-arguments],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Qunused-arguments"],,)
        AX_CHECK_COMPILE_FLAG([-Wno-deprecated-declarations],[WSTRICT_CFLAGS="${WSTRICT_CFLAGS} -Wno-deprecated-declarations"],,)
    fi
    WSTRICT_CXXFLAGS="${WSTRICT_CFLAGS} ${WSTRICT_CXXFLAGS}"
    WSTRICT_CFLAGS="${WSTRICT_CFLAGS} ${WSTRICT_CFLAGS_ONLY}"
    AC_SUBST([WSTRICT_CFLAGS], [${WSTRICT_CFLAGS}])
    AC_SUBST([WSTRICT_CXXFLAGS], [${WSTRICT_CXXFLAGS}])
])
