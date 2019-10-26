/*
 * log.h: Logging functions header file
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2003  Antti Tapaninen <aet@cc.hut.fi>
 * Copyright (C) 2016-  for the binding: Carsten Blüggel <bluecars@posteo.eu>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/*
Written in the D programming language.
For git maintenance (ensure at least one congruent line with originating C header):
#define _OPENSC_LOG_H

Content covered by this file is SOME of of header C/libopensc/log.h (some #define functions are skipped,
all that defer "instantiating" __FILE__, __MODULE__, __LINE__, __FUNCTION__ aren't usefull in D)
It's functions are NOT ALL exported from "libopensc.[so|dll]" binary, some not in ervery opensc version
*/
// Functions exported from "libopensc.*"
// check this module !

module libopensc.log;

import core.stdc.stdarg;
import std.conv : to;
import libopensc.opensc : sc_context;

version(none) { // the original implementation found somewhere

template ArgStringOf_orig(TS...) {
    static if (TS.length == 0)
        enum ArgStringOf = "";
    else {
        static if (TS.length == 1)
            enum ArgStringOf = TS[0];
        else
            enum ArgStringOf = TS[0] ~ "," ~ ArgStringOf_orig!(TS[1 .. $]);
    }
}

enum log_orig(PS...) = "sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, " ~ ArgStringOf_orig!PS ~ ");";
// must be used like this (back-ticks for first 2 args preserving the " !), all usable/interpretable as C language strings (char*), i.e. may not be D strings except literals!:
// mixin (log!(`"argument_for_function"`, `"argument_for_C_language_format_string"`, "to_be_formated_argument_1", "to_be_formated_argument_2"));
} // version



template ArgStringOf(TS...) {
    static if (TS.length == 0)
        enum ArgStringOf = "";
    else {
        static if (TS.length == 1)
            enum ArgStringOf = "," ~ TS[0];
        else
            enum ArgStringOf = "," ~ TS[0] ~ ArgStringOf!(TS[1 .. $]);
    }
}


// an implementation specialized to work for sc_do_log, not requiring back-ticks in source code
template First2QuotedArgStringOf(TS...) {
    static assert(TS.length >= 2); // at least 2 args (func and format) are required for sc_do_log, more are optional
    static if (TS.length == 2)
        enum string First2QuotedArgStringOf = `,"`~TS[0]~`","`~TS[1]~`"`;
    else
        enum string First2QuotedArgStringOf = `,"`~TS[0]~`","`~TS[1]~`"` ~ ArgStringOf!(TS[2 .. $]);
}

version(NOLOG)
enum log(PS...) = "{}";
else
enum log(PS...) = "sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__" ~ First2QuotedArgStringOf!PS ~ ");";
//                sc_do_log(      card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_card_ctl",
//                    "so_pin (%s), label (%s)", sc_dump_hex(so_pin, so_pin_len), label);

//void sc_do_log(sc_context_t *ctx, int level, const char *file, int line, const char *func, const char *format, ...)



enum log_v(int line, string func, string fmt, Args...) = "sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, " ~ to!string(line) ~ `, "`~func~`", "`~fmt~`"` ~ ArgStringOf!(Args) ~ ");";

enum {
    SC_LOG_DEBUG_VERBOSE_TOOL = 1,  /* tools only: verbose */
    SC_LOG_DEBUG_VERBOSE,           /* helps users */
    SC_LOG_DEBUG_NORMAL,            /* helps developers */
    SC_LOG_DEBUG_RFU1,              /* RFU */
    SC_LOG_DEBUG_SM,                /* secure messaging */
    SC_LOG_DEBUG_ASN1,              /* asn1.c */
    SC_LOG_DEBUG_MATCH,             /* card matching */
}

enum {
    SC_COLOR_FG_RED      =  0x0001,
    SC_COLOR_FG_GREEN    =  0x0002,
    SC_COLOR_FG_YELLOW   =  0x0004,
    SC_COLOR_FG_BLUE     =  0x0008,
    SC_COLOR_FG_MAGENTA  =  0x0010,
    SC_COLOR_FG_CYAN     =  0x0020,
    SC_COLOR_BG_RED      =  0x0100,
    SC_COLOR_BG_GREEN    =  0x0200,
    SC_COLOR_BG_YELLOW   =  0x0400,
    SC_COLOR_BG_BLUE     =  0x0800,
    SC_COLOR_BG_MAGENTA  =  0x1000,
    SC_COLOR_BG_CYAN     =  0x2000,
    SC_COLOR_BOLD        =  0x8080,
}


extern(C) @nogc nothrow /*pure*/ :


void sc_do_log(scope sc_context* ctx, int level, const(char)* file, int line, const(char)* func, const(char)* format, ...) pure @trusted;
version(OPENSC_VERSION_LATEST)
void sc_do_log_color(sc_context* ctx, int level, const(char)* file, int line,
	                 const(char)* func, int color, const(char)* format, ...); // __attribute__ ((format (SC_PRINTF_FORMAT, 7, 8)));
void sc_do_log_noframe(sc_context* ctx, int level, const(char)* format, va_list args);
void _sc_debug(sc_context* ctx, int level, const(char)* format, ...);
void _sc_log(sc_context* ctx, const(char)* format, ...);
version(OPENSC_VERSION_LATEST) {
import core.stdc.stdio : FILE;
int sc_color_fprintf(int colors, sc_context* ctx, FILE * stream, const char * format, ...); // __attribute__ ((format (SC_PRINTF_FORMAT, 4, 5)));
}

/**
 * @brief Log binary data to a sc context
 *
 * @param[in] ctx   Context for logging
 * @param[in] level
 * @param[in] label Label to prepend to the buffer
 * @param[in] data  Binary data
 * @param[in] len   Length of \a data
 */
void sc_debug_hex()(sc_context* ctx, int level, const(char)* label, const(ubyte)* data, size_t len) {
    _sc_debug_hex(ctx, level, __MODULE__, __LINE__, __FUNCTION__, label, data, len);
}

void sc_log_hex()(sc_context* ctx, const(char)* label, const(ubyte)* data, size_t len) {
    sc_debug_hex(ctx, SC_LOG_DEBUG_NORMAL, label, data, len);
}

/**
 * @brief Log binary data
 *
 * @param[in] ctx   Context for logging
 * @param[in] level Debug level
 * @param[in] file  File name to be prepended
 * @param[in] line  Line to be prepended
 * @param[in] func  Function to be prepended
 * @param[in] label label to prepend to the buffer
 * @param[in] data  binary data
 * @param[in] len   length of \a data
 */
void  _sc_debug_hex(sc_context* ctx, int level, const(char)* file, int line, const(char)* func, const(char)* label, const(ubyte)* data, size_t len);

void  sc_hex_dump(const(ubyte)* buf, size_t len, char* out_, size_t outlen);
const(char)* sc_dump_hex(const(ubyte)* in_, size_t count) pure @trusted;

version(PATCH_LIBOPENSC_EXPORTS)
    const(char)* sc_dump_oid(const(sc_object_id)* oid);

/*
#define SC_FUNC_CALLED
#define LOG_FUNC_CALLED

#define SC_FUNC_RETURN
#define LOG_FUNC_RETURN

#define SC_TEST_RET
#define LOG_TEST_RET

#define SC_TEST_GOTO_ERR
#define LOG_TEST_GOTO_ERR
*/
