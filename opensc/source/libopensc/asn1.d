/*
 * asn1.h: ASN.1 header file
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
/*
Written in the D programming language.
For git maintenance (ensure at least one congruent line with originating C header):
#define _OPENSC_ASN1_H

Content covered by this file is ALL of header C/libopensc/asn1.h
ALL extern(C) functions are exported from "libopensc.so|opensc.dll" binary, except those controlled by PATCH_LIBOPENSC_EXPORTS
*/

module libopensc.asn1;

import libopensc.opensc;
import libopensc.types;

struct sc_asn1_entry {
	const(char)*  name;
	uint          type;
	uint          tag;
	uint          flags;
	void*         parm;
	void*         arg;
}

/* //used internally by C code only
import libopensc.pkcs15;

struct sc_asn1_pkcs15_object {
	sc_pkcs15_object*  p15_obj;
	sc_asn1_entry*     asn1_class_attr;
	sc_asn1_entry*     asn1_subclass_attr;
	sc_asn1_entry*     asn1_type_attr;
}

struct sc_asn1_pkcs15_algorithm_info {
	int           id;
	sc_object_id  oid;
	extern(C) int  function(sc_context*, void**, const(ubyte)*, size_t, int)  decode;
	extern(C) int  function(sc_context*, void*, ubyte**, size_t*, int)        encode;
	extern(C) void function(void*) free;
}
*/

extern(C) nothrow @nogc
{
	/* Utility functions */
	void sc_format_asn1_entry(sc_asn1_entry* entry, void* parm, void* arg, int set_present);
	void sc_copy_asn1_entry(const(sc_asn1_entry)* src, sc_asn1_entry* dest);

	/* DER tag and length parsing */
	int sc_asn1_decode       (sc_context* ctx, sc_asn1_entry* asn1, const(ubyte)* in_, size_t len, const(ubyte)** newp, size_t* left);
	int sc_asn1_decode_choice(sc_context* ctx, sc_asn1_entry* asn1, const(ubyte)* in_, size_t len, const(ubyte)** newp, size_t* left);
	int sc_asn1_encode       (sc_context* ctx, const(sc_asn1_entry)* asn1, ubyte** buf, size_t* bufsize);
	int _sc_asn1_decode      (sc_context*, sc_asn1_entry*, const(ubyte)*, size_t, const(ubyte)**, size_t*, int, int);
	int _sc_asn1_encode      (sc_context*, const(sc_asn1_entry)*, ubyte**, size_t*, int);

	int sc_asn1_read_tag(const(ubyte)** buf, size_t buflen, uint* cla_out, uint* tag_out, size_t* taglen);
	const(ubyte)* sc_asn1_find_tag  (sc_context* ctx, const(ubyte)*  buf, size_t  buflen, uint tag, size_t* taglen);
	const(ubyte)* sc_asn1_verify_tag(sc_context* ctx, const(ubyte)*  buf, size_t  buflen, uint tag, size_t* taglen);
	const(ubyte)* sc_asn1_skip_tag  (sc_context* ctx, const(ubyte)** buf, size_t* buflen, uint tag, size_t* taglen);

	/* DER encoding */

	/* Argument 'ptr' is set to the location of the next possible ASN.1 object.
	 * If NULL, no action on 'ptr' is performed.
	 * If out is NULL or outlen is zero, the length that would be written is returned.
	 * If data is NULL, the data field will not be written. This is helpful for constructed structures. */
	int sc_asn1_put_tag(uint tag, const(ubyte)* data, size_t datalen, ubyte* out_, size_t outlen, ubyte** ptr);


	/* ASN.1 printing functions */
	void sc_asn1_print_tags(const(ubyte)* buf, size_t buflen);

	/* ASN.1 object decoding functions */
version(PATCH_LIBOPENSC_EXPORTS)
	int sc_asn1_utf8string_to_ascii(const(ubyte)* buf, size_t buflen, ubyte* outbuf, size_t outlen);

	int sc_asn1_decode_bit_string(const(ubyte)* inbuf, size_t inlen, void* outbuf, size_t outlen, const int strict);
	/* non-inverting version */
	int sc_asn1_decode_bit_string_ni(const(ubyte)* inbuf, size_t inlen, void* outbuf, size_t outlen, const int strict);
	int sc_asn1_decode_integer(const(ubyte)* inbuf, size_t inlen, int* out_, int strict);
	int sc_asn1_decode_object_id(const(ubyte)* inbuf, size_t inlen, sc_object_id* id);
	int sc_asn1_encode_object_id(ubyte** buf, size_t* buflen, const(sc_object_id)* id);

	/* algorithm encoding/decoding */
	int sc_asn1_decode_algorithm_id(sc_context*, const(ubyte)*, size_t, sc_algorithm_id*, int);
	int sc_asn1_encode_algorithm_id(sc_context*, ubyte**, size_t*, const(sc_algorithm_id)*, int);
	void sc_asn1_clear_algorithm_id(sc_algorithm_id*);

	/* ASN.1 object encoding functions */
	int sc_asn1_write_element(sc_context* ctx, uint tag, const(ubyte)* data, size_t datalen, ubyte** out_, size_t* outlen);

	int sc_asn1_sig_value_rs_to_sequence(sc_context* ctx, ubyte* in_, size_t inlen, ubyte** buf, size_t* buflen);
	int sc_asn1_sig_value_sequence_to_rs(sc_context* ctx, const(ubyte)* in_, size_t inlen, ubyte* buf, size_t buflen);

	/* ECDSA signature decoding*/
	int sc_asn1_decode_ecdsa_signature(sc_context* ctx, const(ubyte)* data, size_t datalen,
		size_t fieldsize, ubyte** out_, size_t outlen);

enum : uint {
		/* long form tags use these */
		/* Same as  SC_ASN1_TAG_* shifted left by 24 bits  */
		SC_ASN1_CLASS_MASK      = 0xC000_0000,
		SC_ASN1_UNI             = 0x0000_0000, /* Universal */
		SC_ASN1_APP             = 0x4000_0000, /* Application */
		SC_ASN1_CTX             = 0x8000_0000, /* Context */
		SC_ASN1_PRV             = 0xC000_0000, /* Private */
		SC_ASN1_CONS            = 0x2000_0000,

		SC_ASN1_CLASS_CONS      = 0xE000_0000, /* CLASS and CONS */
		SC_ASN1_TAG_MASK        = 0x00FF_FFFF,
		SC_ASN1_TAGNUM_SIZE     = 3,

		SC_ASN1_PRESENT         = 0x0000_0001,
		SC_ASN1_OPTIONAL        = 0x0000_0002,
		SC_ASN1_ALLOC           = 0x0000_0004,
		SC_ASN1_UNSIGNED        = 0x0000_0008,
		SC_ASN1_EMPTY_ALLOWED   = 0x0000_0010,
	}

	enum {
		SC_ASN1_BOOLEAN         = 1,
		SC_ASN1_INTEGER         = 2,
		SC_ASN1_BIT_STRING      = 3,
		SC_ASN1_BIT_STRING_NI   = 128,
		SC_ASN1_OCTET_STRING    = 4,
		SC_ASN1_NULL            = 5,
		SC_ASN1_OBJECT          = 6,
		SC_ASN1_ENUMERATED      = 10,
		SC_ASN1_UTF8STRING      = 12,
		SC_ASN1_SEQUENCE        = 16,
		SC_ASN1_SET             = 17,
		SC_ASN1_PRINTABLESTRING = 19,
		SC_ASN1_UTCTIME         = 23,
		SC_ASN1_GENERALIZEDTIME = 24,

		/* internal structures */
		SC_ASN1_STRUCT          = 129,
		SC_ASN1_CHOICE          = 130,
		SC_ASN1_BIT_FIELD       = 131,	/* bit string as integer */

		/* 'complex' structures */
		SC_ASN1_PATH            = 256,
		SC_ASN1_PKCS15_ID       = 257,
		SC_ASN1_PKCS15_OBJECT   = 258,
		SC_ASN1_ALGORITHM_ID    = 259,
		SC_ASN1_SE_INFO         = 260,

		/* use callback function */
		SC_ASN1_CALLBACK        = 384,
	}

	/* use with short one byte tags */
	enum : ubyte {
		SC_ASN1_TAG_CLASS             = 0xC0,
		SC_ASN1_TAG_UNIVERSAL         = 0x00,
		SC_ASN1_TAG_APPLICATION       = 0x40,
		SC_ASN1_TAG_CONTEXT           = 0x80,
		SC_ASN1_TAG_PRIVATE           = 0xC0,

		SC_ASN1_TAG_CONSTRUCTED       = 0x20,
		SC_ASN1_TAG_PRIMITIVE         = 0x1F,
		SC_ASN1_TAG_CLASS_CONS        = 0xE0,

		SC_ASN1_TAG_EOC               = 0,
		SC_ASN1_TAG_BOOLEAN           = 1,
		SC_ASN1_TAG_INTEGER           = 2,
		SC_ASN1_TAG_BIT_STRING        = 3,
		SC_ASN1_TAG_OCTET_STRING      = 4,
		SC_ASN1_TAG_NULL              = 5,
		SC_ASN1_TAG_OBJECT            = 6,
		SC_ASN1_TAG_OBJECT_DESCRIPTOR = 7,
		SC_ASN1_TAG_EXTERNAL          = 8,
		SC_ASN1_TAG_REAL              = 9,
		SC_ASN1_TAG_ENUMERATED        = 10,
		SC_ASN1_TAG_UTF8STRING        = 12,
		SC_ASN1_TAG_SEQUENCE          = 16,
		SC_ASN1_TAG_SET               = 17,
		SC_ASN1_TAG_NUMERICSTRING     = 18,
		SC_ASN1_TAG_PRINTABLESTRING   = 19,
		SC_ASN1_TAG_T61STRING         = 20,
		SC_ASN1_TAG_TELETEXSTRING     = 20,
		SC_ASN1_TAG_VIDEOTEXSTRING    = 21,
		SC_ASN1_TAG_IA5STRING         = 22,
		SC_ASN1_TAG_UTCTIME           = 23,
		SC_ASN1_TAG_GENERALIZEDTIME   = 24,
		SC_ASN1_TAG_GRAPHICSTRING     = 25,
		SC_ASN1_TAG_ISO64STRING       = 26,
		SC_ASN1_TAG_VISIBLESTRING     = 26,
		SC_ASN1_TAG_GENERALSTRING     = 27,
		SC_ASN1_TAG_UNIVERSALSTRING   = 28,
		SC_ASN1_TAG_BMPSTRING         = 30,
		SC_ASN1_TAG_ESCAPE_MARKER     = 31,
	}
}
