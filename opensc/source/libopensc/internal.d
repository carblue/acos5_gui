/*
 * internal.h: Internal definitions for libopensc
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 *               2005        The OpenSC project
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
#define _SC_INTERNAL_H

Content covered by this file is SOME of of header C/libopensc/internal.h (funcctions exported neither from 0.16.0 nor 0.15.0 are skipped)
It's functions are NOT ALL exported from "libopensc.[so|dll]" binary, some not in ervery opensc version
*/


module libopensc.internal;

/* selective imports are public by default in spite of supposedly being private
TODO check, if this answer from 2010 is still true:
http://stackoverflow.com/questions/3518840/in-d-whats-the-difference-between-a-private-import-and-a-normal-import
*/
import core.stdc.config; // : c_ulong;
version(ENABLE_TOSTRING) {
	import std.format;
	import std.string; // : toStringz, fromStringz;
	import std.algorithm.searching; // : canFind;

	import mixin_templates_opensc;
}

import libopensc.opensc; // : sc_context, sc_card, sc_card_driver;
import libopensc.types; // : sc_atr;
import scconf.scconf; // : scconf_block;

enum SC_FILE_MAGIC = 0x1442_6950;

struct sc_atr_table {
	/* The atr fields are required to
	 * be in aa:bb:cc hex format. */
	const(char)*   atr;
	/* The atrmask is logically AND'd with an
	 * card atr prior to comparison with the
	 * atr reference value above. */
	const(char)*   atrmask;
	const(char)*   name;
	int            type;
	c_ulong        flags;
	/* Reference to card_atr configuration block,
	 * available to user configured card entries. */
	scconf_block*  card_atr;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = [
			"atr",
			"atrmask",
			"name",
			"card_atr",
		];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
/+
				string name_member = typeof(this).tupleof[i].stringof;
				string unqual_type = typeof(member).stringof[6..$-1];
				string value_rep = format("%s", member);
				bool isDereferencable = (unqual_type[$-1]=='*' && unqual_type[0..$-1]!="void") && value_rep!="null";
				sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
				if (isDereferencable)
					sink("0x");
				sink.formatValue(member, fmt);
+/
				mixin(head_foreach_Pointer);
//				sink(";  ");
//				sink(isDereferencable ? "YES": "NO");
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
					if      (name_member=="atr")
						sink(format(`  "%s"`, fromStringz(atr)));
					else if (name_member=="atrmask")
						sink(format(`  "%s"`, fromStringz(atrmask)));
					else if (name_member=="name")
						sink(format(`  "%s"`, fromStringz(name)));
					else if (name_member=="card_atr")
						sink.formatValue(*card_atr, fmt);
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception t) { /* todo: handle exception */ }
	} // void toString
} // struct sc_atr_table

//pragma(msg, "sc_atr_table.sizeof, sc_atr_table.alignof ", sc_atr_table.sizeof, " ", sc_atr_table.alignof); // sc_atr_table.sizeof, sc_atr_table.alignof 48LU 8LU

uint BYTES4BITS()(uint num) { return (num + 7) / 8; }    /* number of bytes necessary to hold 'num' bits */


extern(C) @nogc nothrow :


/* Returns an scconf_block entry with matching ATR/ATRmask to the ATR specified,
 * NULL otherwise. Additionally, if card driver is not specified, search through
 * all card drivers user configured ATRs. */
scconf_block* _sc_match_atr_block(sc_context* ctx, sc_card_driver* driver, sc_atr* atr);


	/* Returns an index number if a match was found, -1 otherwise. table has to
	 * be null terminated. */
	int _sc_match_atr(sc_card* card, const(sc_atr_table)* table, int* type_out) pure @trusted;  // const since v0.19.0 : const struct sc_atr_table *table

	int _sc_card_add_rsa_alg(sc_card* card, uint key_length, c_ulong flags, c_ulong exponent);
	int _sc_card_add_ec_alg(sc_card* card, uint key_length, c_ulong flags, c_ulong ext_flags, sc_object_id* curve_oid);
version(PATCH_LIBOPENSC_EXPORTS) {
	int _sc_card_add_algorithm(sc_card* card, const(sc_algorithm_info)* info);                     // duplicated for acos5_64 : missingExport_sc_card_add_algorithm
	int _sc_card_add_symmetric_alg(sc_card* card, uint algorithm, uint key_length, c_ulong flags); // duplicated for acos5_64 : missingExport_sc_card_add_symmetric_alg

	/********************************************************************/
	/*                 pkcs1 padding/encoding functions                 */
	/********************************************************************/

	int sc_pkcs1_strip_01_padding(sc_context* ctx, const(ubyte)* in_dat, size_t in_len,        // duplicated for acos5_64 : missingExport_sc_pkcs1_strip_01_padding
		ubyte* out_dat, size_t* out_len);
	int sc_pkcs1_strip_02_padding(sc_context* ctx, const(ubyte)* in_dat, size_t in_len,        // duplicated for acos5_64 : missingExport_sc_pkcs1_strip_02_padding
		ubyte* out_dat, size_t* out_len);
	int sc_pkcs1_strip_digest_info_prefix(uint* algorithm,
		const(ubyte)* in_dat, size_t in_len, ubyte* out_dat, size_t* out_len);
}

/**
 * PKCS1 encodes the given data.
 * @param  ctx     IN  sc_context_t object
 * @param  flags   IN  the algorithm to use
 * @param  in      IN  input buffer
 * @param  inlen   IN  length of the input
 * @param  out     OUT output buffer (in == out is allowed)
 * @param  outlen  OUT length of the output buffer
 * @param  mod_bits IN  length of the modulus in bits (version v0.19.0: modlen in bytes)
 * @return SC_SUCCESS on success and an error code otherwise
 */
int sc_pkcs1_encode(sc_context* ctx, c_ulong flags,
	const(ubyte)* in_, size_t inlen, ubyte* out_, size_t* outlen, size_t mod_bits/*modlen*/); // since version 0.20.0: modlen renamed to mod_bits: is length of the modulus in bits; before (modlen) it was in bytes !
