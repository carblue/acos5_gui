/*
 * opensc.h: OpenSC library header file
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 *               2005        The OpenSC project
 *               2016-  for the binding: Carsten Blüggel <bluecars@posteo.eu>
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

/**
 * @file src/libopensc/opensc.h
 * OpenSC library core header file
 */
/*
Written in the D programming language.
For git maintenance (ensure at least one congruent line with originating C header):
#define _OPENSC_H

Content covered by this file is ALL of header C/libopensc/opensc.h
ALL extern(C) functions are exported from "libopensc.so|opensc.dll" binary, except those controlled by PATCH_LIBOPENSC_EXPORTS
*/

// Functions exported from "libopensc.*"

module libopensc.opensc;


import core.stdc.stdio : FILE;
import core.stdc.config : c_ulong;
version(ENABLE_TOSTRING) {
	import std.string : fromStringz;
	import std.format;
	import std.algorithm.comparison : clamp;
	import std.algorithm.searching : canFind;

	import mixin_templates_opensc;
}

import common.simclist : list_t;
import scconf.scconf;
import libopensc.internal;
import libopensc.errors;
import libopensc.types;
import libopensc.sm;

//#if defined(_WIN32) && !(defined(__MINGW32__) && defined (__MINGW_PRINTF_FORMAT))
version(Win32) {
	version(MinGW) {
		enum const(char)* SC_FORMAT_LEN_SIZE_T    = "z";
		enum const(char)* SC_FORMAT_LEN_PTRDIFF_T = "t";
	}
	else {
		enum const(char)* SC_FORMAT_LEN_SIZE_T    = "I";
		enum const(char)* SC_FORMAT_LEN_PTRDIFF_T = "I";
	}
}
else
{
	/* hope SUSv3 ones work */
	enum const(char)* SC_FORMAT_LEN_SIZE_T    = "z";
	enum const(char)* SC_FORMAT_LEN_PTRDIFF_T = "t";
}


enum /*SC_SEC_OPERATION*/ {
	SC_SEC_OPERATION_DECIPHER      = 0x0001,
	SC_SEC_OPERATION_SIGN          = 0x0002,
	SC_SEC_OPERATION_AUTHENTICATE  = 0x0003,
	SC_SEC_OPERATION_DERIVE        = 0x0004,
	SC_SEC_OPERATION_WRAP          = 0x0005,
	SC_SEC_OPERATION_UNWRAP        = 0x0006,
	SC_SEC_OPERATION_ENCRYPT_SYM   = 0x0007,
	SC_SEC_OPERATION_DECRYPT_SYM   = 0x0008,
}
//	mixin FreeEnumMembers!SC_SEC_OPERATION;


/* sc_security_env flags */
enum {
	SC_SEC_ENV_ALG_REF_PRESENT     = 0x0001,
	SC_SEC_ENV_FILE_REF_PRESENT    = 0x0002,
	SC_SEC_ENV_KEY_REF_PRESENT     = 0x0004,
	SC_SEC_ENV_KEY_REF_SYMMETRIC   = 0x0008,
	SC_SEC_ENV_ALG_PRESENT         = 0x0010,
	SC_SEC_ENV_TARGET_FILE_REF_PRESENT= 0x0020,
}

/* sc_security_env additional parameters */
enum {
	SC_SEC_ENV_MAX_PARAMS        = 10,
	SC_SEC_ENV_PARAM_IV          = 1,
	SC_SEC_ENV_PARAM_TARGET_FILE = 2,
}

/* PK algorithms */
//enum /* SC_ALGORITHM */ : uint {
enum uint SC_ALGORITHM_RSA                = 0;
enum uint SC_ALGORITHM_DSA                = 1;
enum uint SC_ALGORITHM_EC                 = 2;
enum uint SC_ALGORITHM_GOSTR3410          = 3;

	/* Symmetric algorithms */
enum uint SC_ALGORITHM_DES                = 64;
enum uint SC_ALGORITHM_3DES               = 65;
enum uint SC_ALGORITHM_GOST               = 66;
enum uint SC_ALGORITHM_AES                = 67;
enum uint SC_ALGORITHM_UNDEFINED          = 68; /* used with CKK_GENERIC_SECRET type keys */

	/* Hash algorithms */
enum uint SC_ALGORITHM_MD5                = 128;
enum uint SC_ALGORITHM_SHA1               = 129;
enum uint SC_ALGORITHM_GOSTR3411          = 130;

	/* Key derivation algorithms */
enum uint SC_ALGORITHM_PBKDF2             = 192;

	/* Key encryption algorithms */
enum uint SC_ALGORITHM_PBES2              = 256;

enum uint SC_ALGORITHM_ONBOARD_KEY_GEN    = 0x8000_0000;  // ?         #define CKM_RSA_PKCS_KEY_PAIR_GEN 0x00000000
	/* need usage = either sign or decrypt. keys with both? decrypt, emulate sign */
enum uint SC_ALGORITHM_NEED_USAGE         = 0x4000_0000; /* does this mean, that it's up to opensc, whether for signing RSA raw (decipher) is called instead of compute_signature? acos keys may be configured unable to decipher !*/

enum uint SC_ALGORITHM_SPECIFIC_FLAGS     = 0x001F_FFFF;

/* If the card is willing to produce a cryptogram padded with the following
 * methods, set these flags accordingly.  These flags are exclusive: an RSA card
 * must support at least one of them, and exactly one of them must be selected
 * for a given operation. */
enum uint SC_ALGORITHM_RSA_RAW            = 0x0000_0001;  // RSA-X-509 #define CKM_RSA_X_509 0x00000003
	/*
	 * If the card is willing to produce a cryptogram (after padding by card/driver, not by opensc) padded with the following
	 * methods, set these flags accordingly.

	 * https://github.com/NWilson/OpenSC/commit/42f3199 (NWilson@42f3199), refering also to SC_ALGORITHM_RSA_RAW:
	 * These flags are exclusive: an RSA card
	 * must support at least one of them, and exactly one of them must be selected
	 * for a given operation.)
	 */
version(OPENSC_VERSION_LATEST) {
	enum uint SC_ALGORITHM_RSA_PADS     = 0x0000_003F;  /* NWilson@42f3199: = 0x0004_000F, */
	enum uint SC_ALGORITHM_RSA_PAD_OAEP = 0x0000_0020;  /* PKCS#1 v2.0 OAEP */
}
else {
	enum uint SC_ALGORITHM_RSA_PADS     = 0x0000_001F;  /* NWilson@42f3199: = 0x0004_000F, */
}


enum uint SC_ALGORITHM_RSA_PAD_NONE       = 0x0000_0001;  // NWilson@42f3199: = SC_ALGORITHM_RSA_RAW, /* alias for RAW */
enum uint SC_ALGORITHM_RSA_PAD_PKCS1      = 0x0000_0002;  /* PKCS#1 v1.5 padding */ // RSA-PKCS  #define CKM_RSA_PKCS  0x00000001
enum uint SC_ALGORITHM_RSA_PAD_ANSI       = 0x0000_0004;
enum uint SC_ALGORITHM_RSA_PAD_ISO9796    = 0x0000_0008;  //           #define CKM_RSA_9796 0x00000002
enum uint SC_ALGORITHM_RSA_PAD_PSS        = 0x0000_0010;  // since v0.19.0
//enum uint SC_ALGORITHM_RSA_PAD_PSS_MGF1   = 0x0004_0000   /* PKCS#1 v2.0 PSS */ this is from NWilson@42f3199

	/*
	 * If the card is willing to produce a cryptogram (from following hashed input; the card is not supposed to hash itself) with the following
	 * hash values, set these flags accordingly.

	 * NWilson@42f3199: The interpretation of the hash
	 * flags depends on the algorithm and padding chosen: for RSA, the hash flags
	 * determine how the padding is constructed and do not describe the first
	 * hash applied to the document before padding begins.
	 *
	 *   - For PAD_NONE, ANSI X9.31, (and ISO9796?), the hash value is therefore
	 *     ignored.  For ANSI X9.31, the input data must already have the hash
	 *     identifier byte appended (eg 0x33 for SHA-1).
	 *   - For PKCS1 (v1.5) the hash is recorded in the padding, and HASH_NONE is a
	 *     valid value, meaning that the hash's DigestInfo has already been
	 *     prepended to the data, otherwise the hash id is put on the front.
	 *   - For PSS (PKCS#1 v2.0) the hash is used to derive the padding from the
	 *     already-hashed message.
	 *
	 * In no case is the hash actually applied to the entire document.
	 *
	 * It's possible that the card may support different hashes for PKCS1 and PSS
	 * signatures; in this case the card driver has to pick the lowest-denominator
	 * when it sets these flags to indicate its capabilities.
	 */
enum uint SC_ALGORITHM_RSA_HASH_NONE      = 0x0000_0100; /* only applies to PKCS1 padding */
enum uint SC_ALGORITHM_RSA_HASH_SHA1      = 0x0000_0200;
enum uint SC_ALGORITHM_RSA_HASH_MD5       = 0x0000_0400;
enum uint SC_ALGORITHM_RSA_HASH_MD5_SHA1  = 0x0000_0800;
enum uint SC_ALGORITHM_RSA_HASH_RIPEMD160 = 0x0000_1000;
enum uint SC_ALGORITHM_RSA_HASH_SHA256    = 0x0000_2000;
enum uint SC_ALGORITHM_RSA_HASH_SHA384    = 0x0000_4000;
enum uint SC_ALGORITHM_RSA_HASH_SHA512    = 0x0000_8000;
enum uint SC_ALGORITHM_RSA_HASH_SHA224    = 0x0001_0000;
enum uint SC_ALGORITHM_RSA_HASHES         = 0x0001_FF00;  /* NWilson@42f3199: = 0x0000_1FF0, */

/* This defines the hashes to be used with MGF1 in PSS padding */
enum uint SC_ALGORITHM_MGF1_SHA1      = 0x0010_0000;
enum uint SC_ALGORITHM_MGF1_SHA256    = 0x0020_0000;
enum uint SC_ALGORITHM_MGF1_SHA384    = 0x0040_0000;
enum uint SC_ALGORITHM_MGF1_SHA512    = 0x0080_0000;
enum uint SC_ALGORITHM_MGF1_SHA224    = 0x0100_0000;
enum uint SC_ALGORITHM_MGF1_HASHES    = 0x01F0_0000;

	/*
	 * NWilson@42f3199:
	 * These flags are exclusive: a GOST R34.10 card must support at least one or the
	 * other of the methods, and exactly one of them applies to any given operation.
	 * Note that the GOST R34.11 hash is actually applied to the data (ie if this
	 * algorithm is chosen the entire unhashed document is passed in).
	 */
enum uint SC_ALGORITHM_GOSTR3410_RAW            = 0x0002_0000;
enum uint SC_ALGORITHM_GOSTR3410_HASH_NONE      = SC_ALGORITHM_GOSTR3410_RAW /*XXX*/;  /* NWilson@42f3199: = SC_ALGORITHM_GOSTR3410_RAW, */
enum uint SC_ALGORITHM_GOSTR3410_HASH_GOSTR3411 = 0x0008_0000;
enum uint SC_ALGORITHM_GOSTR3410_HASHES         = 0x000A_0000;  /* NWilson@42f3199: = 0x0000_A000, */
	/*TODO: -DEE Should the above be 0x0000E000 */
	/* Or should the HASH_NONE be 0x00000010  and HASHES be 0x00008010 */

	/* May need more bits if card can do more hashes */
	/* TODO: -DEE Will overload RSA_HASHES with EC_HASHES */
	/* Not clear if these need their own bits or not */
	/* The PIV card does not support any hashes */

	/*
	 * NWilson@42f3199, deleteing the preceding part of the comment:
	 * The ECDSA flags are exclusive, and exactly one of them applies to any given
	 * operation.  If ECDSA with a hash is specified, then the data passed in is
	 * the entire document, unhashed, and the hash is applied once to it before
	 * truncating and signing.  These flags are distinct from the RSA hash flags,
	 * which determine the hash ids the card is willing to put in RSA message
	 * padding.
	 */
enum uint SC_ALGORITHM_ECDH_CDH_RAW       = 0x0020_0000;
enum uint SC_ALGORITHM_ECDSA_RAW          = 0x0010_0000;
enum uint SC_ALGORITHM_ECDSA_HASH_NONE    = SC_ALGORITHM_RSA_HASH_NONE;     /*  NWilson@42f3199: = SC_ALGORITHM_ECDSA_RAW, */
enum uint SC_ALGORITHM_ECDSA_HASH_SHA1    = SC_ALGORITHM_RSA_HASH_SHA1;     /*  NWilson@42f3199: = 0x0004_0000, */
enum uint SC_ALGORITHM_ECDSA_HASH_SHA224  = SC_ALGORITHM_RSA_HASH_SHA224;   /*  NWilson@42f3199: = 0x0008_0000, */
enum uint SC_ALGORITHM_ECDSA_HASH_SHA256  = SC_ALGORITHM_RSA_HASH_SHA256;   /*  NWilson@42f3199: = 0x0010_0000, */
enum uint SC_ALGORITHM_ECDSA_HASH_SHA384  = SC_ALGORITHM_RSA_HASH_SHA384;   /*  NWilson@42f3199: = 0x0020_0000, */
enum uint SC_ALGORITHM_ECDSA_HASH_SHA512  = SC_ALGORITHM_RSA_HASH_SHA512;   /*  NWilson@42f3199: = 0x0040_0000, */
enum uint SC_ALGORITHM_ECDSA_HASHES       = SC_ALGORITHM_ECDSA_HASH_SHA1 |  /*  NWilson@42f3199: = 0x007D_0000, */
											SC_ALGORITHM_ECDSA_HASH_SHA224 |
											SC_ALGORITHM_ECDSA_HASH_SHA256 |
											SC_ALGORITHM_ECDSA_HASH_SHA384 |
											SC_ALGORITHM_ECDSA_HASH_SHA512;

/* define mask of all algorithms that can do raw */
enum uint SC_ALGORITHM_RAW_MASK =	SC_ALGORITHM_RSA_RAW |
									SC_ALGORITHM_GOSTR3410_RAW |
									SC_ALGORITHM_ECDH_CDH_RAW |
									SC_ALGORITHM_ECDSA_RAW;

/* extended algorithm bits for selected mechs */
enum uint SC_ALGORITHM_EXT_EC_F_P          = 0x0000_0001;
enum uint SC_ALGORITHM_EXT_EC_F_2M         = 0x0000_0002;
enum uint SC_ALGORITHM_EXT_EC_ECPARAMETERS = 0x0000_0004;
enum uint SC_ALGORITHM_EXT_EC_NAMEDCURVE   = 0x0000_0008;
enum uint SC_ALGORITHM_EXT_EC_UNCOMPRESES  = 0x0000_0010;
enum uint SC_ALGORITHM_EXT_EC_COMPRESS     = 0x0000_0020;
//}

/* symmetric algorithm flags. More algorithms to be added when implemented. */
enum : uint {
    SC_ALGORITHM_AES_ECB      = 0x0100_0000,
    SC_ALGORITHM_AES_CBC      = 0x0200_0000,
    SC_ALGORITHM_AES_CBC_PAD  = 0x0400_0000,
    SC_ALGORITHM_AES_FLAGS    = 0x0F00_0000,
}
/* Event masks for sc_wait_for_event() */
enum {
	SC_EVENT_CARD_INSERTED   = 0x0001,
	SC_EVENT_CARD_REMOVED    = 0x0002,
	SC_EVENT_CARD_EVENTS     = SC_EVENT_CARD_INSERTED | SC_EVENT_CARD_REMOVED,
	SC_EVENT_READER_ATTACHED = 0x0004,
	SC_EVENT_READER_DETACHED = 0x0008,
	SC_EVENT_READER_EVENTS   = SC_EVENT_READER_ATTACHED | SC_EVENT_READER_DETACHED,
}

enum MAX_FILE_SIZE = 65535;

struct sc_supported_algo_info {
	uint          reference;
	uint          mechanism;
version(OPENSC_VERSION_LATEST)
	sc_object_id  parameters; /* OID for ECC */
else
	sc_object_id* parameters; /* OID for ECC, NULL for RSA */
	uint          operations;
	sc_object_id  algo_id;
	uint          algo_ref;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{
/+
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				string name_member = typeof(this).tupleof[i].stringof;
				string unqual_type = typeof(member).stringof[6..$-1];
				sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
				sink.formatValue(member, fmt);
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
+/
		mixin(frame_noPointer_noArray_noUnion);
	} // void toString
} // struct sc_supported_algo_info

struct sc_sec_env_param {
	uint   param_type;
	void*  value;
	uint   value_len;
} // sc_sec_env_param_t;

struct sc_security_env {
	c_ulong   flags;            /* e.g. SC_SEC_ENV_KEY_REF_SYMMETRIC, ... */
	int       operation;        /* SC_SEC_OPERATION */
	uint      algorithm;        /* if used, set flag SC_SEC_ENV_ALG_PRESENT */
	uint      algorithm_flags;  /* e.g. SC_ALGORITHM_RSA_RAW */

	uint      algorithm_ref;    /* if used, set flag SC_SEC_ENV_ALG_REF_PRESENT */
	sc_path   file_ref;         /* if used, set flag SC_SEC_ENV_FILE_REF_PRESENT */
	ubyte[8]  key_ref;          /* if used, set flag SC_SEC_ENV_KEY_REF_PRESENT */
	size_t    key_ref_len;
	sc_path   target_file_ref;  /* target key file in unwrap operation */

	sc_supported_algo_info[SC_MAX_SUPPORTED_ALGORITHMS]  supported_algos;
	/* optional parameters */
	sc_sec_env_param[SC_SEC_ENV_MAX_PARAMS]  params;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				string name_member = typeof(this).tupleof[i].stringof;
				string unqual_type = typeof(member).stringof[6..$-1];
				sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
				if (name_member=="key_ref")
					sink(format("  [%(%#x, %)]", key_ref[0..clamp(key_ref_len,0,8)]));
				else if (name_member=="supported_algos") {
					sink("  temporarily omitted");
/* exclude temporarily
					sink("  [");
					foreach (ref sub_member; supported_algos) {
						sink.formatValue(sub_member, fmt);
						sink(", ");
					}
					sink("]");
*/
				}
				else
					sink.formatValue(member, fmt);
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
	} // void toString
} // struct sc_security_env
//	alias sc_security_env_t = sc_security_env;

struct sc_algorithm_id {
	uint          algorithm;
	sc_object_id  oid;
	void*         params;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{
/+
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				string name_member = typeof(this).tupleof[i].stringof;
				string unqual_type = typeof(member).stringof[6..$-1];
				sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
				sink.formatValue(member, fmt);
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
+/
		mixin(frame_noPointer_noArray_noUnion);
	} // void toString
}

struct sc_pbkdf2_params {
	ubyte[16]        salt;
	size_t           salt_len;
	int              iterations;
	size_t           key_length;
	sc_algorithm_id  hash_alg;
}

struct sc_pbes2_params {
	sc_algorithm_id  derivation_alg;
	sc_algorithm_id  key_encr_alg;

version(none)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{ mixin(frame_noPointer_noArray_noUnion); }
}

/*
 * The ecParameters can be presented as
 * - name of curve;
 * - OID of named curve;
 * - implicit parameters.
 *
 * type - type(choice) of 'EC domain parameters' as it present in CKA_EC_PARAMS (PKCS#11).
          Recommended value '1' -- namedCurve.
 * field_length - EC key size in bits.
 */
struct sc_ec_parameters {
	char*         named_curve;
	sc_object_id  id;
	sc_lv_data    der;

	int           type;
	size_t        field_length;
}

struct sc_algorithm_info {
	uint       algorithm;
	uint       key_length;
	uint       flags;

	union anonymous {
		struct sc_rsa_info {
			c_ulong  exponent;

version(ENABLE_TOSTRING)
			void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
			{
				try {
					sink("\n{\n");
					foreach (i, ref member; this.tupleof) {
						string name_member = typeof(this).tupleof[i].stringof;
						string unqual_type = typeof(member).stringof[6..$-1];
						sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
						sink.formatValue(member, fmt);
						sink("\n");
					}
					sink("}\n");
				}
				catch (Exception e) { /* todo: handle exception */ }
			} // void toString
		} // struct sc_rsa_info
		sc_rsa_info  _rsa;

		struct sc_ec_info {
			uint              ext_flags;
			sc_ec_parameters  params;
		}
		sc_ec_info   _ec;

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					if (name_member=="_ec") {}
					else {
						string unqual_type = typeof(member).stringof[6..$-1];
						sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
						sink.formatValue(member, fmt);
						sink("\n");
					}
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
		} // void toString
	} // union anonymous
	anonymous  u;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				string name_member = typeof(this).tupleof[i].stringof;
				string unqual_type = typeof(member).stringof[6..$-1]; // peel off const(payload) to get payload
				sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
				if (name_member=="flags")
					sink(format("  0x%08x", flags));
				else
					sink.formatValue(member, fmt);
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
	} // void toString
} // struct sc_algorithm_info
//	alias sc_algorithm_info_t = sc_algorithm_info;

struct sc_app_info {
	char*    label;
	sc_aid   aid;
	sc_ddo   ddo;
	sc_path  path;
	int      rec_nr;   /* -1, if EF(DIR) is transparent */

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{
		string[] pointersOfInterest = ["label"];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				string name_member = typeof(this).tupleof[i].stringof;
				string unqual_type = typeof(member).stringof[6..$-1];
				sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
				sink.formatValue(member, fmt);
				string value_rep = format("%s", member);
				bool isDereferencable = (unqual_type[$-1]=='*' && unqual_type[0..$-1]!="void") && value_rep!="null";
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
					if (name_member=="label")
						sink(format(`  "%s"`, fromStringz(label)));
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
	} // void toString
} // struct sc_app_info
//	alias sc_app_info_t = sc_app_info;

struct sc_ef_atr {
	ubyte         card_service;
	ubyte         df_selection;
	size_t        unit_size;
	ubyte         card_capabilities;
	size_t        max_command_apdu;
	size_t        max_response_apdu;

	sc_aid        aid;

	ubyte[6]      pre_issuing;
	size_t        pre_issuing_len;

	ubyte[16]     issuer_data;
	size_t        issuer_data_len;

	sc_object_id  allocation_oid;

	uint          status;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				string name_member = typeof(this).tupleof[i].stringof;
				string unqual_type = typeof(member).stringof[6..$-1];
				sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
				if (name_member=="pre_issuing" || name_member=="issuer_data")
					sink(format("  [%(%#x, %)]", member));
				else
					sink.formatValue(member, fmt);
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
	} // void toString
} // struct sc_ef_atr

struct sc_card_cache {
	sc_path   current_path;
	sc_file*  current_ef;
	sc_file*  current_df;
	int       valid;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{
		string[] pointersOfInterest = [
			"current_ef",
			"current_df",
		];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				string name_member = typeof(this).tupleof[i].stringof;
				string unqual_type = typeof(member).stringof[6..$-1]; // peel off const(payload) to get payload
				sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
				sink.formatValue(member, fmt);
				string value_rep = format("%s", member);
				bool isDereferencable = (unqual_type[$-1]=='*' && unqual_type[0..$-1]!="void") && value_rep!="null";
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
					if (name_member=="current_ef")
						sink.formatValue(*current_ef, fmt);
					else if (name_member=="current_df")
						sink.formatValue(*current_df, fmt);
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
	} // void toString
} // struct sc_card_cache

enum {
	SC_PROTO_T0  = 0x0000_0001,
	SC_PROTO_T1  = 0x0000_0002,
	SC_PROTO_RAW = 0x0000_1000,
	SC_PROTO_ANY = 0xFFFF_FFFF,
}

struct sc_reader_driver {
	const(char)*           name;
	const(char)*           short_name;
	sc_reader_operations*  ops;

	void*                  dll;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{
		string[] pointersOfInterest = [
			"name",
			"short_name",
			"ops",
//			"dll",
		];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				string name_member = typeof(this).tupleof[i].stringof;
				string unqual_type = typeof(member).stringof[6..$-1]; // peel off const(payload) to get payload
				sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
				sink.formatValue(member, fmt);
				string value_rep = format("%s", member);
				bool isDereferencable = (unqual_type[$-1]=='*' && unqual_type[0..$-1]!="void") && value_rep!="null";
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
					if (name_member=="name")
						sink(format(`  "%s"`, fromStringz(name)));
					else if (name_member=="short_name")
						sink(format(`  "%s"`, fromStringz(short_name)));
					else if (name_member=="ops")
						sink.formatValue(*ops, fmt);
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
	} // void toString
} // struct sc_reader_driver

enum {
	/* reader flags */
	SC_READER_CARD_PRESENT      = 0x0000_0001,
	SC_READER_CARD_CHANGED      = 0x0000_0002,
	SC_READER_CARD_INUSE        = 0x0000_0004,
	SC_READER_CARD_EXCLUSIVE    = 0x0000_0008,
	SC_READER_HAS_WAITING_AREA  = 0x0000_0010,
	SC_READER_REMOVED           = 0x0000_0020,
	SC_READER_ENABLE_ESCAPE     = 0x0000_0040,
}

enum {
	/* reader capabilities */
	SC_READER_CAP_DISPLAY               = 0x0000_0001,
	SC_READER_CAP_PIN_PAD               = 0x0000_0002,
	SC_READER_CAP_PACE_EID              = 0x0000_0004,
	SC_READER_CAP_PACE_ESIGN            = 0x0000_0008,
	SC_READER_CAP_PACE_DESTROY_CHANNEL  = 0x0000_00010,
	SC_READER_CAP_PACE_GENERIC          = 0x0000_00020,
}

/* reader send/receive length of short APDU */
enum SC_READER_SHORT_APDU_MAX_SEND_SIZE = 255;
enum SC_READER_SHORT_APDU_MAX_RECV_SIZE = 256;

struct sc_reader {
	sc_context*                   ctx;
	const(sc_reader_driver)*      driver;
	const(sc_reader_operations)*  ops;
	void*                         drv_data;
	char*                         name;
	char*                         vendor;
	ubyte                         version_major;
	ubyte                         version_minor;
	c_ulong                       flags;
	c_ulong                       capabilities;
	uint                          supported_protocols;
	uint                          active_protocol;
	size_t                        max_send_size; /* Max Lc supported by the reader layer */
	size_t                        max_recv_size; /* Mac Le supported by the reader layer */
	sc_atr                        atr;
	sc_uid                        uid;

	struct _atr_info {
		ubyte*  hist_bytes;
		size_t  hist_bytes_len;
		int     Fi;
		int     f;
		int     Di;
		int     N;
		ubyte   FI;
		ubyte   DI;

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
			string[] pointersOfInterest = ["hist_bytes"];
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1];
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
					sink.formatValue(member, fmt);
					string value_rep = format("%s", member);
					bool isDereferencable = (unqual_type[$-1]=='*' && unqual_type[0..$-1]!="void") && value_rep!="null";
					if (isDereferencable && canFind(pointersOfInterest, name_member)) {
						if (name_member=="hist_bytes")
							sink(format("  [%(%#x, %)]", hist_bytes[0..clamp(hist_bytes_len,0,SC_MAX_ATR_SIZE)]));
					}
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
		}
	} // struct _atr_info
	_atr_info                     atr_info;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{
		string[] pointersOfInterest = [
//			"ctx",
//			"driver",
//			"ops",
//			"drv_data",
			"name",
			"vendor",
		];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				string name_member = typeof(this).tupleof[i].stringof;
				string unqual_type = typeof(member).stringof[6..$-1]; // peel off const(payload) to get payload
				sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
				sink.formatValue(member, fmt);
				string value_rep = format("%s", member);
				bool isDereferencable = (unqual_type[$-1]=='*' && unqual_type[0..$-1]!="void") && value_rep!="null";
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
					if (name_member=="ctx")
						sink.formatValue(*ctx, fmt);
					else if (name_member=="driver")
						sink.formatValue(*driver, fmt);
					else if (name_member=="ops")
						sink.formatValue(*ops, fmt);
					else if (name_member=="name")
						sink(format(`  "%s"`, fromStringz(name)));
					if (name_member=="vendor")
						sink(format(`  "%s"`, fromStringz(vendor)));
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
	} // void toString
} //  // struct sc_reader
//	alias sc_reader_t = sc_reader;

/* This will be the new interface for handling PIN commands.
 * It is supposed to support pin pads (with or without display)
 * attached to the reader.
 */
enum SC_PIN_CMD : uint {
	SC_PIN_CMD_VERIFY          = 0,
	SC_PIN_CMD_CHANGE          = 1,
	SC_PIN_CMD_UNBLOCK         = 2,
	SC_PIN_CMD_GET_INFO        = 3,
	SC_PIN_CMD_GET_SESSION_PIN = 4,
}
mixin FreeEnumMembers!SC_PIN_CMD;

enum : uint /* SC_PIN_CMD_DATA_FLAGS */ {
	SC_PIN_CMD_USE_PINPAD      = 0x0001,
	SC_PIN_CMD_NEED_PADDING    = 0x0002,
	SC_PIN_CMD_IMPLICIT_CHANGE = 0x0004,
}

enum /* SC_PIN_ENCODING */ {
	SC_PIN_ENCODING_ASCII = 0,
	SC_PIN_ENCODING_BCD   = 1,
	SC_PIN_ENCODING_GLP   = 2, /* Global Platform - Card Specification v2.0.1 */
}

/** Values for sc_pin_cmd_pin.logged_in */
enum /* SC_PIN_STATE */ {
	SC_PIN_STATE_UNKNOWN     = -1,
	SC_PIN_STATE_LOGGED_OUT  =  0,
	SC_PIN_STATE_LOGGED_IN   =  1,
}

/* A card driver receives the sc_pin_cmd_data and sc_pin_cmd_pin structures filled in by the
 * caller, with the exception of the fields returned by the driver for SC_PIN_CMD_GET_INFO.
 * It may use and update any of the fields before passing the structure to the ISO 7816 layer for
 * processing.
 */
struct sc_pin_cmd_pin {
	const(char)*   prompt;         /* Prompt to display */

	const(ubyte)*  data;           /* PIN, set to NULL when using pin pad */
	int            len;            /* set to 0 when using pin pad */

	size_t         min_length;     /* min length of PIN */
	size_t         max_length;     /* max length of PIN */
version(OPENSC_VERSION_LATEST) {}
else {
	size_t         stored_length;  /* stored length of PIN */
}

	uint           encoding;       /* SC_PIN_ENCODING: ASCII-numeric, BCD, etc */

	size_t         pad_length;     /* PIN padding options, used with SC_PIN_CMD_NEED_PADDING */
	ubyte          pad_char;

	size_t         offset;         /* PIN offset in the APDU when using pin pad */
version(OPENSC_VERSION_LATEST) {}
else {
	size_t         length_offset;  /* Effective PIN length offset in the APDU */
}

	int            max_tries;      /* Used for signaling back from SC_PIN_CMD_GET_INFO */
	int            tries_left;     /* Used for signaling back from SC_PIN_CMD_GET_INFO */
	int            logged_in;      /* SC_PIN_STATE: Used for signaling back from SC_PIN_CMD_GET_INFO */

version(OPENSC_VERSION_LATEST) {}
else {
	sc_acl_entry[SC_MAX_SDO_ACLS] acls;
}

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
			string[] pointersOfInterest = [
				"prompt",
				"data",
			];
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					mixin(head_foreach_Pointer_noSinkMember);
					if (name_member=="acls") {
/*
						sink("[\n");
						foreach (sub_member; acls)
							sink.formatValue(sub_member, fmt);
						sink("]");
*/
						sink.formatValue(acls.ptr, fmt);
					}
					else
						sink.formatValue(member, fmt);
					if (isDereferencable && canFind(pointersOfInterest, name_member)) {
						if      (name_member=="prompt")
							sink(format(`  "%s"`, fromStringz(prompt)));
						else if (name_member=="data")
							sink(format("  [%(%#x, %)]", data[0..clamp(len,0,8)]));
					}
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
		} // void toString
}

/* A NULL in apdu means that the APDU is prepared by the ISO 7816 layer, which also handles PIN
 * padding and setting offset fields for the PINs (for PIN-pad use). A non-NULL in APDU means that
 * the card driver has prepared the APDU (including padding) and set the PIN offset fields.
 *
 * Note that flags apply to both PINs for multi-PIN operations.
 */
struct sc_pin_cmd_data {
	uint            cmd;   /* SC_PIN_CMD */
	uint            flags; /* SC_PIN_CMD_DATA_FLAGS */

	uint            pin_type;       /* usually SC_AC_CHV */
	int             pin_reference;
version(OPENSC_VERSION_LATEST)
	int             puk_reference;  /* non-zero means that reference is available */

	sc_pin_cmd_pin  pin1;
	sc_pin_cmd_pin  pin2; /* Usage for SC_PIN_CMD_CHANGE, SC_PIN_CMD_UNBLOCK and SC_PIN_CMD_GET_SESSION_PIN/SC_CARD_CAP_SESSION_PIN */

	sc_apdu*        apdu;           /* APDU of the PIN command */

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{
			string[] pointersOfInterest = ["apdu"];
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					mixin(head_foreach_Pointer_noSinkMember);
					if (isDereferencable)
						sink("0x");
					sink.formatValue(member, fmt);

					if (isDereferencable && canFind(pointersOfInterest, name_member))
						if (name_member=="apdu")
							sink.formatValue(*apdu, fmt);

					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
	} // void toString
}

//	alias reader_fun1_t = extern(C) int function(sc_context* ctx);
//	alias reader_fun2_t = extern(C) int function(sc_reader* reader);

struct sc_reader_operations {
	extern(C) nothrow @nogc {
		/* Called during sc_establish_context(), when the driver
		 * is loaded */
		int function(sc_context* ctx)                init;
		/* Called when the driver is being unloaded.  finish() has to
		 * release any resources. */
		int function(sc_context* ctx)                finish;
		/* Called when library wish to detect new readers
		 * should add only new readers. */
		int function(sc_context* ctx)                detect_readers;
		int function(sc_context* ctx)                cancel;
		/* Called when releasing a reader.  release() has to
		 * deallocate the private data.  Other fields will be
		 * freed by OpenSC. */
		int function(sc_reader* reader)              release;

		int function(sc_reader* reader)              detect_card_presence;
		int function(sc_reader* reader)              connect;
		int function(sc_reader* reader)              disconnect;
		int function(sc_reader* reader,
				sc_apdu* apdu)                           transmit;
		int function(sc_reader* reader)              lock;
		int function(sc_reader* reader)              unlock;
		int function(sc_reader* reader,
				uint proto)                              set_protocol;
		/* Pin pad functions */
		int function(sc_reader* reader,
				const(char)*)                            display_message;
		int function(sc_reader* reader,
				sc_pin_cmd_data*)                        perform_verify;
		int function(sc_reader* reader,
				void* establish_pace_channel_input,
				void* establish_pace_channel_output)     perform_pace;

		/* Wait for an event */
		int function(sc_context* ctx,
				uint event_mask,
				sc_reader** event_reader,
				uint* event,
				int timeout,
				void** reader_states)                    wait_for_event;
		/* Reset a reader */
		int function(sc_reader* reader,
				int)                                     reset;
		/* Used to pass in PC/SC handles to minidriver */
		int function(sc_context* ctx,
				void* pcsc_context_handle,
				void* pcsc_card_handle)                  use_reader;
	} // extern(C)

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				string name_member = typeof(this).tupleof[i].stringof;
				string unqual_type = typeof(member).stringof[6..$-1]; // peel off const(payload) to get payload
				sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
				sink.formatValue(member, fmt);
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
	}
} // struct sc_reader_operations

/*
 * Card flags
 *
 * Used to hint about card specific capabilities and algorithms
 * supported to the card driver. Used in sc_atr_table and
 * card_atr block structures in the configuration file.
 *
 * Unknown, card vendor specific values may exists, but must
 * not conflict with values defined here. All actions defined
 * by the flags must be handled by the card driver themselves.
 */

enum {
	/* Mask for card vendor specific values */
	SC_CARD_FLAG_VENDOR_MASK = 0xFFFF_0000,

	/* Hint SC_CARD_CAP_RNG */
	SC_CARD_FLAG_RNG         = 0x0000_0002,
	SC_CARD_FLAG_KEEP_ALIVE	 = 0x0000_0004, // since v0.18.0
}

/*
 * Card capabilities
 */
enum {
	/* Card can handle large (> 256 bytes) buffers in calls to
	 * read_binary, write_binary and update_binary; if not,
	 * several successive calls to the corresponding function
	 * is made. */
	SC_CARD_CAP_APDU_EXT               = 0x0000_0001,

	/* Card has on-board random number source. */
	SC_CARD_CAP_RNG                    = 0x0000_0004,

	/* Card supports ISO7816 PIN status queries using an empty VERIFY */
	SC_CARD_CAP_ISO7816_PIN_INFO       = 0x0000_0008,

	/* Use the card's ACs in sc_pkcs15init_authenticate(),
	 * instead of relying on the ACL info in the profile files. */
	SC_CARD_CAP_USE_FCI_AC             = 0x0000_0010,

	/* D-TRUST CardOS cards special flags */
	SC_CARD_CAP_ONLY_RAW_HASH          = 0x0000_0040,
	SC_CARD_CAP_ONLY_RAW_HASH_STRIPPED = 0x0000_0080,

	/* Card (or card driver) supports an protected authentication mechanism */
	SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH	= 0x0000_0100,

	/* Card (or card driver) supports generating a session PIN */
	SC_CARD_CAP_SESSION_PIN            = 0x0000_0200,

	/* Card and driver supports handling on card session objects.
	 * If a driver has this capability, the driver handles storage and operations
	 * with objects that CKA_TOKEN set to FALSE. If a driver doesn't support this,
	 * OpenSC handles them as in memory objects.*/
	SC_CARD_CAP_ONCARD_SESSION_OBJECTS = 0x0000_0400, // OPENSC_VERSION_LATEST

	/* Card (or card driver) supports key wrapping operations */
	SC_CARD_CAP_WRAP_KEY               = 0x0000_0800, // OPENSC_VERSION_LATEST
	/* Card (or card driver) supports key unwrapping operations */
	SC_CARD_CAP_UNWRAP_KEY             = 0x0000_1000, // OPENSC_VERSION_LATEST
}

version(sym_hw_encrypt)
/* Card supports symmetric/secret key algorithms (currently at least AES, modes ECB and CBC) */
enum SC_CARD_CAP_SYM_KEY_ALGOS = 0x0000_2000;


	struct sc_card {
		sc_context*          ctx;
		sc_reader*           reader;

		sc_atr               atr;
		sc_uid               uid;

		int                  type;           /* Card type, for card driver internal use */
		c_ulong              caps;
		c_ulong              flags;
		int                  cla;
		size_t               max_send_size;  /* Max Lc supported by the card */
		size_t               max_recv_size;  /* Max Le supported by the card */
		sc_app_info*[SC_MAX_CARD_APPS] app;
		int                  app_count;

		sc_ef_atr*           ef_atr;
		sc_algorithm_info*   algorithms;
		int                  algorithm_count;
		int                  lock_count;
		sc_card_driver*      driver;
		sc_card_operations*  ops;
		const(char)*         name;
		void*                drv_data;
		int                  max_pin_len;
		sc_card_cache        cache;
		sc_serial_number     serialnr;
		sc_version           version_;
		void*                mutex;

		version(ENABLE_SM)
			sm_context         sm_ctx;

		uint                 magic;
/+
version(none/*ENABLE_TOSTRING*/)
		string toString() nothrow {
			string result;
			try {
				result = "\nctx:\n====\n";
				if (ctx)
  				result ~= format("%s", *ctx);
  			else
    			result ~= format("%s",  ctx);
				result ~= "\nreader:\n=======\n";
				if (reader)
  				result ~= format("%s\n", *reader);
  			else
    			result ~= format("%s\n",  reader);
				result ~= format(
					"\atr:  %s\ntype: %s\ncaps(hex): %X\nflags(hex): %X\ncla(hex): %X\nmax_send_size: %s\nmax_recv_size: %s\n",//app: %s\n",
					atr, type, caps, flags, cla, max_send_size, max_recv_size);//, app[0..clamp(app_count, 0, SC_MAX_CARD_APPS)]);
			}
			catch (Exception e) { /* todo: handle exception */ }
			return result;
		}
+/

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
			string[] pointersOfInterest = [
//				"ctx", it's not safe to dereference a sc_context* as long as it's .sizeof is not known exactly !!!
//				"reader",
				"ef_dir",
				"ef_atr",
				"algorithms",
				"driver",
				"ops",
				"name",
//			"drv_data", not dereferencable without cast
//			"mutex", not dereferencable without cast
			];
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1]; // peel off const(payload) to get payload
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
					if (name_member=="app") {
						sink("  [");
						foreach (j, ref sub_member; app) {
							if (j+1>app_count)
								break;
							if (sub_member)
								sink.formatValue(*sub_member, fmt);
							sink(", ");
						}
						sink("]");
					}
					else
						sink.formatValue(member, fmt);
					string value_rep = format("%s", member);
//					sink(";  ");
					bool isDereferencable = (unqual_type[$-1]=='*' && unqual_type[0..$-1]!="void") && value_rep!="null";
//					sink(isDereferencable ? "YES": "NO"); //  ops:  231D380;  sc_card_operations*; YES
					if (isDereferencable && canFind(pointersOfInterest, name_member)) {
//						formattedWrite(writer, "%s", *card);
//						sink.formatValue(*(this.tupleof[i]), fmt);
						if (name_member=="ctx")
							sink.formatValue(*ctx, fmt);
						else if (name_member=="reader")
							sink.formatValue(*reader, fmt);
						else if (name_member=="ef_dir")
							sink.formatValue(*ef_dir, fmt);
						else if (name_member=="ef_atr")
							sink.formatValue(*ef_atr, fmt);
						else if (name_member=="algorithms") {
/*
							sc_algorithm_info* p = cast(sc_algorithm_info*)algorithms;
							int ii;
							while(p && ii++< algorithm_count) {
								sink.formatValue(*p, fmt);
								p++;
							}
*/
							sink.formatValue(*algorithms, fmt);
						}
						else if (name_member=="driver")
							sink.formatValue(*driver, fmt);
						else if (name_member=="ops")
							sink.formatValue(*ops, fmt);
						else if (name_member=="name")
							sink(format(`  "%s"`, fromStringz(name)));
					}
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
		} // void toString
	} // struct sc_card
//	alias sc_card_t = sc_card;

extern(C) nothrow
{
	alias card_fun1_t = int function(sc_card* card);
	alias card_fun2_t = int function(sc_card* card, uint idxORrec_nr,       ubyte*  buf, size_t count, c_ulong flags);
	alias card_fun3_t = int function(sc_card* card, uint idxORrec_nr, const(ubyte)* buf, size_t count, c_ulong flags);
	alias card_fun4_t = int function(sc_card* card, const(ubyte)* in_, size_t in_len, ubyte* out_, size_t out_len);
	alias erase_binary_tf = int function(sc_card* card, uint idx, size_t count, c_ulong flags);
	alias append_record_tf = int function(sc_card* card, const(ubyte)* buf, size_t count, c_ulong flags);
	alias select_file_tf = int function(sc_card* card, const(sc_path)* path, sc_file** file_out);
	alias get_response_tf = int function(sc_card* card, size_t* count, ubyte* buf);
	alias get_challenge_tf = int function(sc_card* card, ubyte* buf, size_t count);
	alias verify_tf = int function(sc_card* card, uint type, int ref_qualifier, const(ubyte)* data, size_t data_len, int* tries_left);
	alias restore_security_env_tf = int function(sc_card* card, int se_num);
	alias set_security_env_tf = int function(sc_card* card, const(sc_security_env)* env, int se_num);
	alias change_reference_data_tf = int function(sc_card* card, uint type, int ref_qualifier, const(ubyte)* old, size_t oldlen, const(ubyte)* newref, size_t newlen, int* tries_left);
	alias reset_retry_counter_tf = int function(sc_card* card, uint type, int ref_qualifier, const(ubyte)* puk, size_t puklen, const(ubyte)* newref, size_t newlen);
	alias create_file_tf = int function(sc_card* card, sc_file* file);
	alias delete_file_tf = int function(sc_card* card, const(sc_path)* path);
	alias list_files_tf = int function(sc_card* card, ubyte* buf, size_t buflen);
	alias check_sw_tf = int function(sc_card* card, uint sw1, uint sw2);
	alias card_ctl_tf = int function(sc_card* card, c_ulong request, void* data);
	alias process_fci_tf = int function(sc_card* card, sc_file* file, const(ubyte)* buf, size_t buflen);
	alias construct_fci_tf = int function(sc_card* card, const(sc_file)* file, ubyte* out_, size_t* outlen);
	alias pin_cmd_tf = int function(sc_card* card, sc_pin_cmd_data* data, int* tries_left);
	alias get_data_tf = int function(sc_card* card, uint, ubyte*, size_t);
	alias put_data_tf = int function(sc_card* card, uint, const(ubyte)*, size_t);
	alias delete_record_tf = int function(sc_card* card, uint rec_nr);
	alias read_public_key_tf = int function(sc_card* card, uint, sc_path* path, uint, uint, ubyte**, size_t*);
	alias card_reader_lock_obtained_tf = int function(sc_card* card, int was_reset);
	alias wrap_tf = int function(sc_card* card, ubyte* out_, size_t outlen);
	alias unwrap_tf = int function(sc_card* card, const(ubyte)* crgram, size_t crgram_len);
} // extern(C)

	struct sc_card_operations {
		/* Called in sc_connect_card().  Must return 1, if the current
		 * card can be handled with this driver, or 0 otherwise.  ATR
		 * field of the sc_card struct is filled in before calling
		 * this function. */
		card_fun1_t         match_card;

		/* Called when ATR of the inserted card matches an entry in ATR
		 * table.  May return SC_ERROR_INVALID_CARD to indicate that
		 * the card cannot be handled with this driver. */
		card_fun1_t         init;

		/* Called when the card object is being freed.  finish() has to
		 * deallocate all possible private data. */
		card_fun1_t         finish;

	/* ISO 7816-4 functions */

		card_fun2_t         read_binary;
		card_fun3_t         write_binary;
		card_fun3_t         update_binary;
		erase_binary_tf     erase_binary;
		card_fun2_t         read_record;
		card_fun3_t         write_record;
		append_record_tf    append_record;
		card_fun3_t         update_record;

		/* select_file: Does the equivalent of SELECT FILE command specified
		 *   in ISO7816-4. Stores information about the selected file to
		 *   <file>, if not NULL. */
		select_file_tf      select_file;
		get_response_tf     get_response;
		get_challenge_tf    get_challenge;

	/*
	 * ISO 7816-8 functions
	 */

		/* verify:  Verifies reference data of type <acl>, identified by
		 *   <ref_qualifier>. If <tries_left> is not NULL, number of verifying
		 *   tries left is saved in case of verification failure, if the
		 *   information is available. */
		deprecated("Don't use this: It's old style and not necessary if pin_cmd is supported") verify_tf verify;

		/* logout: Resets all access rights that were gained. */
		card_fun1_t         logout;

		/* restore_security_env:  Restores a previously saved security
		 *   environment, and stores information about the environment to
		 *   <env_out>, if not NULL. */
		restore_security_env_tf restore_security_env;

		/* set_security_env:  Initializes the security environment on card
		 *   according to <env>, and stores the environment as <se_num> on the
		 *   card. If se_num <= 0, the environment will not be stored. */
		set_security_env_tf set_security_env;

		/* decipher:  Engages the deciphering operation.  Card will use the
		 *   security environment set in a call to set_security_env or
		 *   restore_security_env. */
		card_fun4_t         decipher;

		/* compute_signature:  Generates a digital signature on the card.  Similar
		 *   to the function decipher. */
		card_fun4_t         compute_signature;
		deprecated("Don't use this: It's old style and not necessary if pin_cmd is supported") {
			change_reference_data_tf  change_reference_data;
			reset_retry_counter_tf    reset_retry_counter;
		}
		/*
		 * ISO 7816-9 functions
		 */

		create_file_tf      create_file;
		delete_file_tf      delete_file;

		/* list_files:  Enumerates all the files in the current DF, and
		 *   writes the corresponding file identifiers to <buf>.  Returns
		 *   the number of bytes stored. */
		list_files_tf       list_files;
		check_sw_tf         check_sw;
		card_ctl_tf         card_ctl;
		process_fci_tf      process_fci;
		construct_fci_tf    construct_fci;

		/* pin_cmd: verify/change/unblock command; optionally using the
		 * card's pin pad if supported.
		 */
		pin_cmd_tf          pin_cmd;
		get_data_tf         get_data;
		put_data_tf         put_data;
		delete_record_tf    delete_record;
		read_public_key_tf  read_public_key;
		card_reader_lock_obtained_tf  card_reader_lock_obtained;

		wrap_tf             wrap;
		unwrap_tf           unwrap;

	version(sym_hw_encrypt) {
		/* encrypt_sym:  Engages the enciphering operation with a sym. key.  Card will use the
		 *   security environment set in a call to set_security_env or
		 *   restore_security_env.
		 *
		 *   Responsibility for padding to block_size: Preliminary decision, that it's the
		 *   card driver who is responsible for padding !
		 *   ACOS5 hw op encrypt (Symmetric Key Encrypt): The operation computes DES/3DES/AES
		 *     in ECB or CBC mode. The command takes blocks of data in multiples of 8 (for DES)
		 *     or 16 (AES), up to 248 bytes ? and encrypts it. The implementation for ACOS5
		 *     will be complex to manage: looping, switching CLA from  Plain Chaining Mode to
		 *     Plain Mode (last block). Also, possible SM Mode will reduce data_len transferable
		 *     in each command invocation.
		 *   */
		card_fun4_t         encrypt_sym;

		/* decrypt_sym:  Engages the deciphering operation with a sym. key.  Card will use the
		 *   security environment set in a call to set_security_env or
		 *   restore_security_env.
		 *
		 *   Basically the same considerations as for encrypt and a relaxation: It is
		 *   presupposed, that crgram_len already is a multiple of block_size !
		 *   Card driver needs to remove padding bytes (if there are any) !
		 *   */
			card_fun4_t         decrypt_sym;
	}

	version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1]; // peel off const(payload) to get payload
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
					sink.formatValue(member, fmt);
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
		}
	} // struct sc_card_operations

	struct sc_card_driver {
		const(char)*         name;
		const(char)*         short_name;
		sc_card_operations*  ops;
		sc_atr_table*        atr_map; // get's free'ed by opensc, thus must use malloc/calloc
		uint                 natrs;
		void*                dll;

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
			string[] pointersOfInterest = [
				"name",
				"short_name",
				"ops",
				"atr_map",
//			"dll", not dereferencable
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
//					sink(";  ");
//					sink(isDereferencable ? "YES": "NO");
					if (isDereferencable && canFind(pointersOfInterest, name_member)) {
						if (name_member=="name")
							sink(format(`  "%s"`, fromStringz(name)));
						else if (name_member=="short_name")
							sink(format(`  "%s"`, fromStringz(short_name)));
						else if (name_member=="ops")
							sink.formatValue(*ops, fmt);
						else if (name_member=="atr_map")
							sink.formatValue(*atr_map, fmt);
					}
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
		}
	} // struct sc_card_driver
//	alias sc_card_driver_t = sc_card_driver;

	struct sc_thread_context_t {
		uint                    ver;
		extern(C) nothrow @nogc {
			int function(void**)  create_mutex;
			int function(void*)   lock_mutex;
			int function(void*)   unlock_mutex;
			int function(void*)   destroy_mutex;
			c_ulong function()    thread_id;
		}

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1]; // peel off const(payload) to get payload
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
					sink.formatValue(member, fmt);
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
		}
	} // struct sc_thread_context_t

	/** Stop modifying or using external resources
	 *
	 * Currently this is used to avoid freeing duplicated external resources for a
	 * process that has been forked. For example, a child process may want to leave
	 * the duplicated card handles for the parent process. With this flag the child
	 * process indicates that shall the reader shall ignore those resources when
	 * calling sc_disconnect_card.
	 */
	enum : uint /*SC_CTX_FLAG*/ {
		SC_CTX_FLAG_TERMINATE              = 0x0000_0001,
		/** removed in 0.18.0 and later */
		SC_CTX_FLAG_PARANOID_MEMORY        = 0x0000_0002,
		SC_CTX_FLAG_DEBUG_MEMORY           = 0x0000_0004,
		SC_CTX_FLAG_ENABLE_DEFAULT_DRIVER  = 0x0000_0008,
		SC_CTX_FLAG_DISABLE_POPUPS         = 0x0000_0010,
		SC_CTX_FLAG_DISABLE_COLORS         = 0x0000_0020,
	}

	struct sc_context {
		scconf_context*       conf;
		scconf_block*[3]      conf_blocks;
		char*                 app_name;
		int                   debug_;
		c_ulong               flags;

		FILE*                 debug_file;
		char*                 debug_filename;
		char*                 preferred_language;

		list_t                readers;
		sc_reader_driver*     reader_driver;
		void*                 reader_drv_data;

		sc_card_driver*[SC_MAX_CARD_DRIVERS] card_drivers;
		sc_card_driver*       forced_driver;

		sc_thread_context_t*  thread_ctx;
		void*                 mutex;

		uint                  magic;
/+
version(none/*ENABLE_TOSTRING*/)
		string toString() nothrow
		{
			string result;
			try {
				result = "conf: ";
				if (conf)
  				result ~= format("%s", *conf);
  			else
    			result ~= format("%s",  conf);
//				result = format("todo");
				result ~= format("conf_blocks: %s\napp_name: %s\ndebug_: %s\nflags: %s\ndebug_file: %s\ndebug_filename: %s\npreferred_language: %s\nreaders: %s\n" ~
					"  reader_driver: %s\nreader_drv_data: %s\ncard_drivers: %s\nforced_driver: %s\nthread_ctx: %s\nmutex: %s\nmagic: %s\n",
					conf_blocks, fromStringz(app_name), debug_, flags, debug_file, fromStringz(debug_filename), fromStringz(preferred_language), readers,
					reader_driver, reader_drv_data, card_drivers, forced_driver, thread_ctx, mutex, magic);
			}
			catch (Exception e) { /* todo: handle exception */ }
			return result;
		}
+/

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
			string[] pointersOfInterest = [
				"conf",
				"app_name",
/+ +/
//					"debug_file",        not dereferencable ?
				"debug_filename",
				"preferred_language",
				"reader_driver",
//					"reader_drv_data", not dereferencable without cast
				"forced_driver",
//			"thread_ctx",
//					"mutex", not dereferencable without cast
/+ +/
			];
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					mixin(head_foreach_Pointer_noSinkMember);
					if (name_member=="conf_blocks") {
						sink(format("  [%(%#x, %)]\n", member));
/+
/* looking at this once, index 0 was populated with opensc.conf's content of app default, thus probably:
												 index 1 will be app opensc-pkcs11
												 index 2 will be app onepin-opensc-pkcs11
	scconf_context.root has anything anyway, thus exclude conf_blocks
*/
					  foreach (conf_block_p; conf_blocks) {
					    if (conf_block_p == null)
					      continue;
							sink.formatValue(*conf_block_p, fmt);
					  }
+/
					}
// pointer of default card driver gets excluded
					else if (name_member=="card_drivers") {
						sink(format("  [%(%#x, %)]", member));
					  foreach (card_driver_p; card_drivers) {
					    if (card_driver_p == null || card_driver_p.short_name.fromStringz=="default")
					      continue;
							sink.formatValue(*card_driver_p, fmt);
					  }
					}
					else {
						if (isDereferencable || isDereferencableVoid)
							sink("0x");
						sink.formatValue(member, fmt);
					}

					if (isDereferencable && canFind(pointersOfInterest, name_member)) {
						if      (name_member=="conf")
							sink.formatValue(*conf, fmt);
						else if (name_member=="app_name")
							sink(format(`  "%s"`, fromStringz(app_name)));
						else if (name_member=="debug_filename")
							sink(format(`  "%s"`, fromStringz(debug_filename)));
						else if (name_member=="preferred_language")
							sink(format(`  "%s"`, fromStringz(preferred_language)));
						else if (name_member=="reader_driver")
							sink.formatValue(*reader_driver, fmt);
						else if (name_member=="forced_driver")
							sink.formatValue(*forced_driver, fmt);
						else if (name_member=="thread_ctx")
							sink.formatValue(*thread_ctx, fmt);
					}
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
		}
	} // struct sc_context
//	alias sc_context_t = sc_context;

extern(C) @nogc nothrow
/* no function that calls driver specific code is eligible to be attributed pure/@trusted: Far to much to check */
{
	/* APDU handling functions */

	/** Sends a APDU to the card
	 *  @param  card  struct sc_card object to which the APDU should be send
	 *  @param  apdu  sc_apdu_t object of the APDU to be send
	 *  @return SC_SUCCESS on success and an error code otherwise
	 */
	int  sc_transmit_apdu(scope sc_card* card, scope sc_apdu* apdu) /*impure, definitely may have side-effect*/ @trusted;

	void sc_format_apdu(scope const sc_card* card, scope sc_apdu* apdu, int apdu_case, int ins, int p1, int p2) pure @trusted; // signature changed: orig: sc_card* card

	/** Format an APDU based on the data to be sent and received.
	 *
	 * Calls \a sc_transmit_apdu() by determining the APDU case based on \a datalen
	 * and \a resplen. As result, no chaining or GET RESPONSE will be performed in
	 * sc_format_apdu().
	 */
	void sc_format_apdu_ex(sc_apdu* apdu,
		ubyte cla, ubyte ins, ubyte p1, ubyte p2,
		const(ubyte)* data, size_t datalen,
		ubyte* resp, size_t resplen);

int  sc_check_apdu(scope const sc_card* card, scope const(sc_apdu)* apdu) pure @trusted; // signature changed: orig: sc_card* card, const(sc_apdu)* apdu

/** Transforms an APDU from binary to its @c sc_apdu_t representation
 *  @param  ctx     sc_context_t object (used for logging)
 *  @param  buf     APDU to be encoded as an @c sc_apdu_t object
 *  @param  len     length of @a buf
 *  @param  apdu    @c sc_apdu_t object to initialize
 *  @return SC_SUCCESS on success and an error code otherwise
 *  @note On successful initialization apdu->data will point to @a buf with an
 *  appropriate offset. Only free() @a buf, when apdu->data is not needed any
 *  longer.
 *  @note On successful initialization @a apdu->resp and apdu->resplen will be
 *  0. You should modify both if you are expecting data in the response APDU.
 */
int  sc_bytes2apdu(scope sc_context* ctx, scope const ubyte* buf, size_t len, scope sc_apdu* apdu) pure /*don't count poss. log entry as side-effect*/ @trusted;

version(PATCH_LIBOPENSC_EXPORTS) {
	/** Encodes a APDU as an octet string
	 *  @param  ctx     sc_context_t object (used for logging)
	 *  @param  apdu    APDU to be encoded as an octet string
	 *  @param  proto   protocol version to be used
	 *  @param  out     output buffer of size outlen.
	 *  @param  outlen  size of the output buffer
	 *  @return SC_SUCCESS on success and an error code otherwise
	 */
	int sc_apdu2bytes(sc_context* ctx, const(sc_apdu)* apdu,
		uint proto, ubyte* out_, size_t outlen);

	/** Calculates the length of the encoded APDU in octets.
	 *  @param  apdu   the APDU
	 *  @param  proto  the desired protocol
	 *  @return length of the encoded APDU
	 */
	size_t sc_apdu_get_length(const(sc_apdu)* apdu, uint proto);
}

	int  sc_check_sw(sc_card* card, uint sw1, uint sw2) pure /*@trusted*/;
	deprecated("Please use sc_context_create() instead") int sc_establish_context(sc_context** ctx, const(char)* app_name);

	struct sc_context_param_t {
		uint                  ver;
		const(char)*          app_name;
		c_ulong               flags;
		sc_thread_context_t*  thread_ctx;
	}

version(PATCH_LIBOPENSC_EXPORTS)
	int sc_context_repair(sc_context** ctx);

int sc_context_create(scope sc_context** ctx, scope const(sc_context_param_t)* parm)                  @trusted;
int sc_release_context(sc_context* ctx)                                                               @trusted;
int sc_ctx_detect_readers(sc_context* ctx);
int sc_ctx_win32_get_config_value(const(char)* env, const(char)* reg, const(char)* key, void* out_, size_t* out_size);

	sc_reader* sc_ctx_get_reader(sc_context* ctx, uint i);
	int sc_ctx_use_reader(sc_context* ctx, void* pcsc_context_handle, void* pcsc_card_handle);
	sc_reader* sc_ctx_get_reader_by_name(sc_context* ctx, const(char)* name);
	sc_reader* sc_ctx_get_reader_by_id(sc_context* ctx, uint id);
	uint sc_ctx_get_reader_count(sc_context* ctx);
	int _sc_delete_reader(sc_context* ctx, sc_reader* reader);
	int sc_ctx_log_to_file(sc_context* ctx, const(char)* filename);
	int sc_set_card_driver(sc_context* ctx, const(char)* short_name);
	int sc_connect_card(sc_reader* reader, sc_card** card);
	int sc_disconnect_card(sc_card* card)                                                                 @trusted;
	int sc_detect_card_presence(sc_reader* reader);

/**
 * Waits for an event on readers.
 *
 * In case of a reader event (attached/detached), the list of reader is
 * adjusted accordingly. This means that a subsequent call to
 * `sc_ctx_detect_readers()` is not needed.
 *
 * @note Only PC/SC backend implements this. An infinite timeout on macOS does
 * not detect reader events (use a limited timeout instead if needed).
 *
 * @param ctx (IN) pointer to a Context structure
 * @param event_mask (IN) The types of events to wait for; this should
 *   be ORed from one of the following:
 *   - SC_EVENT_CARD_REMOVED
 *   - SC_EVENT_CARD_INSERTED
 *	 - SC_EVENT_READER_ATTACHED
 *	 - SC_EVENT_READER_DETACHED
 * @param event_reader (OUT) the reader on which the event was detected
 * @param event (OUT) the events that occurred. This is also ORed
 *   from the constants listed above.
 * @param timeout Amount of millisecs to wait; -1 means forever
 * @retval < 0 if an error occurred
 * @retval = 0 if a an event happened
 * @retval = 1 if the timeout occurred
 */
	int sc_wait_for_event(sc_context* ctx, uint event_mask, sc_reader** event_reader, uint* event, int timeout, void** reader_states);
	int sc_reset(sc_card* card, int do_cold_reset);
	int sc_cancel(sc_context* ctx);
	int sc_lock(sc_card* card);
	int sc_unlock(sc_card* card)                                                                          @trusted;

version(PATCH_LIBOPENSC_EXPORTS) {
	size_t sc_get_max_recv_size(const(sc_card)* card);
	size_t sc_get_max_send_size(const(sc_card)* card);
}
	int sc_select_file(sc_card* card, const(sc_path)* path, sc_file** file);
	int sc_list_files(sc_card* card, ubyte* buf, size_t buflen);
	int sc_read_binary(sc_card* card, uint idx, ubyte* buf, size_t count, c_ulong flags);
	int sc_write_binary(sc_card* card, uint idx, const(ubyte)* buf, size_t count, c_ulong flags);
	int sc_update_binary(sc_card* card, uint idx, const(ubyte)* buf, size_t count, c_ulong flags);
	int sc_erase_binary(sc_card* card, uint idx, size_t count, c_ulong flags);

	enum : c_ulong
	{
		SC_RECORD_EF_ID_MASK = 0x000_1FUL,
		/** flags for record operations */
		/** use first record */
		SC_RECORD_BY_REC_ID  = 0x000_00UL,     // this name currently isn't used by opensc
		/** use the specified record number */
		SC_RECORD_BY_REC_NR  = 0x001_00UL,
		/** use currently selected record */
		SC_RECORD_CURRENT    = 0UL,            // this name currently isn't used by opensc
	}

	/**
	 * Reads a record from the current (i.e. selected) file.
	 * @param  card    struct sc_card object on which to issue the command
	 * @param  rec_nr  SC_READ_RECORD_CURRENT or a record number starting from 1
	 * @param  buf     Pointer to a buffer for storing the data
	 * @param  count   Number of bytes to read
	 * @param  flags   flags (may contain a short file id of a file to select)
	 * @retval number of bytes read or an error value
	 */
	int sc_read_record  (sc_card* card, uint rec_nr, ubyte* buf, size_t count, c_ulong flags);

	int sc_write_record (sc_card* card, uint rec_nr, const(ubyte)* buf, size_t count, c_ulong flags);
	int sc_append_record(sc_card* card, const(ubyte)* buf, size_t count, c_ulong flags);
	int sc_update_record(sc_card* card, uint rec_nr, const(ubyte)* buf, size_t count, c_ulong flags);
	int sc_delete_record(sc_card* card, uint rec_nr);
	int sc_get_data(sc_card* card, uint tag, ubyte* buf, size_t len);
	int sc_put_data(sc_card* card, uint tag, const(ubyte)* buf, size_t len);
	int sc_get_challenge(sc_card* card, ubyte* rndout, size_t len);
	int sc_restore_security_env(sc_card* card, int se_num);
	int sc_set_security_env(sc_card* card, const(sc_security_env)* env, int se_num);
	int sc_decipher(sc_card* card, const(ubyte)* crgram, size_t crgram_len, ubyte* out_, size_t outlen);
	int sc_compute_signature(sc_card* card, const(ubyte)* data, size_t data_len, ubyte* out_, size_t outlen);
	int sc_verify(sc_card* card, uint type, int ref_, const(ubyte)* buf, size_t buflen, int* tries_left);
	int sc_logout(sc_card* card);
	int sc_pin_cmd(sc_card* card, sc_pin_cmd_data*, int* tries_left);
	int sc_change_reference_data(sc_card* card, uint type, int ref_, const(ubyte)* old, size_t oldlen, const(ubyte)* newref, size_t newlen, int* tries_left);
	int sc_reset_retry_counter(sc_card* card, uint type, int ref_, const(ubyte)* puk, size_t puklen, const(ubyte)* newref, size_t newlen);
	int sc_build_pin(ubyte* buf, size_t buflen, sc_pin_cmd_pin* pin, int pad);
version(sym_hw_encrypt) {
	int sc_encrypt_sym(sc_card* card, const(ubyte)* plaintext, size_t plaintext_len,
		ubyte* out_, size_t outlen/*, u8 block_size*/);
	int sc_decrypt_sym(sc_card* card, const(ubyte)* crgram, size_t crgram_len,
		ubyte* out_, size_t outlen/*, u8 block_size*/);
}
/********************************************************************/
/*               ISO 7816-9 related functions                       */
/********************************************************************/

	int sc_create_file(sc_card* card, sc_file* file);
	int sc_delete_file(sc_card* card, const(sc_path)* path);
	int sc_card_ctl(sc_card* card, c_ulong command, void* arg);
	int sc_file_valid(const(sc_file)* file);
	sc_file* sc_file_new();
	void sc_file_free(sc_file* file);
	void sc_file_dup(sc_file** dest, const(sc_file)* src);
	int sc_file_add_acl_entry(sc_file* file, uint operation, uint method, c_ulong key_ref);
	const(sc_acl_entry)* sc_file_get_acl_entry(const(sc_file)* file, uint operation);
	void sc_file_clear_acl_entries(sc_file* file, uint operation);
	int sc_file_set_sec_attr(sc_file* file, const(ubyte)* sec_attr, size_t sec_attr_len);
	int sc_file_set_prop_attr(sc_file* file, const(ubyte)* prop_attr, size_t prop_attr_len);
	int sc_file_set_type_attr(sc_file* file, const(ubyte)* type_attr, size_t type_attr_len);
	int sc_file_set_content(sc_file* file, const(ubyte)* content, size_t content_len);

/********************************************************************/
/*               Key wrapping and unwrapping                        */
/********************************************************************/

int sc_unwrap(sc_card* card, const(ubyte)* data,
			 size_t data_len, ubyte* out_, size_t outlen);
int sc_wrap(sc_card* card, const(ubyte)* data,
			 size_t data_len, ubyte* out_, size_t outlen);

/********************************************************************/
/*             sc_path_t handling functions                         */
/********************************************************************/

/**
 * Sets the content of a sc_path_t object.
 * @param  path    sc_path_t object to set
 * @param  type    type of path
 * @param  id      value of the path
 * @param  id_len  length of the path value
 * @param  index   index within the file
 * @param  count   number of bytes
 * @return SC_SUCCESS on success and an error code otherwise
 */
int sc_path_set(sc_path* path, int type, const(ubyte)* id, size_t id_len, int index, int count);
void sc_format_path(const(char)* path_in, sc_path* path_out);
    const(char)* sc_print_path(const(sc_path)* path);
int sc_path_print(char* buf, size_t buflen, const(sc_path)* path);
int sc_compare_path(const(sc_path)* patha, const(sc_path)* pathb);
int sc_concatenate_path(sc_path* d, const(sc_path)* p1, const(sc_path)* p2);
int sc_append_path(sc_path* dest, const(sc_path)* src);
int sc_compare_path_prefix(const(sc_path)* prefix, const(sc_path)* path);
int sc_append_path_id(sc_path* dest, const(ubyte)* id, size_t idlen);
int sc_append_file_id(sc_path* dest, uint fid);
const(sc_path)* sc_get_mf_path();

/********************************************************************/
/*             miscellaneous functions                              */
/********************************************************************/

int sc_hex_to_bin(const(char)* in_, ubyte* out_, size_t* outlen);
/**
 * Converts an u8 array to a string representing the input as hexadecimal,
 * human-readable/printable form. It's the inverse function of sc_hex_to_bin.
 *
 * @param in The u8 array input to be interpreted, may be NULL iff in_len==0
 * @param in_len Less or equal to the amount of bytes available from in
 * @param out output buffer offered for the string representation, *MUST NOT*
 *             be NULL and *MUST* be sufficiently sized, see out_len
 * @param out_len *MUST* be at least 1 and state the maximum of bytes available
 *                 within out to be written, including the \0 termination byte
 *                 that will be written unconditionally
 * @param separator The character to be used to separate the u8 string
 *                   representations. `0` will suppress separation.
 *
 * Example: input [0x3f], in_len=1, requiring an out_len>=3, will write to out:
 * [0x33, 0x66, 0x00] which reads as "3f"
 * Example: input [0x3f, 0x01], in_len=2, separator=':', req. an out_len>=6,
 * writes to out: [0x33, 0x66, 0x3A, 0x30, 0x31, 0x00] which reads as "3f:01"
 */
int sc_bin_to_hex(const(ubyte)*, size_t, char*, size_t, int separator);
version(PATCH_LIBOPENSC_EXPORTS)
	size_t sc_right_trim(ubyte* buf, size_t len);

scconf_block* sc_get_conf_block(sc_context* ctx, const(char)* name1, const(char)* name2, int priority);
void sc_init_oid(sc_object_id* oid);
int sc_format_oid(sc_object_id* oid, const(char)* in_);
int sc_compare_oid(const(sc_object_id)* oid1, const(sc_object_id)* oid2);
int sc_valid_oid(const(sc_object_id)* oid);
int sc_base64_encode(const(ubyte)* in_, size_t inlen, ubyte* out_, size_t outlen, size_t linelength);
int sc_base64_decode(const(char)* in_, ubyte* out_, size_t outlen);
void sc_mem_clear(void* ptr, size_t len);
void *sc_mem_secure_alloc(size_t len);
void sc_mem_secure_free(void* ptr, size_t len);
int sc_mem_reverse(ubyte* buf, size_t len);
int sc_get_cache_dir(sc_context* ctx, char* buf, size_t bufsize);
int sc_make_cache_dir(sc_context* ctx);
int sc_enum_apps(sc_card* card);
sc_app_info* sc_find_app(sc_card* card, sc_aid* aid);
void sc_free_apps(sc_card* card);
int sc_parse_ef_atr(sc_card* card);
void sc_free_ef_atr(sc_card* card);
version(PATCH_LIBOPENSC_EXPORTS)
int sc_parse_ef_gdo(sc_card* card,
		const(ubyte)** iccsn, size_t* iccsn_len,
		const(ubyte)** chn, size_t* chn_len);

int sc_update_dir(sc_card* card, sc_app_info* app);
version(PATCH_LIBOPENSC_EXPORTS)
	void sc_invalidate_cache(sc_card* card);
void sc_print_cache(sc_card* card);
sc_algorithm_info* sc_card_find_rsa_alg(sc_card* card, uint key_length);
sc_algorithm_info* sc_card_find_ec_alg(sc_card* card, uint field_length, sc_object_id* curve_oid);
sc_algorithm_info* sc_card_find_gostr3410_alg(sc_card* card, uint key_length);

version(PATCH_LIBOPENSC_EXPORTS)
	sc_algorithm_info* sc_card_find_alg(sc_card* card,
		uint algorithm, uint key_length, void* param);

scconf_block* sc_match_atr_block(sc_context* ctx, sc_card_driver* driver, sc_atr* atr);
uint sc_crc32(const(ubyte)* value, size_t len);

version(PATCH_LIBOPENSC_EXPORTS)
/**
 * Find a given tag in a compact TLV structure
 * @param[in]  buf  input buffer holding the compact TLV structure
 * @param[in]  len  length of the input buffer @buf in bytes
 * @param[in]  tag  compact tag to search for - high nibble: plain tag, low nibble: length.
 *                  If length is 0, only the plain tag is used for searching,
 *                  in any other case, the length must also match.
 * @param[out] outlen pointer where the size of the buffer returned is to be stored
 * @return pointer to the tag value found within @buf, or NULL if not found/on error
 */
const(ubyte)* sc_compacttlv_find_tag(const(ubyte)* buf, size_t len, ubyte tag, size_t* outlen);

	void sc_remote_data_init(scope sc_remote_data* rdata) pure @trusted;
version(PATCH_LIBOPENSC_EXPORTS)
	int sc_copy_ec_params(sc_ec_parameters*, sc_ec_parameters*);

	struct sc_card_error
	{
		uint SWs;
		int errorno;
		const(char)* errorstr;
	}

	const(char)* sc_get_version() pure @trusted;
	sc_card_driver* sc_get_iso7816_driver() pure @trusted;

	/**
	 * @brief Read a complete EF by short file identifier.
	 *
	 * @param[in]     card
	 * @param[in]     sfid   Short file identifier
	 * @param[in,out] ef     Where to safe the file. the buffer will be allocated
	 *                       using \c realloc() and should be set to NULL, if
	 *                       empty.
	 * @param[in,out] ef_len Length of \a *ef
	 *
	 * @note The appropriate directory must be selected before calling this function.
	 * */
	int iso7816_read_binary_sfid(sc_card* card, ubyte sfid, ubyte** ef, size_t* ef_len);

	/**
	 * @brief Write a complete EF by short file identifier.
	 *
	 * @param[in] card
	 * @param[in] sfid   Short file identifier
	 * @param[in] ef     Date to write
	 * @param[in] ef_len Length of \a ef
	 *
	 * @note The appropriate directory must be selected before calling this function.
	 * */
	int iso7816_write_binary_sfid(sc_card* card, ubyte sfid, ubyte* ef, size_t ef_len);

	/**
	 * @brief Update a EF by short file identifier.
	 *
	 * @param[in] card   card
	 * @param[in] sfid   Short file identifier
	 * @param[in] ef     Data to write
	 * @param[in] ef_len Length of \a ef
	 *
	 * @note The appropriate directory must be selected before calling this function.
	 * */
	int iso7816_update_binary_sfid(sc_card* card, ubyte sfid,
		ubyte* ef, size_t ef_len);

	/**
	 * @brief Set verification status of a specific PIN to “not verified”
	 *
	 * @param[in] card
	 * @param[in] pin_reference  PIN reference written to P2
	 *
	 * @note The appropriate directory must be selected before calling this function.
	 * */
	int iso7816_logout(sc_card* card, ubyte pin_reference);
/+
version(PATCH_LIBOPENSC_EXPORTS)
version(OPENSC_VERSION_LATEST)
/*
 * @brief Format PIN APDU for modifiction by card driver
 *
 * @param[in] card           card
 * @param[in] apdu           apdu structure to update with PIN APDU
 * @param[in] data           pin command data to set into the APDU
 * @param[in] buf            buffer for APDU data field
 * @param[in] buf_len        maximum buffer length
 */
int
iso7816_build_pin_apdu(struct sc_card *card, struct sc_apdu *apdu,
		struct sc_pin_cmd_data *data, u8 *buf, size_t buf_len);
+/

version(OPENSC_VERSION_LATEST)
	/**
	 * Free a buffer returned by OpenSC.
	 * Use this instead your C libraries free() to free memory allocated by OpenSC.
	 * For more details see <https://github.com/OpenSC/OpenSC/issues/2054>
	 *
	 * @param[in] p the buffer
	 */
	void sc_free(void* p);

} // extern(C) @nogc nothrow

/* some wrappers */
// when using this for acos5 with apdu.le, apdu.le must be between 1 and 255
int bytes2apdu()(scope sc_context* ctx, scope const ubyte[] buf, out sc_apdu apdu) @nogc nothrow pure @trusted
{ return  sc_bytes2apdu(ctx, &buf[0], buf.length, &apdu); }

/* Next is not opensc, not Deimos-like, needs compiling irrespective of version(ENABLE_TOSTRING) set or not:
 * See in acos5 package, file util_general_opensc.d: More structs, functions to help with opensc. */
