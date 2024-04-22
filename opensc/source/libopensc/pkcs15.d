/*
 * pkcs15.h: OpenSC PKCS#15 header file
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2016- for the binding: Carsten Blüggel <bluecars@posteo.eu>
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
#define _OPENSC_PKCS15_H

Content covered by this file is ALL! of header C/libopensc/pkcs15.h
It's functions are ALL exported from "libopensc.[so|dll]" binary except those in scopes version(PATCH_LIBOPENSC_EXPORTS)
TODO: void toString covers ALL! structs, but has to be checked/enabled, ALL! comments are retained from header
TODO inspect/overhaul all toString methods (somewhere there is still a bug):
  those that dereference pointers are subject to crashes if not checked for is null or if there is an opensc bug with non-null list termination (dangling pointers)
  watch out for infinite call chains: never follow pointers to next and previous etc.
  watch out for version dependant fields existing or not
  that use any kind of list types, with special care for those with (or leading to types with) 'sameTypePointingMember' etc.
  generalize using common code out-sourced to mixin_templates_opensc
TODO check for function attributes @nogc, nothrow, pure @system/@trusted. Never use @safe directly for a C function binding,
  but a wrapping function like e.g. libopensc.opensc.bytes2apdu may use @safe;
  @trusted only after inspection source code !
*/

module libopensc.pkcs15;


import core.stdc.config : c_ulong;
version(ENABLE_TOSTRING) {
	import std.string : fromStringz, indexOf, CaseSensitive;
	import std.typecons : Flag, Yes, No;
	import std.format;
	import std.algorithm.comparison : clamp;
	import std.algorithm.searching : canFind;

	import mixin_templates_opensc;
}

import libopensc.opensc;
import libopensc.types;
import scconf.scconf;
import libopensc.auxdata : sc_auxiliary_data;

enum SC_PKCS15_CACHE_DIR      = ".eid";
enum SC_PKCS15_PIN_MAGIC      = 0x31415926;
enum SC_PKCS15_MAX_PINS       = 8;
enum SC_PKCS15_MAX_LABEL_SIZE = 255;
enum SC_PKCS15_MAX_ID_SIZE    = 255;

/* When changing this value, change also initialisation of the
 * static ASN1 variables, that use this macro,
 * like for example, 'c_asn1_access_control_rules'
 * in src/libopensc/asn1.c */
enum SC_PKCS15_MAX_ACCESS_RULES = 8;

struct sc_pkcs15_id {
	ubyte[SC_PKCS15_MAX_ID_SIZE] value;
	size_t len;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{ mixin(frame_noPointer_OneArrayFormatx_noUnion!("value", "len", "SC_PKCS15_MAX_ID_SIZE")); }
} // struct sc_pkcs15_id
alias sc_pkcs15_id_t = sc_pkcs15_id;

enum
	SC_PKCS15_CO_FLAG : uint {
	SC_PKCS15_CO_FLAG_PRIVATE     = 0x00000001,
	SC_PKCS15_CO_FLAG_MODIFIABLE  = 0x00000002,
	SC_PKCS15_CO_FLAG_OBJECT_SEEN = 0x80000000, /* for PKCS #11 module */
}
mixin FreeEnumMembers!SC_PKCS15_CO_FLAG;

enum
	SC_PKCS15_PIN_FLAG : ushort {
	SC_PKCS15_PIN_FLAG_CASE_SENSITIVE            = 0x0001,
	SC_PKCS15_PIN_FLAG_LOCAL                     = 0x0002, //
	SC_PKCS15_PIN_FLAG_CHANGE_DISABLED           = 0x0004,
	SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED          = 0x0008,
	SC_PKCS15_PIN_FLAG_INITIALIZED               = 0x0010, //
	SC_PKCS15_PIN_FLAG_NEEDS_PADDING             = 0x0020,
	SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN            = 0x0040, //
	SC_PKCS15_PIN_FLAG_SO_PIN                    = 0x0080, //
	SC_PKCS15_PIN_FLAG_DISABLE_ALLOW             = 0x0100,
	SC_PKCS15_PIN_FLAG_INTEGRITY_PROTECTED       = 0x0200,
	SC_PKCS15_PIN_FLAG_CONFIDENTIALITY_PROTECTED = 0x0400,
	SC_PKCS15_PIN_FLAG_EXCHANGE_REF_DATA         = 0x0800,
}
mixin FreeEnumMembers!SC_PKCS15_PIN_FLAG;

enum
	SC_PKCS15_PIN_TYPE_FLAGS {
	SC_PKCS15_PIN_TYPE_FLAGS_MASK       = SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_LOCAL | SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN | SC_PKCS15_PIN_FLAG_SO_PIN,
	SC_PKCS15_PIN_TYPE_FLAGS_SOPIN      = SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_SO_PIN,
	SC_PKCS15_PIN_TYPE_FLAGS_PIN_GLOBAL = SC_PKCS15_PIN_FLAG_INITIALIZED,
	SC_PKCS15_PIN_TYPE_FLAGS_PIN_LOCAL  = SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_LOCAL,
	SC_PKCS15_PIN_TYPE_FLAGS_PUK_GLOBAL = SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN,
	SC_PKCS15_PIN_TYPE_FLAGS_PUK_LOCAL  = SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN | SC_PKCS15_PIN_FLAG_LOCAL,
}
mixin FreeEnumMembers!SC_PKCS15_PIN_TYPE_FLAGS;

enum
	SC_PKCS15_PIN_TYPE {
	SC_PKCS15_PIN_TYPE_BCD             = 0,
	SC_PKCS15_PIN_TYPE_ASCII_NUMERIC   = 1,
	SC_PKCS15_PIN_TYPE_UTF8            = 2,
	SC_PKCS15_PIN_TYPE_HALFNIBBLE_BCD  = 3,
	SC_PKCS15_PIN_TYPE_ISO9564_1       = 4,
}
mixin FreeEnumMembers!SC_PKCS15_PIN_TYPE;

enum
	SC_PKCS15_PIN_AUTH_TYPE {
	SC_PKCS15_PIN_AUTH_TYPE_PIN        = 0,
	SC_PKCS15_PIN_AUTH_TYPE_BIOMETRIC  = 1,
	SC_PKCS15_PIN_AUTH_TYPE_AUTH_KEY   = 2,
	SC_PKCS15_PIN_AUTH_TYPE_SM_KEY     = 3,
}
mixin FreeEnumMembers!SC_PKCS15_PIN_AUTH_TYPE;

/* PinAttributes as they defined in PKCS#15 v1.1 for PIN authentication object */
struct sc_pkcs15_pin_attributes {
	uint    flags;          /* SC_PKCS15_PIN_FLAG */
	uint    type;           /* SC_PKCS15_PIN_TYPE */
	size_t  min_length;
	size_t  stored_length;
	size_t  max_length;
	int     reference;
	ubyte   pad_char;
}

/* AuthKeyAttributes of the authKey authentication object */
struct sc_pkcs15_authkey_attributes {
	int           derived;
	sc_pkcs15_id  skey_id;
}

/* BiometricAttributes of the biometricTemplate authentication object */
struct sc_pkcs15_biometric_attributes
{
	uint          flags;
	sc_object_id  template_id;
}

struct sc_pkcs15_auth_info {
	/* CommonAuthenticationObjectAttributes */
	sc_pkcs15_id  auth_id;

	/* AuthObjectAttributes */
	sc_path       path;
	uint          auth_type; /* SC_PKCS15_PIN_AUTH_TYPE_PIN, SC_PKCS15_PIN_AUTH_TYPE_BIOMETRIC, ... */

	union anonymous {
		sc_pkcs15_pin_attributes        pin;
		sc_pkcs15_biometric_attributes  bio;
		sc_pkcs15_authkey_attributes    authkey;
	}
	anonymous     attrs;

	/* authentication method: CHV, SEN, SYMBOLIC, ... */
	uint          auth_method;

	int           tries_left;
	int           max_tries;
	int           logged_in;

	int           max_unlocks;
}

enum
	SC_PKCS15_ALGO_OP : ubyte {
	SC_PKCS15_ALGO_OP_COMPUTE_CHECKSUM   = 0x01,
	SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE  = 0x02,
	SC_PKCS15_ALGO_OP_VERIFY_CHECKSUM    = 0x04,
	SC_PKCS15_ALGO_OP_VERIFY_SIGNATURE   = 0x08,
	SC_PKCS15_ALGO_OP_ENCIPHER           = 0x10,
	SC_PKCS15_ALGO_OP_DECIPHER           = 0x20,
	SC_PKCS15_ALGO_OP_HASH               = 0x40,
	SC_PKCS15_ALGO_OP_GENERATE_KEY       = 0x80,
}
mixin FreeEnumMembers!SC_PKCS15_ALGO_OP;

/* A large integer, big endian notation */
struct sc_pkcs15_bignum {
	ubyte*  data;
	size_t  len;
}
//alias sc_pkcs15_bignum_t = sc_pkcs15_bignum;

struct sc_pkcs15_der {
	ubyte*  value;
	size_t  len;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = ["value"];
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
					if (name_member=="value")
						sink(format("  [%(%#x, %)]", value));
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception t) { /* todo: handle exception */ }
	} // void toString
} // struct sc_pkcs15_der
//alias sc_pkcs15_der_t = sc_pkcs15_der;

struct sc_pkcs15_u8
{
	ubyte*  value;
	size_t  len;
}
//alias sc_pkcs15_u8_t = sc_pkcs15_u8;

struct sc_pkcs15_data {
	ubyte*  data;	/* DER encoded raw data object */
	size_t  data_len;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = ["data"];
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
					if (name_member=="data")
						sink(format("  [%(%#x, %)]", data[0..data_len]));
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception t) { /* todo: handle exception */ }
	} // void toString
} // struct sc_pkcs15_data
//alias sc_pkcs15_data_t = sc_pkcs15_data;

alias sc_pkcs15_skey   = sc_pkcs15_data;
//alias sc_pkcs15_skey_t = sc_pkcs15_data_t;

struct sc_pkcs15_pubkey_rsa {
	sc_pkcs15_bignum  modulus;
	sc_pkcs15_bignum  exponent;
}

struct sc_pkcs15_prkey_rsa {
	/* public components */
	sc_pkcs15_bignum  modulus;
	sc_pkcs15_bignum  exponent;

	/* private components */
	sc_pkcs15_bignum  d;
	sc_pkcs15_bignum  p;
	sc_pkcs15_bignum  q;

	/* optional CRT elements */
	sc_pkcs15_bignum  iqmp;
	sc_pkcs15_bignum  dmp1;
	sc_pkcs15_bignum  dmq1;
}

struct sc_pkcs15_gost_parameters
{
	sc_object_id  key;
	sc_object_id  hash;
	sc_object_id  cipher;
}

struct sc_pkcs15_pubkey_ec {
	sc_ec_parameters  params;
	sc_pkcs15_u8      ecpointQ; /* This is NOT DER, just value and length */
}

struct sc_pkcs15_pubkey_eddsa {
	sc_pkcs15_u8      pubkey;
}

struct sc_pkcs15_prkey_ec
{
	sc_ec_parameters  params;
	sc_pkcs15_bignum  privateD; /* note this is bignum */
	sc_pkcs15_u8      ecpointQ; /* This is NOT DER, just value and length */
}

struct sc_pkcs15_prkey_eddsa {
	sc_pkcs15_u8      pubkey;
	sc_pkcs15_u8      value;
}

struct sc_pkcs15_pubkey_gostr3410 {
	sc_pkcs15_gost_parameters  params;
	sc_pkcs15_bignum           xy;
}

struct sc_pkcs15_prkey_gostr3410 {
	sc_pkcs15_gost_parameters  params;
	sc_pkcs15_bignum           d;
}

struct sc_pkcs15_pubkey {
version(OPENSC_VERSION_LATEST)
	c_ulong           algorithm;
else
	int               algorithm;
	sc_algorithm_id*  alg_id;

	/* Decoded key */
	union anonymous {
		sc_pkcs15_pubkey_rsa        rsa;
		sc_pkcs15_pubkey_ec         ec;
		sc_pkcs15_pubkey_eddsa      eddsa;
		sc_pkcs15_pubkey_gostr3410  gostr3410;
	}
	anonymous         u;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = ["alg_id"];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				mixin(head_foreach_Pointer_noSinkMember);
				if (name_member!="u") {
					if (isDereferencable)
						sink("0x");
					sink.formatValue(member, fmt);
				}
				else {
					switch (algorithm) {
						case SC_ALGORITHM_RSA:       sink.formatValue(u.rsa, fmt); break;
						case SC_ALGORITHM_DSA:       sink.formatValue(u.dsa, fmt); break;
						case SC_ALGORITHM_EC:        sink.formatValue(u.ec,  fmt); break;
						case SC_ALGORITHM_GOSTR3410: sink.formatValue(u.gostr3410, fmt); break;
						default: break;
					}
				}
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
					if      (name_member=="alg_id")
						sink.formatValue(*alg_id, fmt);
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception t) { /* todo: handle exception */ }
	} // void toString
} // struct sc_pkcs15_pubkey
//alias sc_pkcs15_pubkey_t = sc_pkcs15_pubkey;

struct sc_pkcs15_prkey {
version(OPENSC_VERSION_LATEST)
    c_ulong    algorithm;
else
    uint       algorithm;
/* TODO do we need:	sc_algorithm_id* alg_id; */

	union anonymous
	{
		sc_pkcs15_prkey_rsa        rsa;
		sc_pkcs15_prkey_ec         ec;
		sc_pkcs15_prkey_eddsa      eddsa;
		sc_pkcs15_prkey_gostr3410  gostr3410;
		sc_pkcs15_skey             secret;
	}
	anonymous  u;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				mixin(head_foreach_noPointer_noSinkMember);
				if (name_member!="u")
					sink.formatValue(member, fmt);
				else
					switch (algorithm) {
						case SC_ALGORITHM_RSA:       sink.formatValue(u.rsa, fmt); break;
						case SC_ALGORITHM_DSA:       sink.formatValue(u.dsa, fmt); break;
						case SC_ALGORITHM_EC:        sink.formatValue(u.ec,  fmt); break;
						case SC_ALGORITHM_GOSTR3410: sink.formatValue(u.gostr3410, fmt); break;
						case SC_ALGORITHM_DES, SC_ALGORITHM_3DES, SC_ALGORITHM_GOST, SC_ALGORITHM_AES:
							sink("  secret  (sc_pkcs15_skey) : ");
							sink.formatValue(u.secret, fmt);
							break;
						default: break;
					}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception t) { /* todo: handle exception */ }
	} // void toString
} // struct sc_pkcs15_prkey
//alias sc_pkcs15_prkey_t = sc_pkcs15_prkey;

/* Enveloped objects can be used to provide additional
 * protection to non-native private keys */
struct sc_pkcs15_enveloped_data {
	/* recipient info */
	sc_pkcs15_id     id;          /* key ID */
	sc_algorithm_id  ke_alg;      /* key-encryption algo */
	ubyte*           key;         /* encrypted key */
	size_t           key_len;
	sc_algorithm_id  ce_alg;      /* content-encryption algo */
	ubyte*           content;     /* encrypted content */
	size_t           content_len;
}

struct sc_pkcs15_cert {
	int                version_;
	ubyte*             serial;
	size_t             serial_len;
	ubyte*             issuer;
	size_t             issuer_len;
	ubyte*             subject;
	size_t             subject_len;
	ubyte*             extensions;
	size_t             extensions_len;

	sc_pkcs15_pubkey*  key;

	/* DER encoded raw cert */
	sc_pkcs15_der      data;
}
//alias sc_pkcs15_cert_t = sc_pkcs15_cert;

struct sc_pkcs15_cert_info 	{
	sc_pkcs15_id  id;	       /* correlates to private key id */
	int           authority; /* boolean */
	/* identifiers [2] SEQUENCE OF CredentialIdentifier{{KeyIdentifiers}} */
	sc_path       path;

	sc_pkcs15_der value;
}
//alias sc_pkcs15_cert_info_t = sc_pkcs15_cert_info;

struct sc_pkcs15_data_info {
	/* FIXME: there is no pkcs15 ID in DataType */
	sc_pkcs15_id                    id;

	/* Identify the application:
	 * either or both may be set */
	char[SC_PKCS15_MAX_LABEL_SIZE]  app_label;
	sc_object_id                    app_oid;

	sc_path                         path;

	sc_pkcs15_der                   data;
}
//alias sc_pkcs15_data_info_t = sc_pkcs15_data_info;

/* keyUsageFlags are the same for all key types */
enum
	SC_PKCS15_PRKEY_USAGE : ushort {
	SC_PKCS15_PRKEY_USAGE_ENCRYPT         = 0x01,
	SC_PKCS15_PRKEY_USAGE_DECRYPT         = 0x02,
	SC_PKCS15_PRKEY_USAGE_SIGN            = 0x04,
	SC_PKCS15_PRKEY_USAGE_SIGNRECOVER     = 0x08,
	SC_PKCS15_PRKEY_USAGE_WRAP            = 0x10,
	SC_PKCS15_PRKEY_USAGE_UNWRAP          = 0x20,
	SC_PKCS15_PRKEY_USAGE_VERIFY          = 0x40,
	SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER   = 0x80,
	SC_PKCS15_PRKEY_USAGE_DERIVE          = 0x100,
	SC_PKCS15_PRKEY_USAGE_NONREPUDIATION  = 0x200,
}
mixin FreeEnumMembers!SC_PKCS15_PRKEY_USAGE;

enum
	SC_PKCS15_PRKEY_ACCESS : ubyte {
	SC_PKCS15_PRKEY_ACCESS_SENSITIVE         = 0x01,
	SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE       = 0x02,
	SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE   = 0x04,
	SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE  = 0x08,
	SC_PKCS15_PRKEY_ACCESS_LOCAL             = 0x10,
}
mixin FreeEnumMembers!SC_PKCS15_PRKEY_ACCESS;

enum {
	SC_PKCS15_PARAMSET_GOSTR3410_A = 1,
	SC_PKCS15_PARAMSET_GOSTR3410_B = 2,
	SC_PKCS15_PARAMSET_GOSTR3410_C = 3,
}

enum SC_PKCS15_GOSTR3410_KEYSIZE = 256;

struct sc_pkcs15_keyinfo_gostparams {
	uint gostr3410, gostr3411, gost28147;
}

/* AccessMode bit definitions specified in PKCS#15 v1.1
 * and extended by IAS/ECC v1.0.1 specification. */
enum
	SC_PKCS15_ACCESS_RULE_MODE : ushort {
	SC_PKCS15_ACCESS_RULE_MODE_READ         = 0x01,
	SC_PKCS15_ACCESS_RULE_MODE_UPDATE       = 0x02,
	SC_PKCS15_ACCESS_RULE_MODE_EXECUTE      = 0x04,
	SC_PKCS15_ACCESS_RULE_MODE_DELETE       = 0x08,
	SC_PKCS15_ACCESS_RULE_MODE_ATTRIBUTE    = 0x10,
	SC_PKCS15_ACCESS_RULE_MODE_PSO_CDS      = 0x20,
	SC_PKCS15_ACCESS_RULE_MODE_PSO_VERIFY   = 0x40,
	SC_PKCS15_ACCESS_RULE_MODE_PSO_DECRYPT  = 0x80,
	SC_PKCS15_ACCESS_RULE_MODE_PSO_ENCRYPT  = 0x100,
	SC_PKCS15_ACCESS_RULE_MODE_INT_AUTH     = 0x200,
	SC_PKCS15_ACCESS_RULE_MODE_EXT_AUTH     = 0x400,
}
mixin FreeEnumMembers!SC_PKCS15_ACCESS_RULE_MODE;

struct sc_pkcs15_accessrule {
	uint          access_mode;
	sc_pkcs15_id  auth_id;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
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
		catch (Exception t) { /* todo: handle exception */ }
	} // void toString
} // struct sc_pkcs15_accessrule
//alias sc_pkcs15_accessrule_t = sc_pkcs15_accessrule;

struct sc_pkcs15_key_params
{
	void*                           data;
	size_t                          len;
	extern(C) void function(void*)  free_params;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = [
//			"data"
		];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				string name_member = typeof(this).tupleof[i].stringof;
				string unqual_type = typeof(member).stringof[6..$-1];
				sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
				sink.formatValue(member, fmt);
				string value_rep = format("%s", member);
				bool isDereferencable = (unqual_type[$-1]=='*' /*&& unqual_type[0..$-1]!="void"*/) && value_rep!="null";
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
					if (name_member=="data")
						sink(format("  [%(%#x, %)]", data[0..clamp(len,0,99)])); // 99 is an assumption of uppr limit
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception t) { /* todo: handle exception */ }
	} // void toString
} // struct sc_pkcs15_key_params

struct sc_md_data;

struct sc_pkcs15_prkey_info {
	sc_pkcs15_id                       id; /* correlates to public certificate id */
	uint                               usage;
	uint                               access_flags;
	int                                native;
	int                                key_reference;
	/* convert to union if other types are supported */
	size_t                             modulus_length; /* RSA, in bits */
	size_t                             field_length;   /* EC in bits */

	uint[SC_MAX_SUPPORTED_ALGORITHMS]  algo_refs;

	sc_pkcs15_der                      subject;

	sc_pkcs15_key_params               params;

	sc_path                            path;

	/* Non-pkcs15 data, like MD CMAP record */
	sc_auxiliary_data*                 aux_data;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = ["aux_data"];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				string name_member = typeof(this).tupleof[i].stringof;
				string unqual_type = typeof(member).stringof[6..$-1];
				sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
				if (name_member=="algo_refs")
					sink(format("  [%(%#x, %)]", algo_refs));
				else
					sink.formatValue(member, fmt);
				string value_rep = format("%s", member);
				bool isDereferencable = (unqual_type[$-1]=='*' && unqual_type[0..$-1]!="void") && value_rep!="null";
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
					if (name_member=="aux_data")
						sink.formatValue(*aux_data, fmt);
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception t) { /* todo: handle exception */ }
	} // void toString
} // struct sc_pkcs15_prkey_info
//	alias sc_pkcs15_prkey_info_t = sc_pkcs15_prkey_info;

struct sc_pkcs15_pubkey_info {
	sc_pkcs15_id                       id;	/* correlates to private key id */
	uint                               usage;
	uint                               access_flags;
	int                                native;
	int                                key_reference;
	/* convert to union if other types are supported */
	size_t                             modulus_length; /* RSA */
	size_t                             field_length;   /* EC in bits */

	uint[SC_MAX_SUPPORTED_ALGORITHMS]  algo_refs;

	sc_pkcs15_der                      subject;

	sc_pkcs15_key_params               params;

	sc_path                            path;

	struct anonymous {
		sc_pkcs15_der  raw;
		sc_pkcs15_der  spki;
	}
	anonymous                          direct;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				string name_member = typeof(this).tupleof[i].stringof;
				string unqual_type = typeof(member).stringof[6..$-1];
				sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
					if (name_member=="algo_refs")
					sink(format("  [%(%#x, %)]", algo_refs));
				else
					sink.formatValue(member, fmt);
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception t) { /* todo: handle exception */ }
	} // void toString
} // struct sc_pkcs15_pubkey_info
//alias sc_pkcs15_pubkey_info_t = sc_pkcs15_pubkey_info;

struct sc_pkcs15_skey_info {
	sc_pkcs15_id                      id;
	uint                              usage;
	uint                              access_flags;
	int                               native;
	int                               key_reference;
	size_t                            value_len;
	c_ulong                           key_type;
	uint[SC_MAX_SUPPORTED_ALGORITHMS] algo_refs;
	sc_path                           path; /* if on card */
	sc_pkcs15_der                     data;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				string name_member = typeof(this).tupleof[i].stringof;
				string unqual_type = typeof(member).stringof[6..$-1];
				sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
				if (name_member=="algo_refs")
					sink(format("  [%(%#x, %)]", algo_refs));
				else
					sink.formatValue(member, fmt);
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception t) { /* todo: handle exception */ }
	} // void toString
} // struct sc_pkcs15_skey_info
//alias sc_pkcs15_skey_info_t = sc_pkcs15_skey_info;

enum
	SC_PKCS15_TYPE : ushort {
	SC_PKCS15_TYPE_CLASS_MASK       = 0xF00,

	SC_PKCS15_TYPE_PRKEY            = 0x100,
	SC_PKCS15_TYPE_PRKEY_RSA        = 0x101,
	SC_PKCS15_TYPE_PRKEY_GOSTR3410  = 0x103,
	SC_PKCS15_TYPE_PRKEY_EC         = 0x104,
	SC_PKCS15_TYPE_PRKEY_EDDSA		= 0x105,
	SC_PKCS15_TYPE_PRKEY_XEDDSA		= 0x106,

	SC_PKCS15_TYPE_PUBKEY           = 0x200,
	SC_PKCS15_TYPE_PUBKEY_RSA       = 0x201,
	SC_PKCS15_TYPE_PUBKEY_GOSTR3410 = 0x203,
	SC_PKCS15_TYPE_PUBKEY_EC        = 0x204,
	SC_PKCS15_TYPE_PUBKEY_EDDSA		= 0x205,
	SC_PKCS15_TYPE_PUBKEY_XEDDSA	= 0x206,

	SC_PKCS15_TYPE_SKEY             = 0x300,
	SC_PKCS15_TYPE_SKEY_GENERIC     = 0x301,
	SC_PKCS15_TYPE_SKEY_DES         = 0x302,
	SC_PKCS15_TYPE_SKEY_2DES        = 0x303,
	SC_PKCS15_TYPE_SKEY_3DES        = 0x304,

	SC_PKCS15_TYPE_CERT             = 0x400,
	SC_PKCS15_TYPE_CERT_X509        = 0x401,
	SC_PKCS15_TYPE_CERT_SPKI        = 0x402,

	SC_PKCS15_TYPE_DATA_OBJECT      = 0x500,

	SC_PKCS15_TYPE_AUTH             = 0x600,
	SC_PKCS15_TYPE_AUTH_PIN         = 0x601,
	SC_PKCS15_TYPE_AUTH_BIO         = 0x602,
	SC_PKCS15_TYPE_AUTH_AUTHKEY     = 0x603,
}
mixin FreeEnumMembers!SC_PKCS15_TYPE;

ushort SC_PKCS15_TYPE_TO_CLASS()(uint t) { return cast(ushort)(1 << (t >> 8)); }

enum
	SC_PKCS15_SEARCH_CLASS : ushort {
	SC_PKCS15_SEARCH_CLASS_PRKEY  = 0x0002U,
	SC_PKCS15_SEARCH_CLASS_PUBKEY = 0x0004U,
	SC_PKCS15_SEARCH_CLASS_SKEY   = 0x0008U,
	SC_PKCS15_SEARCH_CLASS_CERT   = 0x0010U,
	SC_PKCS15_SEARCH_CLASS_DATA   = 0x0020U,
	SC_PKCS15_SEARCH_CLASS_AUTH   = 0x0040U,
}
mixin FreeEnumMembers!SC_PKCS15_SEARCH_CLASS;

struct sc_pkcs15_object {
	uint                            type; /* e.g. SC_PKCS15_TYPE_PUBKEY_RSA */
	/* CommonObjectAttributes */
	char[SC_PKCS15_MAX_LABEL_SIZE]  label; /* zero terminated */
	uint                            flags;
	sc_pkcs15_id                    auth_id;

	int                             usage_counter;
	int                             user_consent;

	sc_pkcs15_accessrule[SC_PKCS15_MAX_ACCESS_RULES] access_rules;

	/* Object type specific data */
	void*                           data;
	/* emulated object pointer */
	void*                           emulated;

	sc_pkcs15_df*                   df;         /* can be NULL, if object is 'floating' */
	sc_pkcs15_object*               next, prev; /* used only internally */

	sc_pkcs15_der                   content;

	int session_object;	/* used internally. if nonzero, object is a session object. */

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = [
			"data",
//			"emulated",
			"df",
//			"next",
//			"prev",
		];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				string name_member = typeof(this).tupleof[i].stringof;
				string unqual_type = typeof(member).stringof[6..$-1];
				sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
//				if (name_member=="label") {
//					ptrdiff_t label_pos0 = indexOf(label, ['\0'], 0, No.caseSensitive);
////					sink(format("  [%(%s, %)]", label[0..clamp(label_pos0,0,SC_PKCS15_MAX_LABEL_SIZE)]));
//					sink(format(`  "%s"`, label[0..label_pos0].idup));
//				}
				if      (name_member=="label")
						sink(format(`  "%s"`, fromStringz(label.ptr)));
				else if (name_member=="access_rules") {
					sink("  [");
					foreach (ref sub_member; access_rules) {
						sink.formatValue(sub_member, fmt);
//						sink(", ");
					}
					sink("]");
				}
				else
					sink.formatValue(member, fmt);
				string value_rep = format("%s", member);
				bool isDereferencable = (unqual_type[$-1]=='*' && (unqual_type[0..$-1]!="void" || name_member=="data")) && value_rep!="null";
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
					if (name_member=="data") {
						if      (type==SC_PKCS15_TYPE_PRKEY_RSA)
							sink.formatValue(*(cast(sc_pkcs15_prkey_info*)data), fmt);
						else if (type==SC_PKCS15_TYPE_PUBKEY_RSA)
							sink.formatValue(*(cast(sc_pkcs15_pubkey_info*)data), fmt);
						else if (SC_PKCS15_TYPE_TO_CLASS!()(type) == SC_PKCS15_SEARCH_CLASS.SC_PKCS15_SEARCH_CLASS_SKEY){
							sink("  (sc_pkcs15_skey_info) : ");
							sink.formatValue(*(cast(sc_pkcs15_skey_info*)data), fmt);
						}
					}
					else if (name_member=="df")
						sink.formatValue(*df, fmt);
					else if (name_member=="next")
						sink.formatValue(*next, fmt);
					else if (name_member=="prev")
						sink.formatValue(*prev, fmt);
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception t) { /* todo: handle exception */ }
	} // void toString
} // struct sc_pkcs15_object
//alias sc_pkcs15_object_t = sc_pkcs15_object;

/* PKCS #15 DF types */
enum SC_PKCS15_DF : ubyte {
	SC_PKCS15_PRKDF          = 0,
	SC_PKCS15_PUKDF          = 1,
	SC_PKCS15_PUKDF_TRUSTED  = 2,
	SC_PKCS15_SKDF           = 3,
	SC_PKCS15_CDF            = 4,
	SC_PKCS15_CDF_TRUSTED    = 5,
	SC_PKCS15_CDF_USEFUL     = 6,
	SC_PKCS15_DODF           = 7,
	SC_PKCS15_AODF           = 8,
	SC_PKCS15_DF_TYPE_COUNT  = 9,
}
mixin FreeEnumMembers!SC_PKCS15_DF;

struct sc_pkcs15_df {
	sc_path        path;
	int            record_length;
	uint           type;
	int            enumerated;

	sc_pkcs15_df*  next, prev;
}
//alias sc_pkcs15_df_t = sc_pkcs15_df;

struct sc_pkcs15_unusedspace {
	sc_path                 path;
	sc_pkcs15_id            auth_id;

	sc_pkcs15_unusedspace*  next, prev;
}
//alias sc_pkcs15_unusedspace_t = sc_pkcs15_unusedspace;

enum SC_PKCS15_CARD_MAGIC = 0x10203040;

struct sc_pkcs15_sec_env_info {
	int           se;
	sc_object_id  owner;
	sc_aid        aid;
}
//alias sc_pkcs15_sec_env_info_t = sc_pkcs15_sec_env_info;

struct sc_pkcs15_last_update {
	char*    gtime;
	sc_path  path;
}
//alias sc_pkcs15_last_update_t = sc_pkcs15_last_update;

struct sc_pkcs15_profile_indication {
	sc_object_id  oid;
	char*         name;
}
//alias sc_pkcs15_profile_indication_t = sc_pkcs15_profile_indication;

struct sc_pkcs15_tokeninfo {
	uint                          version_;
	uint                          flags;
	char*                         label;
	char*                         serial_number;
	char*                         manufacturer_id;

	sc_pkcs15_last_update         last_update;
	sc_pkcs15_profile_indication  profile_indication;

	char*                         preferred_language;
	sc_pkcs15_sec_env_info**      seInfo;
	size_t                        num_seInfo;

	sc_supported_algo_info[SC_MAX_SUPPORTED_ALGORITHMS] supported_algos;
}
//alias sc_pkcs15_tokeninfo_t = sc_pkcs15_tokeninfo;

struct sc_pkcs15_operations {
	extern(C) int  function(sc_pkcs15_card*, sc_pkcs15_df*)                              parse_df;
	extern(C) void function(sc_pkcs15_card*)                                             clear;
	extern(C) int  function(sc_pkcs15_card*, const(sc_pkcs15_object)*, ubyte*, size_t*)  get_guid;
}

struct sc_pkcs15_card {
	sc_card*                card;
	uint                    flags;

	sc_app_info*            app;

	sc_file*                file_app;
	sc_file*                file_tokeninfo;
	sc_file*                file_odf;
	sc_file*                file_unusedspace;

	sc_pkcs15_df*           df_list;
	sc_pkcs15_object*       obj_list;
	sc_pkcs15_tokeninfo*    tokeninfo;
	sc_pkcs15_unusedspace*  unusedspace_list;
	int                     unusedspace_read;

	struct sc_pkcs15_card_opts {
		int  use_file_cache;
		int  use_pin_cache;
		int  pin_cache_counter;
		int  pin_cache_ignore_user_consent;
		int  private_certificate;
	}
	sc_pkcs15_card_opts     opts;

	uint                    magic;
	void*                   dll_handle; /* shared lib for emulated cards */
	sc_md_data*             md_data;    /* minidriver specific data */

	sc_pkcs15_operations    ops;
} // struct sc_pkcs15_card

/* flags suitable for sc_pkcs15_tokeninfo_t */
enum
	SC_PKCS15_TOKEN : ubyte {
	SC_PKCS15_TOKEN_READONLY       = 0x01,
	SC_PKCS15_TOKEN_LOGIN_REQUIRED = 0x02, /* Don't use */
	SC_PKCS15_TOKEN_PRN_GENERATION = 0x04,
	SC_PKCS15_TOKEN_EID_COMPLIANT  = 0x08,
}
mixin FreeEnumMembers!SC_PKCS15_TOKEN;

enum SC_PKCS15_CARD_FLAG_EMULATED = 0x02000000;

/* suitable for struct sc_pkcs15_card.opts.use_file_cache */
enum {
	SC_PKCS15_OPTS_CACHE_NO_FILES      = 0,
	SC_PKCS15_OPTS_CACHE_PUBLIC_FILES  = 1,
	SC_PKCS15_OPTS_CACHE_ALL_FILES     = 2,
}

/* suitable for struct sc_pkcs15_card.opts.private_certificate */
enum {
    SC_PKCS15_CARD_OPTS_PRIV_CERT_PROTECT    = 0,
    SC_PKCS15_CARD_OPTS_PRIV_CERT_IGNORE     = 1,
    SC_PKCS15_CARD_OPTS_PRIV_CERT_DECLASSIFY = 2,
}

/* X509 bits for certificate usage extension */
enum : uint {
	SC_X509_DIGITAL_SIGNATURE     = 0x0001UL,
	SC_X509_NON_REPUDIATION       = 0x0002UL,
	SC_X509_KEY_ENCIPHERMENT      = 0x0004UL,
	SC_X509_DATA_ENCIPHERMENT     = 0x0008UL,
	SC_X509_KEY_AGREEMENT         = 0x0010UL,
	SC_X509_KEY_CERT_SIGN         = 0x0020UL,
	SC_X509_CRL_SIGN              = 0x0040UL,
	SC_X509_ENCIPHER_ONLY         = 0x0080UL,
	SC_X509_DECIPHER_ONLY         = 0x0100UL,
}

extern (C) nothrow @nogc
{
/* sc_pkcs15_bind:  Binds a card object to a PKCS #15 card object
 * and initializes a new PKCS #15 card object.  Will return
 * SC_ERROR_PKCS15_APP_NOT_FOUND, if the card hasn't got a
 * valid PKCS #15 file structure. */
	int  sc_pkcs15_bind(sc_card* card, sc_aid* aid, sc_pkcs15_card** pkcs15_card);
/* sc_pkcs15_unbind:  Releases a PKCS #15 card object, and frees any
 * memory allocations done on the card object. */
	int  sc_pkcs15_unbind(sc_pkcs15_card* card);
	int  sc_pkcs15_bind_internal(sc_pkcs15_card* p15card, sc_aid* aid);

	int  sc_pkcs15_get_objects(sc_pkcs15_card* card, uint type, sc_pkcs15_object** ret, size_t ret_count);
	int  sc_pkcs15_get_objects_cond(sc_pkcs15_card* card, uint type, int function(sc_pkcs15_object*, void*) func, void* func_arg, sc_pkcs15_object** ret, size_t ret_count);
	int  sc_pkcs15_find_object_by_id(sc_pkcs15_card*, uint, const(sc_pkcs15_id)*, sc_pkcs15_object**);

	sc_pkcs15_card* sc_pkcs15_card_new();
	void sc_pkcs15_card_free(sc_pkcs15_card* p15card);
	void sc_pkcs15_card_clear(sc_pkcs15_card* p15card);
	sc_pkcs15_tokeninfo* sc_pkcs15_tokeninfo_new();
	void sc_pkcs15_free_tokeninfo(sc_pkcs15_tokeninfo* tokeninfo);

	int  sc_pkcs15_decipher(sc_pkcs15_card* p15card, const(sc_pkcs15_object)* prkey_obj, c_ulong flags, const(ubyte)* in_, size_t inlen, ubyte* out_, size_t outlen, void* pMechanism);
	int  sc_pkcs15_derive(sc_pkcs15_card* p15card, const(sc_pkcs15_object)* prkey_obj, c_ulong flags, const(ubyte)* in_, size_t inlen, ubyte* out_, size_t* poutlen);

	int sc_pkcs15_unwrap(sc_pkcs15_card* p15card,
		const(sc_pkcs15_object)* key,
		sc_pkcs15_object* target_key,
		c_ulong flags,
		const(ubyte)* in_, size_t inlen,
		const(ubyte)* param, size_t paramlen);

	int sc_pkcs15_wrap(sc_pkcs15_card* p15card,
		const(sc_pkcs15_object)* key,
		sc_pkcs15_object* target_key,
		c_ulong flags,
		ubyte* cryptogram, c_ulong* crgram_len,
		const(ubyte)* param, size_t paramlen);

	int  sc_pkcs15_compute_signature(sc_pkcs15_card* p15card, const(sc_pkcs15_object)* prkey_obj, c_ulong alg_flags,
		const(ubyte)* in_, size_t inlen, ubyte* out_, size_t outlen, void *pMechanism);

	int sc_pkcs15_encrypt_sym(sc_pkcs15_card* p15card, const(sc_pkcs15_object)* obj, c_ulong flags,
	    const(ubyte)* in_, size_t inlen, ubyte* out_, size_t* outlen, const(ubyte)* param, size_t paramlen);

    int sc_pkcs15_decrypt_sym(sc_pkcs15_card* p15card, const(sc_pkcs15_object)* obj, c_ulong flags,
		const(ubyte)* in_, size_t inlen, ubyte* out_, size_t* outlen, const(ubyte)* param, size_t paramlen);

	int  sc_pkcs15_read_pubkey(sc_pkcs15_card*, const(sc_pkcs15_object)*, sc_pkcs15_pubkey**);
	int  sc_pkcs15_decode_pubkey_rsa(sc_context*, sc_pkcs15_pubkey_rsa*, const(ubyte)*, size_t);
	int  sc_pkcs15_encode_pubkey_rsa(sc_context*, sc_pkcs15_pubkey_rsa*, ubyte**, size_t*);
	int  sc_pkcs15_decode_pubkey_gostr3410(sc_context*, sc_pkcs15_pubkey_gostr3410*, const(ubyte)*, size_t);
	int  sc_pkcs15_encode_pubkey_gostr3410(sc_context*, sc_pkcs15_pubkey_gostr3410*, ubyte**, size_t*);
	int  sc_pkcs15_decode_pubkey_ec(sc_context*, sc_pkcs15_pubkey_ec*, const(ubyte)*, size_t);
	int  sc_pkcs15_encode_pubkey_ec(sc_context*, sc_pkcs15_pubkey_ec*, ubyte**, size_t*);
	int  sc_pkcs15_encode_pubkey_eddsa(sc_context*, sc_pkcs15_pubkey_eddsa*, ubyte**, size_t*);

	int  sc_pkcs15_decode_pubkey(sc_context*, sc_pkcs15_pubkey*, const(ubyte)*, size_t);
	int  sc_pkcs15_encode_pubkey(sc_context*, sc_pkcs15_pubkey*, ubyte**, size_t*);
	int  sc_pkcs15_encode_pubkey_as_spki(sc_context*, sc_pkcs15_pubkey*, ubyte**, size_t*);
	void sc_pkcs15_erase_pubkey(sc_pkcs15_pubkey*);
	void sc_pkcs15_free_pubkey(sc_pkcs15_pubkey*);
	int  sc_pkcs15_pubkey_from_prvkey(sc_context*, sc_pkcs15_prkey*, sc_pkcs15_pubkey**);
	int  sc_pkcs15_dup_pubkey(sc_context*, sc_pkcs15_pubkey*, sc_pkcs15_pubkey**);
	int  sc_pkcs15_pubkey_from_cert(sc_context*, sc_pkcs15_der*, sc_pkcs15_pubkey**);

version(PATCH_LIBOPENSC_EXPORTS) {
	int  sc_pkcs15_pubkey_from_spki_file(sc_context*, char*, sc_pkcs15_pubkey**);
	int  sc_pkcs15_pubkey_from_spki_fields(sc_context*, sc_pkcs15_pubkey**, ubyte*, size_t, int);
	int  sc_pkcs15_encode_prkey(sc_context*, sc_pkcs15_prkey*, ubyte**, size_t*);
}
	void sc_pkcs15_free_prkey(sc_pkcs15_prkey* prkey);
	void sc_pkcs15_erase_prkey(sc_pkcs15_prkey* prkey);
	void sc_pkcs15_free_key_params(sc_pkcs15_key_params* params);

	int  sc_pkcs15_read_data_object(sc_pkcs15_card* p15card, const(sc_pkcs15_data_info)* info,
		int private_obj, sc_pkcs15_data** data_object_out);
	int  sc_pkcs15_find_data_object_by_id(sc_pkcs15_card* p15card, const(sc_pkcs15_id)* id, sc_pkcs15_object** out_);
	int  sc_pkcs15_find_data_object_by_app_oid(sc_pkcs15_card* p15card, const(sc_object_id)* app_oid, sc_pkcs15_object** out_);
	int  sc_pkcs15_find_data_object_by_name(sc_pkcs15_card* p15card, const(char)* app_label, const(char)* label, sc_pkcs15_object** out_);
	void sc_pkcs15_free_data_object(sc_pkcs15_data* data_object);

	int  sc_pkcs15_read_certificate(sc_pkcs15_card* card, const(sc_pkcs15_cert_info)* info,
		int private_obj, sc_pkcs15_cert** cert);
	void sc_pkcs15_free_certificate(sc_pkcs15_cert* cert);
	int  sc_pkcs15_find_cert_by_id(sc_pkcs15_card* card, const sc_pkcs15_id* id, sc_pkcs15_object** out_);

	int  sc_pkcs15_get_name_from_dn(sc_context* ctx,
	                                const(ubyte)* dn, size_t dn_len,
	                                const(sc_object_id)* type,
	                                ubyte** name, size_t* name_len);
version(PATCH_LIBOPENSC_EXPORTS) {
version(OPENSC_VERSION_LATEST)
	int sc_pkcs15_map_usage(uint cert_usage, c_ulong algorithm,
	                        uint* pub_usage_ptr, uint* pr_usage_ptr,
	                        int allow_nonrepudiation);
else
    int sc_pkcs15_map_usage(uint cert_usage, int algorithm,
			                uint* pub_usage_ptr, uint* pr_usage_ptr,
			                int allow_nonrepudiation);
	int  sc_pkcs15_get_extension(sc_context* ctx,
                                 sc_pkcs15_cert* cert,
                                 const(sc_object_id)* type,
                                 ubyte** ext_val, size_t* ext_val_len,
                                 int* is_critical);

	int  sc_pkcs15_get_bitstring_extension(sc_context* ctx,
                                           sc_pkcs15_cert* cert,
                                           const(sc_object_id)* type,
                                           uint* value,
                                           int* is_critical);
}

version(PATCH_LIBOPENSC_EXPORTS) {
/* sc_pkcs15_create_cdf:  Creates a new certificate DF on a card pointed
 * by <card>.  Information about the file, such as the file ID, is read
 * from <file>.  <certs> has to be NULL-terminated. */
	int  sc_pkcs15_create_cdf(sc_pkcs15_card* card, sc_file* file, const(sc_pkcs15_cert_info)** certs);
}

	int  sc_pkcs15_find_prkey_by_id(sc_pkcs15_card* card, const(sc_pkcs15_id)* id, sc_pkcs15_object** out_);
	int  sc_pkcs15_find_prkey_by_id_usage(sc_pkcs15_card* card, const(sc_pkcs15_id)* id, uint usage, sc_pkcs15_object** out_);
	int  sc_pkcs15_find_prkey_by_reference(sc_pkcs15_card*, const(sc_path)*, int, sc_pkcs15_object**);
	int  sc_pkcs15_find_pubkey_by_id(sc_pkcs15_card* card, const(sc_pkcs15_id)* id, sc_pkcs15_object** out_);
	int  sc_pkcs15_find_skey_by_id(sc_pkcs15_card* card, const(sc_pkcs15_id)* id, sc_pkcs15_object** out_);

	int  sc_pkcs15_verify_pin(sc_pkcs15_card* card, sc_pkcs15_object* pin_obj, const(ubyte)* pincode, size_t pinlen);
	int  sc_pkcs15_verify_pin_with_session_pin(sc_pkcs15_card* p15card,
	                                           sc_pkcs15_object* pin_obj,
	                                           const(ubyte)* pincode, size_t pinlen,
	                                           const(ubyte)* sessionpin, size_t* sessionpinlen);

	int  sc_pkcs15_change_pin(sc_pkcs15_card* card, sc_pkcs15_object* pin_obj, const(ubyte)* oldpincode, size_t oldpinlen, const(ubyte)* newpincode, size_t newpinlen);
	int  sc_pkcs15_unblock_pin(sc_pkcs15_card* card, sc_pkcs15_object* pin_obj, const(ubyte)* puk, size_t puklen, const(ubyte)* newpin, size_t newpinlen);
	int  sc_pkcs15_get_pin_info(sc_pkcs15_card* card, sc_pkcs15_object* pin_obj);
	int  sc_pkcs15_find_pin_by_auth_id(sc_pkcs15_card* card, const(sc_pkcs15_id)* id, sc_pkcs15_object** out_);
	int  sc_pkcs15_find_pin_by_reference(sc_pkcs15_card* card, const(sc_path)* path, int reference, sc_pkcs15_object** out_);
version(PATCH_LIBOPENSC_EXPORTS)
	int  sc_pkcs15_find_pin_by_type_and_reference(sc_pkcs15_card* card, const(sc_path)* path, uint auth_method, int reference, sc_pkcs15_object** out_);
	int  sc_pkcs15_find_so_pin(sc_pkcs15_card* card, sc_pkcs15_object** out_);
	int  sc_pkcs15_find_pin_by_flags(sc_pkcs15_card* p15card, uint flags, uint mask, int* index, sc_pkcs15_object** out_);

version(PATCH_LIBOPENSC_EXPORTS) {
	void sc_pkcs15_pincache_add(sc_pkcs15_card*, sc_pkcs15_object*, const(ubyte)*, size_t);
	int  sc_pkcs15_pincache_revalidate(sc_pkcs15_card* p15card, const(sc_pkcs15_object)* obj);
}
	void sc_pkcs15_pincache_clear(sc_pkcs15_card* p15card);

version(PATCH_LIBOPENSC_EXPORTS)
	int  sc_pkcs15_encode_dir(sc_context* ctx, sc_pkcs15_card* card, ubyte** buf, size_t* buflen);
	int  sc_pkcs15_parse_tokeninfo(sc_context* ctx, sc_pkcs15_tokeninfo* ti, const(ubyte)* buf, size_t blen);
	int  sc_pkcs15_encode_tokeninfo(sc_context* ctx, sc_pkcs15_tokeninfo* ti, ubyte** buf, size_t* buflen);
	int  sc_pkcs15_encode_odf(sc_context* ctx, sc_pkcs15_card* card, ubyte** buf, size_t* buflen);
	int  sc_pkcs15_encode_df(sc_context* ctx, sc_pkcs15_card* p15card, sc_pkcs15_df* df, ubyte** buf, size_t* bufsize);
	int  sc_pkcs15_encode_cdf_entry(sc_context* ctx, const(sc_pkcs15_object)* obj, ubyte** buf, size_t* bufsize);
	int  sc_pkcs15_encode_prkdf_entry(sc_context* ctx, const(sc_pkcs15_object)* obj, ubyte** buf, size_t* bufsize);
	int  sc_pkcs15_encode_pukdf_entry(sc_context* ctx, const(sc_pkcs15_object)* obj, ubyte** buf, size_t* bufsize);
	int  sc_pkcs15_encode_skdf_entry(sc_context* ctx, const(sc_pkcs15_object)* obj, ubyte** buf, size_t* buflen);
	int  sc_pkcs15_encode_dodf_entry(sc_context* ctx, const(sc_pkcs15_object)* obj, ubyte** buf, size_t* bufsize);
	int  sc_pkcs15_encode_aodf_entry(sc_context* ctx, const(sc_pkcs15_object)* obj, ubyte** buf, size_t* bufsize);

	int  sc_pkcs15_parse_df(sc_pkcs15_card* p15card, sc_pkcs15_df* df);
version(PATCH_LIBOPENSC_EXPORTS)
	int sc_pkcs15_read_df(sc_pkcs15_card* p15card, sc_pkcs15_df* df);
	int sc_pkcs15_decode_cdf_entry(sc_pkcs15_card* p15card, sc_pkcs15_object* obj, const(ubyte)** buf, size_t* bufsize);
	int sc_pkcs15_decode_dodf_entry(sc_pkcs15_card* p15card, sc_pkcs15_object* obj, const(ubyte)** buf, size_t* bufsize);
	int sc_pkcs15_decode_aodf_entry(sc_pkcs15_card* p15card, sc_pkcs15_object* obj, const(ubyte)** buf, size_t* bufsize);
	int sc_pkcs15_decode_prkdf_entry(sc_pkcs15_card* p15card, sc_pkcs15_object* obj, const(ubyte)** buf, size_t* bufsize);
	int sc_pkcs15_decode_pukdf_entry(sc_pkcs15_card* p15card, sc_pkcs15_object* obj, const(ubyte)** buf, size_t* bufsize);
	int sc_pkcs15_decode_skdf_entry(sc_pkcs15_card* p15card, sc_pkcs15_object* obj, const(ubyte)** buf, size_t* bufsize);

	int sc_pkcs15_add_object(sc_pkcs15_card* p15card, sc_pkcs15_object* obj);
	void sc_pkcs15_remove_object(sc_pkcs15_card* p15card, sc_pkcs15_object* obj);
	int sc_pkcs15_add_df(sc_pkcs15_card*, uint, const(sc_path)*);

	int sc_pkcs15_add_unusedspace(sc_pkcs15_card* p15card, const(sc_path)* path, const(sc_pkcs15_id)* auth_id);
	int sc_pkcs15_parse_unusedspace(const(ubyte)* buf, size_t buflen, sc_pkcs15_card* card);
	int sc_pkcs15_encode_unusedspace(sc_context* ctx, sc_pkcs15_card* p15card, ubyte** buf, size_t* buflen);

	/* Deduce private key attributes from corresponding certificate */
	int sc_pkcs15_prkey_attrs_from_cert(sc_pkcs15_card*, sc_pkcs15_object*, sc_pkcs15_object**);

	void sc_pkcs15_free_prkey_info(sc_pkcs15_prkey_info* key);
	void sc_pkcs15_free_pubkey_info(sc_pkcs15_pubkey_info* key);
	void sc_pkcs15_free_cert_info(sc_pkcs15_cert_info* cert);
	void sc_pkcs15_free_data_info(sc_pkcs15_data_info* data);
	void sc_pkcs15_free_auth_info(sc_pkcs15_auth_info* auth_info);
	void sc_pkcs15_free_skey_info(sc_pkcs15_skey_info* key);
	void sc_pkcs15_free_object(sc_pkcs15_object* obj);

	/* Generic file i/o */
	int sc_pkcs15_read_file(sc_pkcs15_card* p15card, const(sc_path)* path, ubyte** buf, size_t* buflen, int private_data);

	/* Caching functions */
	int sc_pkcs15_read_cached_file(sc_pkcs15_card* p15card, const(sc_path)* path, ubyte** buf, size_t* bufsize);
	int sc_pkcs15_cache_file(sc_pkcs15_card* p15card, const(sc_path)* path, const(ubyte)* buf, size_t bufsize);

	/* PKCS #15 ID handling functions */
	int sc_pkcs15_compare_id(const(sc_pkcs15_id)* id1, const(sc_pkcs15_id)* id2);
	const(char)* sc_pkcs15_print_id(const(sc_pkcs15_id)* id);
	void sc_pkcs15_format_id(const(char)* id_in, sc_pkcs15_id* id_out);
	int sc_pkcs15_hex_string_to_id(const(char)* in_, sc_pkcs15_id* out_);
	int sc_der_copy(sc_pkcs15_der*, const(sc_pkcs15_der)*);
	int sc_pkcs15_get_object_id(const(sc_pkcs15_object)*, sc_pkcs15_id*);
	int sc_pkcs15_get_object_guid(sc_pkcs15_card*, const(sc_pkcs15_object)*, uint, ubyte*, size_t*);
	int sc_pkcs15_serialize_guid(ubyte*, size_t, uint, char*, size_t);
	int sc_encode_oid(sc_context*, sc_object_id*, ubyte**, size_t*);

	/* Get application by type: 'protected', 'generic' */
	sc_app_info* sc_pkcs15_get_application_by_type(sc_card*, char*);

	/* Prepend 'parent' to 'child' in case 'child' is a relative path */
	int sc_pkcs15_make_absolute_path(const(sc_path)* parent, sc_path* child);

version(PATCH_LIBOPENSC_EXPORTS) {
	/* Clean and free object content */
	void sc_pkcs15_free_object_content(sc_pkcs15_object*);

	/* Allocate and set object content */
	int sc_pkcs15_allocate_object_content(sc_context*, sc_pkcs15_object*, const(ubyte)*, size_t);

	/* find algorithm from card's supported algorithms by operation and mechanism */
	sc_supported_algo_info* sc_pkcs15_get_supported_algo(sc_pkcs15_card* card, uint operation, uint mechanism);

	/* find algorithm from card's supported algorithms by operation, mechanism and object_id */
	sc_supported_algo_info* sc_pkcs15_get_specific_supported_algo(sc_pkcs15_card*,
		uint operation, uint mechanism, const(sc_object_id)* algo_oid);

	int sc_pkcs15_add_supported_algo_ref(sc_pkcs15_object*, sc_supported_algo_info*);
}

	int sc_pkcs15_fix_ec_parameters(sc_context*, sc_ec_parameters*);

version(PATCH_LIBOPENSC_EXPORTS)
	/* Convert the OpenSSL key data type into the OpenSC key */
	int sc_pkcs15_convert_bignum(sc_pkcs15_bignum* dst, const(void)* bignum);
	int sc_pkcs15_convert_prkey(sc_pkcs15_prkey* key, void* evp_key);
	int sc_pkcs15_convert_pubkey(sc_pkcs15_pubkey* key, void* evp_key);

	/* Get 'LastUpdate' string */
	char* sc_pkcs15_get_lastupdate(sc_pkcs15_card* p15card);

version(PATCH_LIBOPENSC_EXPORTS)
	/* Allocate generalized time string */
	int sc_pkcs15_get_generalized_time(sc_context* ctx, char** out_);
} // extern(C)

/* New object search API.
 * More complex, but also more powerful.
 */
struct sc_pkcs15_search_key {
	uint                  class_mask;
	uint                  type;
	const(sc_pkcs15_id)*  id;
	const(sc_object_id)*  app_oid;
	const(sc_path)*       path;
	uint                  usage_mask, usage_value;
	uint                  flags_mask, flags_value;

	uint                  match_reference; // unsigned int match_reference : 1;  bit field declaration; only values 0 and 1 allowed
	int                   reference;
	const(char)*          app_label;
	const(char)*          label;
}
//alias sc_pkcs15_search_key_t = sc_pkcs15_search_key;

extern(C) int sc_pkcs15_search_objects(sc_pkcs15_card* p15card, sc_pkcs15_search_key* sk,
	sc_pkcs15_object** ret, size_t ret_size);

extern(C) {
	int sc_pkcs15_bind_synthetic(sc_pkcs15_card*);
	int sc_pkcs15_is_emulation_only(sc_card*);
	int sc_pkcs15emu_object_add(sc_pkcs15_card*, uint, const(sc_pkcs15_object)*, const(void)*);
	int sc_pkcs15emu_add_pin_obj(sc_pkcs15_card*, const(sc_pkcs15_object)*, const(sc_pkcs15_auth_info)*);
	int sc_pkcs15emu_add_rsa_prkey(sc_pkcs15_card*, const(sc_pkcs15_object)*, const(sc_pkcs15_prkey_info)*);
	int sc_pkcs15emu_add_rsa_pubkey(sc_pkcs15_card*, const(sc_pkcs15_object)*, const(sc_pkcs15_pubkey_info)*);
	int sc_pkcs15emu_add_ec_prkey(sc_pkcs15_card*, const(sc_pkcs15_object)*, const(sc_pkcs15_prkey_info)*);
	int sc_pkcs15emu_add_ec_pubkey(sc_pkcs15_card*, const(sc_pkcs15_object)*, const(sc_pkcs15_pubkey_info)*);
	int sc_pkcs15emu_add_eddsa_prkey(sc_pkcs15_card*, const(sc_pkcs15_object)*, const(sc_pkcs15_prkey_info)*);
    int sc_pkcs15emu_add_eddsa_pubkey(sc_pkcs15_card*, const(sc_pkcs15_object)*, const(sc_pkcs15_pubkey_info)*);
    int sc_pkcs15emu_add_xeddsa_prkey(sc_pkcs15_card*, const(sc_pkcs15_object)*, const(sc_pkcs15_prkey_info)*);
    int sc_pkcs15emu_add_xeddsa_pubkey(sc_pkcs15_card*, const(sc_pkcs15_object)*, const(sc_pkcs15_pubkey_info)*);
	int sc_pkcs15emu_add_x509_cert(sc_pkcs15_card*, const(sc_pkcs15_object)*, const(sc_pkcs15_cert_info)*);
	int sc_pkcs15emu_add_data_object(sc_pkcs15_card*, const(sc_pkcs15_object)*, const(sc_pkcs15_data_info)*);

/* added from exports (undocumented)*/
	void sc_pkcs15_remove_unusedspace(sc_pkcs15_card* p15card, sc_pkcs15_unusedspace* unusedspace);
} // extern(C)
