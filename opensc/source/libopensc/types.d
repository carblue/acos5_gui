/*
 * types.h: OpenSC general types
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/*
Written in the D programming language.
For git maintenance (ensure at least one congruent line with originating C header):
#define _OPENSC_TYPES_H

Content covered by this file is ALL of header C/libopensc/types.h
NO extern(C) functions are exported from "libopensc.[so|dll]" binary (checked OpenSC-0.17.0)
TODO: void toString NOT available for all structs, but has to be checked/enabled, NOT ALL? comments are retained from header
*/

module libopensc.types;

import core.stdc.config : c_ulong;
version(ENABLE_TOSTRING) {
//	import std.string : fromStringz;
	import std.format;
	import std.algorithm.comparison : clamp;
	import std.algorithm.searching : canFind, any;
	import std.traits : EnumMembers;
	import std.array : split;

	import mixin_templates_opensc;
}

import libopensc.iso7816;


template FreeEnumMembers(T) if (is(T == enum))
{
	mixin(()
	{
		string s;
		foreach (member; __traits(allMembers, T))
		{
			s ~= "enum T " ~ member ~ " = T." ~ member ~ ";\x0a";
		}
		return s;
	}
	());
}

/* various maximum values */
	alias SC_MAX_t = uint;
version(OPENSC_VERSION_LATEST) {
	enum : SC_MAX_t
	{
		SC_MAX_CARD_DRIVERS           = 48,
		SC_MAX_CARD_DRIVER_SNAME_SIZE = 16,
		SC_MAX_CARD_APPS              =  8,
		SC_MAX_APDU_BUFFER_SIZE       = 261, /* takes account of: CLA INS P1 P2 Lc [255 byte of data] Le */
		SC_MAX_APDU_DATA_SIZE         = 0xFF,
		SC_MAX_APDU_RESP_SIZE         = 0xFF+1,
		SC_MAX_EXT_APDU_BUFFER_SIZE   = 0x1_0002,
		SC_MAX_EXT_APDU_DATA_SIZE     = 0xFFFF,
		SC_MAX_EXT_APDU_RESP_SIZE     = 0xFFFF+1,
		SC_MAX_PIN_SIZE               = 0x100, /* OpenPGP card has 254 max */
		SC_MAX_ATR_SIZE               = 33,
		SC_MAX_UID_SIZE               = 10,
		SC_MAX_AID_SIZE               = 16,
		SC_MAX_AID_STRING_SIZE        = SC_MAX_AID_SIZE * 2 + 3,
		SC_MAX_IIN_SIZE               = 10,
		SC_MAX_OBJECT_ID_OCTETS       = 16,
		SC_MAX_PATH_SIZE              = 16,
		SC_MAX_PATH_STRING_SIZE       = SC_MAX_PATH_SIZE * 2 + 3,
		SC_MAX_SDO_ACLS               = 8,
		SC_MAX_CRTS_IN_SE             = 12,
		SC_MAX_SE_NUM                 = 8,

/* When changing this value, pay attention to the initialization of the ASN1
 * static variables that use this macro, like, for example,
 * 'c_asn1_supported_algorithms' in src/libopensc/pkcs15.c,
 * src/libopensc/pkcs15-prkey.c and src/libopensc/pkcs15-skey.c
 * `grep "src/libopensc/types.h SC_MAX_SUPPORTED_ALGORITHMS  defined as"'
 */
		SC_MAX_SUPPORTED_ALGORITHMS   = 16,
	}
}
else {
	enum : SC_MAX_t
	{
		SC_MAX_CARD_DRIVERS           = 48,
		SC_MAX_CARD_DRIVER_SNAME_SIZE = 16,
		SC_MAX_CARD_APPS              =  8,
		SC_MAX_APDU_BUFFER_SIZE       = 261, /* takes account of: CLA INS P1 P2 Lc [255 byte of data] Le */
		SC_MAX_APDU_DATA_SIZE         = 0xFF,
		SC_MAX_APDU_RESP_SIZE         = 0xFF+1,
		SC_MAX_EXT_APDU_BUFFER_SIZE   = 0x1_0002,
		SC_MAX_EXT_APDU_DATA_SIZE     = 0xFFFF,
		SC_MAX_EXT_APDU_RESP_SIZE     = 0xFFFF+1,
		SC_MAX_PIN_SIZE               = 0x100, /* OpenPGP card has 254 max */
		SC_MAX_ATR_SIZE               = 33,
		SC_MAX_UID_SIZE               = 10,
		SC_MAX_AID_SIZE               = 16,
		SC_MAX_AID_STRING_SIZE        = SC_MAX_AID_SIZE * 2 + 3,
		SC_MAX_IIN_SIZE               = 10,
		SC_MAX_OBJECT_ID_OCTETS       = 16,
		SC_MAX_PATH_SIZE              = 16,
		SC_MAX_PATH_STRING_SIZE       = SC_MAX_PATH_SIZE * 2 + 3,
		SC_MAX_SDO_ACLS               = 8,
		SC_MAX_CRTS_IN_SE             = 12,
		SC_MAX_SE_NUM                 = 8,

/* When changing this value, pay attention to the initialization of the ASN1
 * static variables that use this macro, like, for example,
 * 'c_asn1_supported_algorithms' in src/libopensc/pkcs15.c,
 * src/libopensc/pkcs15-prkey.c and src/libopensc/pkcs15-skey.c
 * `grep "src/libopensc/types.h SC_MAX_SUPPORTED_ALGORITHMS  defined as"'
 */
		SC_MAX_SUPPORTED_ALGORITHMS   = 8,
	}
}

	struct sc_lv_data {
		ubyte*  value;
		size_t  len;

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
/+ + /
			string[] pointersOfInterest = ["value",];
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1];
					string value_rep = format("%s", member);
					bool isDereferencable = (unqual_type[$-1]=='*' && unqual_type[0..$-1]!="void") && value_rep!="null";

					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");

					sink.formatValue(member, fmt);
//					sink(";  ");
//					sink(isDereferencable ? "YES": "NO");
					if (isDereferencable && canFind(pointersOfInterest, name_member)) {
						if (name_member=="value")
							sink(format("  [%(%#x, %)]", value[0..clamp(len,0,99)])); // 99 is an assumption of uppr limit
					}
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
/ + +/
			mixin(frame_OnePointerFormatx_noArray_noUnion!("value", "len", "99"));
		}
	} // struct sc_lv_data

	struct sc_tlv_data {
		uint    tag;
		ubyte*  value;
		size_t  len;

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
/+ + /
			string[] pointersOfInterest = ["value"];
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1];
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
					sink.formatValue(member, fmt);
					string value_rep = format("%s", member);
					sink(";  ");
					bool isDereferencable = (unqual_type[$-1]=='*' && unqual_type[0..$-1]!="void") && value_rep!="null";
					sink(isDereferencable ? "YES": "NO");
					if (isDereferencable && canFind(pointersOfInterest, name_member)) {
						if (name_member=="value")
							sink(format("  [%(%#x, %)]", value[0..clamp(len,0,99)])); // 99 is an assumption of uppr limit
					}
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
/ + +/
			mixin(frame_OnePointerFormatx_noArray_noUnion!("value", "len", "99"));
		}
	} // struct sc_tlv_data

	struct sc_object_id {
		int[SC_MAX_OBJECT_ID_OCTETS]  value;

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
					if (name_member=="value")
						sink(format("  [%(%#x, %)]", value));
					else
						sink.formatValue(member, fmt);
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
+/
			mixin(frame_noPointer_OneArrayFormatx_noUnion!("value", "SC_MAX_OBJECT_ID_OCTETS", "SC_MAX_OBJECT_ID_OCTETS"));
		} // void toString
	} // struct sc_object_id

	struct sc_aid {
		ubyte[SC_MAX_AID_SIZE]  value;
		size_t                  len;

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
					if (name_member=="value")
						sink(format("  [%(%#x, %)]", value[0..clamp(len,0,SC_MAX_AID_SIZE)]));
					else
						sink.formatValue(member, fmt);
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
+/
			mixin(frame_noPointer_OneArrayFormatx_noUnion!("value", "len", "SC_MAX_AID_SIZE"));
		} // void toString
	} // struct sc_aid

	struct sc_atr {
		ubyte[SC_MAX_ATR_SIZE]  value;
		size_t                  len;

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
					if (name_member=="value")
						sink(format("  [%(%#x, %)]", value[0..clamp(len,0,SC_MAX_ATR_SIZE)]));
					else
						sink.formatValue(member, fmt);
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
+/
			mixin(frame_noPointer_OneArrayFormatx_noUnion!("value", "len", "SC_MAX_ATR_SIZE"));
		}
	} // struct sc_atr

	struct sc_uid {
		ubyte[SC_MAX_UID_SIZE]  value;
		size_t                  len;

version(none)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{ mixin(frame_noPointer_OneArrayFormatx_noUnion!("value", "len", "SC_MAX_UID_SIZE")); }
	} // struct sc_uid

/* Issuer ID */
	struct sc_iid {
		ubyte[SC_MAX_IIN_SIZE]  value;
		size_t                  len;

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
					if (name_member=="value")
						sink(format("  [%(%#x, %)]", value[0..clamp(len,0,SC_MAX_IIN_SIZE)]));
					else
						sink.formatValue(member, fmt);
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
+/
			mixin(frame_noPointer_OneArrayFormatx_noUnion!("value", "len", "SC_MAX_IIN_SIZE"));
		}
	} // struct sc_iid

	struct sc_version {
		ubyte  hw_major;
		ubyte  hw_minor;
		ubyte  fw_major;
		ubyte  fw_minor;

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
		}
	} // struct sc_version

/* Discretionary ASN.1 data object */
	struct sc_ddo {
		sc_aid        aid;
		sc_iid        iid;
		sc_object_id  oid;
		size_t        len;
		ubyte*        value;

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
/+
			string[] pointersOfInterest = ["value"];
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1];
					string value_rep = format("%s", member);
					bool isDereferencable = (unqual_type[$-1]=='*' && unqual_type[0..$-1]!="void") && value_rep!="null";

					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
					sink.formatValue(member, fmt);
//					sink(";  ");
//					sink(isDereferencable ? "YES": "NO");
					if (isDereferencable && canFind(pointersOfInterest, name_member)) {
						if (name_member=="value")
							sink(format("  [%(%#x, %)]", value[0..clamp(len,0,99)])); // 99 is an assumption of uppr limit
					}
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
+/
			mixin(frame_OnePointerFormatx_noArray_noUnion!("value", "len", "99"));
		}
	} // struct sc_ddo

	enum SC_PATH_TYPE {
		SC_PATH_TYPE_FILE_ID       = 0,
		SC_PATH_TYPE_DF_NAME       = 1,
		SC_PATH_TYPE_PATH          = 2,
		/* path of a file containing EnvelopedData objects */
		SC_PATH_TYPE_PATH_PROT     = 3,
		SC_PATH_TYPE_FROM_CURRENT  = 4,
		SC_PATH_TYPE_PARENT        = 5,
	}
	mixin FreeEnumMembers!SC_PATH_TYPE;

	struct sc_path {
		ubyte[SC_MAX_PATH_SIZE]  value;
		size_t                   len;

		/* The next two fields are used in PKCS15, where
		 * a Path object can reference a portion of a file -
		 * count octets starting at offset index.
		 */
		int                      index;
		int                      count;// = -1;

		int                      type; /* SC_PATH_TYPE */

		sc_aid                   aid;

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
					if (name_member=="value")
						sink(format("  [%(%#x, %)]", value[0..clamp(len,0,SC_MAX_PATH_SIZE)]));
					else
						sink.formatValue(member, fmt);
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
+/
			mixin(frame_noPointer_OneArrayFormatx_noUnion!("value", "len", "SC_MAX_PATH_SIZE"));
		}
	} // struct sc_path

/* Control reference template */
	struct sc_crt {
		uint     tag;
		uint     usage; /* Usage Qualifier Byte */
		uint     algo;  /* Algorithm ID */
		uint[8]  refs;  /* Security Object References */

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
/+ +/
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1];
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
					if      (name_member=="tag")
						sink(format("  %02X", tag));
					else if (name_member=="usage")
						sink(format("  %02X", usage));
					else if (name_member=="algo")
						sink(format("  %02X", algo));
					else if (name_member=="refs")
						sink(format("  [%(%#x, %)]", refs));
					else
						sink.formatValue(member, fmt);
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
/+ +/
//			mixin(frame_noPointer_OneArrayFormatx_noUnion!("refs", "8", "8"));
		}
	} // struct sc_crt

	/* Access Control flags (sc_pkcs15_auth_info.auth_method) */
	enum SC_AC : uint {
		SC_AC_NONE             = 0x0000_0000,  /* operation always/unconditionally allowed */
		SC_AC_CHV              = 0x0000_0001,  /* Card Holder Verif. */
		SC_AC_TERM             = 0x0000_0002,  /* Terminal auth. */
		SC_AC_PRO              = 0x0000_0004,  /* Secure Messaging */
		SC_AC_AUT              = 0x0000_0008,  /* Key auth. */
		SC_AC_SYMBOLIC         = 0x0000_0010,  /* internal use only */
		SC_AC_SEN              = 0x0000_0020,  /* Security Environment. */
		SC_AC_SCB              = 0x0000_0040,  /* IAS/ECC SCB byte. */
		SC_AC_IDA              = 0x0000_0080,  /* PKCS#15 authentication ID */
		SC_AC_SESSION          = 0x0000_0100,  /* Session PIN */
		SC_AC_CONTEXT_SPECIFIC = 0x0000_0200,  /* Context specific login */

		SC_AC_UNKNOWN          = 0xFFFF_FFFE,
		SC_AC_NEVER            = 0xFFFF_FFFF,  /* operation NOT allowed */
	}
	mixin FreeEnumMembers!SC_AC;

	enum SC_AC_OP : ubyte {
		SC_AC_OP_SELECT                 = 0,
		SC_AC_OP_LOCK                   = 1,   // Irreversibly block a file, called TERMINATE by acos
		SC_AC_OP_DELETE                 = 2,   // Delete a uniquely identifiable object (such as a file, application or key).
		SC_AC_OP_CREATE                 = 3,
		SC_AC_OP_REHABILITATE           = 4,   // INS 44: Unblock a file.           ACOS5: Activate   File
		SC_AC_OP_INVALIDATE             = 5,   // INS 04: Reversibly block a file.  ACOS5: Deactivate File
		SC_AC_OP_LIST_FILES             = 6,
		SC_AC_OP_CRYPTO                 = 7,
		SC_AC_OP_DELETE_SELF            = 8,   // ATTENTION: how it's used in opensc-tool/opensc-explorer and how acos differentiates this from SC_AC_OP_DELETE
		SC_AC_OP_PSO_DECRYPT            = 9,   // currently used rarely(authentic, iasecc, oberthur); profile.c: "PSO-DECRYPT"
		SC_AC_OP_PSO_ENCRYPT            = 10,  // currently used rarely(oberthur); profile.c: NO ENTRY !
		SC_AC_OP_PSO_COMPUTE_SIGNATURE  = 11,  // currently used rarely(authentic, iasecc, oberthur); profile.c: "PSO-COMPUTE-SIGNATURE"
		SC_AC_OP_PSO_VERIFY_SIGNATURE   = 12,  // currently used rarely(oberthur); profile.c: NO ENTRY !
		SC_AC_OP_PSO_COMPUTE_CHECKSUM   = 13,  // currently used rarely(oberthur); profile.c: NO ENTRY !
		SC_AC_OP_PSO_VERIFY_CHECKSUM    = 14,  // currently used rarely(oberthur); profile.c: NO ENTRY !
		SC_AC_OP_INTERNAL_AUTHENTICATE  = 15,  // currently used rarely(authentic, iasecc); profile.c: "INTERNAL-AUTHENTICATE"
		SC_AC_OP_EXTERNAL_AUTHENTICATE  = 16,  // currently used rarely(oberthur, iasecc); profile.c: NO ENTRY !
		SC_AC_OP_PIN_DEFINE             = 17,  // currently used rarely(oberthur); profile.c: "PIN-DEFINE"
		SC_AC_OP_PIN_CHANGE             = 18,  // currently used rarely(oberthur); profile.c: "PIN-CHANGE"
		SC_AC_OP_PIN_RESET              = 19,  // currently used rarely(oberthur, rtecp); profile.c: "PIN-RESET"
		SC_AC_OP_ACTIVATE               = 20,  // duplicate/synonym for SC_AC_OP_REHABILITATE  currently used rarely
		SC_AC_OP_DEACTIVATE             = 21,  // duplicate/synonym for SC_AC_OP_INVALIDATE    currently used rarely
		SC_AC_OP_READ                   = 22,  // commonly used
		SC_AC_OP_UPDATE                 = 23,  // commonly used
		SC_AC_OP_WRITE                  = 24,  // commonly used
		SC_AC_OP_RESIZE                 = 25,  // currently used rarely(authentic)
		SC_AC_OP_GENERATE               = 26,  // currently used rarely(3 cards)
		SC_AC_OP_CREATE_EF              = 27,  // currently used rarely(isoApplet, acos5); profile.c: "CREATE-EF"
		SC_AC_OP_CREATE_DF              = 28,  // currently used rarely(isoApplet, acos5); profile.c: "CREATE-DF"
		SC_AC_OP_ADMIN                  = 29,  // currently unused
		SC_AC_OP_PIN_USE                = 30,  // currently unused; profile.c: "PIN-USE"
		SC_MAX_AC_OPS                   = 31,
	}
	mixin FreeEnumMembers!SC_AC_OP;

	/*deprecated("SC_AC_OP_DELETE should be used instead")*/
	enum SC_AC_OP_ERASE               = SC_AC_OP.SC_AC_OP_DELETE;

	enum SC_AC_KEY_REF_NONE           = 0xFFFF_FFFF;

	struct sc_acl_entry {
		uint                       method;  // .init == SC_AC_NONE
		uint                       key_ref;
version(OPENSC_VERSION_LATEST) {}
else {
		sc_crt[SC_MAX_CRTS_IN_SE]  crts;
}
		sc_acl_entry*              next;

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
			string[] pointersOfInterest = [
				"next",
			];
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					mixin(head_foreach_Pointer_noSinkMember);
					if (name_member=="crts") {
/*
						sink("[\n");
						foreach (sub_member; crts)
							if (sub_member.tag==0 && sub_member.usage==0 && sub_member.algo==0 && !any(sub_member.refs[]))
								continue; // omit that case
							else
								sink.formatValue(sub_member, fmt);
						sink("]");
*/
						sink.formatValue(crts.ptr, fmt);
					}
/*
					else if (name_member=="next" && next!=null && canFind(pointersOfInterest, name_member)) {
						sink("0x");
						sink.formatValue(member, fmt);
						if      (next==cast(sc_acl_entry*)1)
							sink("  SC_AC_NEVER\n");
						else if (next==cast(sc_acl_entry*)2) { // omit output for this, NOT INTERESTING
							sink("  SC_AC_NONE\n");
						}
						else if (next==cast(sc_acl_entry*)3)
							sink("  SC_AC_UNKNOWN\n");
						else if (next>cast(sc_acl_entry*)10000)
							sink.formatValue(*next, fmt);
					}
*/
					else {
						if (isDereferencable)
							sink("0x");
						sink.formatValue(member, fmt);
					}
					sink("\n");
				}
				sink("}\n");

				if (next && canFind(pointersOfInterest, "next"))
					sink.formatValue(*next, fmt);
			}
			catch (Exception e) { /* todo: handle exception */ }
		} // void toString
	} // struct sc_acl_entry

	enum SC_FILE_TYPE
	{
		SC_FILE_TYPE_UNKNOWN = 0,
		SC_FILE_TYPE_DF = 4,
		SC_FILE_TYPE_INTERNAL_EF = 3,
//	SC_FILE_TYPE_INTERNAL_SE_EF = 7,
		SC_FILE_TYPE_WORKING_EF = 1,
		SC_FILE_TYPE_BSO = 16, // BSO (Base Security Object) BSO contains data that must never go out from the card, but are essential for cryptographic operations, like PINs or Private Keys
	}
	mixin FreeEnumMembers!SC_FILE_TYPE;

	enum SC_FILE_EF
	{
		SC_FILE_EF_UNKNOWN = 0,
		SC_FILE_EF_TRANSPARENT = ISO7816_FILE_TYPE_TRANSPARENT_EF, //1,
		SC_FILE_EF_LINEAR_FIXED = 2,
		SC_FILE_EF_LINEAR_FIXED_TLV = 3,
		SC_FILE_EF_LINEAR_VARIABLE = 4,
		SC_FILE_EF_LINEAR_VARIABLE_TLV = 5,
		SC_FILE_EF_CYCLIC = 6,
		SC_FILE_EF_CYCLIC_TLV = 7,
	}
	mixin FreeEnumMembers!SC_FILE_EF;

	enum
	{
		SC_FILE_STATUS_ACTIVATED = 0,
		SC_FILE_STATUS_INVALIDATED = 1,
		SC_FILE_STATUS_CREATION = 2,
	}

	struct sc_file {
		sc_path    path;
		ubyte[16]  name;    /* DF name */
		size_t     namelen; /* length of DF name */
		uint       type;         /* values see enum SC_FILE_TYPE */ /* See constant values defined above */
		uint       ef_structure; /* values see enum SC_FILE_EF   */
		uint       status;       /* Life Cycle status Integer LCSI */
		uint       shareable;    /* true(1), false(0) according to ISO 7816-4:2005 Table 14 */ /* ACOS5: always no */
		size_t     size;         /* Size of file (in bytes) */
		int        id;           /* file identifier (2 bytes) */
		int        sid;          /* short EF identifier (1 byte) */ /*ACOS5: 1 byte  Short File Identifier (SFI) */
		sc_acl_entry*[SC_MAX_AC_OPS] acl; /* Access Control List */

		size_t     record_length; /* max. length in case of record-oriented EF */
		size_t     record_count;  /* Valid, if not transparent EF or DF */

		ubyte*     sec_attr;      /* security data in proprietary format. tag '86' */ /*  Security Attribute Compact (SAC) tag '8C' and? Security Attribute Extended SAE  tag 'AB' */
		size_t     sec_attr_len;
		ubyte*     prop_attr;     /* proprietary information. tag '85'*/
		size_t     prop_attr_len;
		ubyte*     type_attr;     /* file descriptor data. tag '82'. replaces the file's type information (DF, EF, ...) */
		size_t     type_attr_len;
		ubyte*     encoded_content;     /* file's content encoded to be used in the file creation command */
		size_t     encoded_content_len; /* size of file's encoded content in bytes */
		uint       magic;

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
			string[] pointersOfInterest = [
				"sec_attr",
//				"prop_attr",
				"type_attr",
				"encoded_content",
			];
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					mixin(head_foreach_Pointer_noSinkMember);
					if (name_member=="name")
						sink(format("  [%(%#x, %)]", name[0..clamp(namelen,0,16)]));
					else if (name_member=="acl") {
						sink(format("  [%(%#x, %)]\n",member));
						sink("[\n");
						string[] E = split(EnumMembers!SC_AC_OP.stringof[6..$], ", "); // EnumMembers!SC_AC_OP.stringof;
						foreach (j, ref sub_member; acl) {
//							string name_sub_member = E[j];
							sink(E[j] ~ " : ");
							if (sub_member is null)
									sink("  null\n");
							else { // sub_member !is null
								if      (sub_member==cast(sc_acl_entry*)1)
									sink("  SC_AC_NEVER\n");
//									sink.formatValue(sc_acl_entry(SC_AC.SC_AC_NEVER,   SC_AC_KEY_REF_NONE), fmt);
								else if (sub_member==cast(sc_acl_entry*)2) { // omit output for this, NOT INTERESTING
									sink("  SC_AC_NONE\n");
//									sink.formatValue(sc_acl_entry(SC_AC.SC_AC_NONE,    SC_AC_KEY_REF_NONE), fmt);
								}
								else if (sub_member==cast(sc_acl_entry*)3)
									sink("  SC_AC_UNKNOWN\n");
//									sink.formatValue(sc_acl_entry(SC_AC.SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE), fmt);
//								else if (sub_member>cast(sc_acl_entry*)10000)
//									sink.formatValue(*sub_member, fmt);
								else
//									sink("  do_that_later\n");
									sink.formatValue(*sub_member, fmt);
							}
						} // foreach
						sink("]\n");
					}
					else {
						if (isDereferencable)
							sink("0x");
						sink.formatValue(member, fmt);
					}

					if (isDereferencable && canFind(pointersOfInterest, name_member)) {
						if      (name_member=="sec_attr")
							sink(format("  [%(%#x, %)]", sec_attr[0..clamp(sec_attr_len,0,42)])); // 32(maxSAE)+8(maxSAC)+2
						else if (name_member=="prop_attr")
							sink(format("  [%(%#x, %)]", prop_attr[0..clamp(prop_attr_len,0,99)])); // 99 is an assumption of uppr limit
						else if (name_member=="type_attr")
							sink(format("  [%(%#x, %)]", type_attr[0..clamp(type_attr_len,0,99)])); // 99 is an assumption of uppr limit
						else if (name_member=="encoded_content")
							sink(format("  [%(%#x, %)]", encoded_content[0..clamp(encoded_content_len,0,99)])); // 99 is an assumption of uppr limit
					}
/+ +/
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { sink("}}}}}}}}}}\n");/* todo: handle exception */ }
		} // void toString
	} // struct sc_file

	enum : ubyte
	{
		SC_APDU_CASE_NONE = 0,
		SC_APDU_CASE_1 = 1,
		SC_APDU_CASE_2_SHORT = 2,
		SC_APDU_CASE_3_SHORT = 3,
		SC_APDU_CASE_4_SHORT = 4,
		SC_APDU_SHORT_MASK = 15,
		SC_APDU_EXT = 16,
		SC_APDU_CASE_2_EXT = SC_APDU_CASE_2_SHORT | SC_APDU_EXT,
		SC_APDU_CASE_3_EXT = SC_APDU_CASE_3_SHORT | SC_APDU_EXT,
		SC_APDU_CASE_4_EXT = SC_APDU_CASE_4_SHORT | SC_APDU_EXT,
		SC_APDU_CASE_2 = 34,
		SC_APDU_CASE_3 = 35,
		SC_APDU_CASE_4 = 36,
	}

	enum /* SC_APDU_FLAGS */ : c_ulong {
		/* use command chaining if the Lc value is greater than normally allowed */
		SC_APDU_FLAGS_CHAINING     = 0x0000_0001UL,
		/* do not automatically call GET RESPONSE to read all available data */
		SC_APDU_FLAGS_NO_GET_RESP  = 0x0000_0002UL,
		/* do not automatically try a re-transmit with a new length if the card
		 * returns 0x6Cxx (wrong length)
		 */
		SC_APDU_FLAGS_NO_RETRY_WL  = 0x0000_0004UL,
		/* APDU is from Secure Messaging  */
		SC_APDU_FLAGS_NO_SM        = 0x0000_0008UL,
	}

	enum /* SC_APDU_ALLOCATE_FLAG */ : uint { // currently unused
		SC_APDU_ALLOCATE_FLAG      = 1,
		SC_APDU_ALLOCATE_FLAG_DATA = 2,
		SC_APDU_ALLOCATE_FLAG_RESP = 4,
	}

	struct sc_apdu {
		int            cse;     /* APDU case, SC_APDU_CASE_*  */
		ubyte          cla;     /* CLA byte */
		ubyte          ins;     /* INS byte */
		ubyte          p1;      /* P1  byte */
		ubyte          p2;      /* P2  byte */
		size_t         lc;      /* Lc  byte */
		size_t         le;      /* Le  byte */
		const(ubyte)*  data;    /* S-APDU data */
		size_t         datalen; /* length of data in S-APDU */
		ubyte*         resp;    /* R-APDU data buffer */
		size_t         resplen; /* in: size of R-APDU buffer, out: length of data returned in R-APDU */

		ubyte          control; /* Set if APDU should go to the reader */
		uint           allocation_flags; /* SC_APDU_ALLOCATE_FLAG */

		uint           sw1;     /* Status words returned in R-APDU */
		uint           sw2;
		ubyte[8]       mac;     /* used in SM: MAC of response */
		size_t         mac_len; /* used in SM: length ? of data in mac */

		c_ulong        flags;   /* SC_APDU_FLAGS;  note the different kind of flags of struct sc_remote_apdu: SC_REMOTE_APDU_FLAG */
		sc_apdu*       next;

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
			string[] pointersOfInterest = [
				"data",
				"resp",
				"next", // sameTypePointingMember
			];
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					mixin(head_foreach_Pointer_noSinkMember);
					if (canFind(["cla", "ins", "p1", "p2", "sw1", "sw2"], name_member))
						sink(format("0x%02X", member));
					else if (name_member=="mac")
						sink(format("  0x [%(%02x %)]", mac[0..clamp(mac_len,0,8)]));
					else {
						if (isDereferencable)
							sink("0x");
						sink.formatValue(member, fmt);
					}
					if (isDereferencable && canFind(pointersOfInterest, name_member)) {
						if      (name_member=="data")
							sink(format("  0x [%(%02x %)]", data[0..clamp(datalen,0,SC_MAX_APDU_BUFFER_SIZE)]));
						else if (name_member=="resp")
							sink(format("  0x [%(%02x %)]", resp[0..clamp(resplen,0,SC_MAX_APDU_BUFFER_SIZE)]));
					}
					sink("\n");
				}
				sink("}\n");

				if (next && canFind(pointersOfInterest, "next"))
					sink.formatValue(*next, fmt);
			}
			catch (Exception e) { /* todo: handle exception */ }
		} // void toString
	} // struct sc_apdu
//	alias sc_apdu_t = sc_apdu;

	enum
	{
		SC_CPLC_TAG = 40831,
		SC_CPLC_DER_SIZE = 45,
	}

	struct sc_cplc
	{
		ubyte[2] ic_fabricator;
		ubyte[2] ic_type;
		ubyte[6] os_data;
		ubyte[2] ic_date;
		ubyte[4] ic_serial;
		ubyte[2] ic_batch_id;
		ubyte[4] ic_module_data;
		ubyte[2] icc_manufacturer;
		ubyte[2] ic_embed_date;
		ubyte[6] pre_perso_data;
		ubyte[6] personalizer_data;
		ubyte[SC_CPLC_DER_SIZE] value;
		size_t len;
	}

	struct sc_iin
	{
		ubyte mii;
		uint country;
		c_ulong issuer_id;

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
		}
	} // struct sc_iin

	enum SC_MAX_SERIALNR = 32;

	struct sc_serial_number
	{
		ubyte[SC_MAX_SERIALNR] value;
		size_t len;
		sc_iin iin;

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
					if (name_member=="value")
						sink(format("  [%(%#x, %)]", value[0..clamp(len,0,SC_MAX_SERIALNR)]));
					else
						sink.formatValue(member, fmt);
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
+/
			mixin(frame_noPointer_OneArrayFormatx_noUnion!("value", "len", "SC_MAX_SERIALNR"));
		}
	} // struct sc_serial_number

	enum /* SC_REMOTE_APDU_FLAG */ : uint {
		SC_REMOTE_APDU_FLAG_NOT_FATAL     = 1,
		SC_REMOTE_APDU_FLAG_RETURN_ANSWER = 2,
	}

	struct sc_remote_apdu { // .sizeof:  1168
		ubyte[2*SC_MAX_APDU_BUFFER_SIZE] sbuf;
		ubyte[2*SC_MAX_APDU_BUFFER_SIZE] rbuf;
		sc_apdu                          apdu;   /* including SC_APDU_FLAGS and SC_APDU_ALLOCATE_FLAG */
		uint                             flags;  /* SC_REMOTE_APDU_FLAG */
		sc_remote_apdu*                  next;   // sameTypePointingMember
	}

/**
 * @struct sc_remote_data
 * Frame for the list of the @c sc_remote_apdu data with
 * the handlers to allocate and free.
 */
	struct sc_remote_data {
		sc_remote_apdu*  data;
		int              length;

		/**
		 * Handler to allocate a new @c sc_remote_apdu data and add it to the list.
		 * @param rdata Self pointer to the @c sc_remote_data
		 * @param out Pointer to newle allocated member
		 */
		extern(C) @nogc nothrow pure @trusted  int  function(scope sc_remote_data* rdata, scope sc_remote_apdu** out_) alloc;
		/**
		 * Handler to free the list of @c sc_remote_apdu data
		 * @param rdata Self pointer to the @c sc_remote_data
		 */
		extern(C) @nogc nothrow pure @trusted  void function(scope sc_remote_data* rdata) free;
	}
