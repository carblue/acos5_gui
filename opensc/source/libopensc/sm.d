/*
 * sm.h: Support of Secure Messaging
 *
 * Copyright (C) 2010  Viktor Tarasov <vtarasov@opentrust.com>
 *                      OpenTrust <www.opentrust.com>
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
#define _SM_H

Content covered by this file is ALL of header C/libopensc/sm.h
??? ALL extern(C) functions are exported from "libopensc.[so|dll]" binary (checked OpenSC-0.17.0)
??? TODO: void toString covers ALL! structs, but has to be checked/enabled, ALL! comments are retained from header
*/
// Functions within struct sm_module_operations exported from "libsmm-local.*",
// all 4 other extern(C) functions exported from "libopensc.*"

module libopensc.sm;

enum SM_SMALL_CHALLENGE_LEN = 8;

version(ENABLE_SM)
{
	import core.stdc.config : c_ulong;
	version(ENABLE_TOSTRING) {
		import std.string : fromStringz, indexOf, CaseSensitive;
		import std.typecons : Flag, Yes, No;
		import std.format;
		import std.algorithm.comparison : clamp;
		import std.algorithm.searching : canFind;

		import mixin_templates_opensc;
}

	import libopensc.errors;
	import libopensc.types;
	import libopensc.opensc : sc_card, sc_context;

	enum SHA_DIGEST_LENGTH    = 20;
	enum SHA1_DIGEST_LENGTH   = 20;
	enum SHA256_DIGEST_LENGTH = 32;

	enum SM_TYPE : uint {
		SM_TYPE_GP_SCP01 = 0x100,
		SM_TYPE_CWA14890 = 0x400,
		SM_TYPE_DH_RSA   = 0x500,
	}
	mixin FreeEnumMembers!SM_TYPE;

	enum SM_MODE : uint {
		/** don't use SM */
		SM_MODE_NONE     = 0x0,
		/** let the card driver decide when to use SM, possibly based on the card's ACLs */
		SM_MODE_ACL      = 0x100,
		/** use SM for all commands */
		SM_MODE_TRANSMIT = 0x200,
	}
	mixin FreeEnumMembers!SM_MODE;

	enum SM_CMD : uint {
		SM_CMD_INITIALIZE            = 0x10,
		SM_CMD_MUTUAL_AUTHENTICATION = 0x20,

		SM_CMD_RSA                   = 0x100,
		SM_CMD_RSA_GENERATE          = 257,    // ACOS5-64v2.00: YES
		SM_CMD_RSA_UPDATE            = 258,    // ACOS5-64v2.00: YES
		SM_CMD_RSA_READ_PUBLIC       = 259,    // ACOS5-64v2.00: YES

		SM_CMD_FILE                  = 512,
		SM_CMD_FILE_READ             = 513,    // ACOS5-64v2.00: YES
		SM_CMD_FILE_UPDATE           = 514,    // ACOS5-64v2.00: YES
		SM_CMD_FILE_CREATE           = 515,    // ACOS5-64v2.00: YES
		SM_CMD_FILE_DELETE           = 516,
		SM_CMD_FILE_ERASE            = 517,    // ACOS5-64v2.00: YES

		SM_CMD_PIN                   = 768,
		SM_CMD_PIN_VERIFY            = 769,
		SM_CMD_PIN_RESET             = 770,
		SM_CMD_PIN_SET_PIN           = 771,

		SM_CMD_PSO                   = 1024,
		SM_CMD_PSO_DST               = 1025,

		SM_CMD_APDU                  = 1280,
		SM_CMD_APDU_TRANSMIT         = 1281,
		SM_CMD_APDU_RAW              = 1282,

		SM_CMD_APPLET                = 1536,
		SM_CMD_APPLET_DELETE         = 1537,
		SM_CMD_APPLET_LOAD           = 1538,
		SM_CMD_APPLET_INSTALL        = 1539,

		SM_CMD_EXTERNAL_AUTH         = 1792,
		SM_CMD_EXTERNAL_AUTH_INIT    = 1793,
		SM_CMD_EXTERNAL_AUTH_CHALLENGE = 1794,
		SM_CMD_EXTERNAL_AUTH_DOIT    = 1795,

		SM_CMD_SDO_UPDATE            = 2048,
		SM_CMD_FINALIZE              = 2304,
	}
	mixin FreeEnumMembers!SM_CMD;

	enum SM_RESPONSE_CONTEXT_TAG      = 0xA1;
	enum SM_RESPONSE_CONTEXT_DATA_TAG = 0xA2;
	enum SM_MAX_DATA_SIZE             = 0xE0; // 224;
//enum SM_SMALL_CHALLENGE_LEN = 8; // it's positioned in the beginning now, outside of version (ENABLE_SM)

	enum SM_GP_SECURITY_NO  = 0x00;
	enum SM_GP_SECURITY_MAC = 0x01;
	enum SM_GP_SECURITY_ENC = 0x03;

	/* Global Platform (SCP01) data types */
	/*
	 * @struct sm_type_params_gp
	 *	Global Platform SM channel parameters
	 */
	struct sm_type_params_gp {
		uint level;
		uint index;
		uint version_;
		sc_cplc cplc;
	}

	/*
	 * @struct sm_gp_keyset
	 *	Global Platform keyset:
	 *	- version, index;
	 *	- keyset presented in three parts: 'ENC', 'MAC' and 'KEK';
	 *	- keyset presented in continuous manner - raw or 'to be diversified'.
	 */
	struct sm_gp_keyset {
		int version_;
		int index;
		ubyte[16] enc;
		ubyte[16] mac;
		ubyte[16] kek;
		ubyte[48] kmc;
		uint kmc_len;
	}

	/*
	 * @struct sm_gp_session
	 *	Global Platform SM session data
	 */
	struct sm_gp_session {
		sm_gp_keyset gp_keyset;
		sm_type_params_gp params;
		ubyte[SM_SMALL_CHALLENGE_LEN] host_challenge;
		ubyte[SM_SMALL_CHALLENGE_LEN] card_challenge;
		ubyte* session_enc;
		ubyte* session_mac;
		ubyte* session_kek;
		ubyte[8] mac_icv;
	} // sm_gp_session.sizeof : 272

	/* CWA, IAS/ECC data types */

	/*
	 * @struct sm_type_params_cwa
	 */
	struct sm_type_params_cwa {
		sc_crt crt_at;

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{ mixin(frame_noPointer_noArray_noUnion); }
	} // sm_type_params_cwa

	/*
	 * @struct sm_cwa_keyset
	 *	CWA keyset:
	 *	- SDO reference;
	 *	- 'ENC' and 'MAC' 3DES keys.
	 */
	struct sm_cwa_keyset {
		uint sdo_reference; // sm_cwa_config_get_keyset(struct sc_context *ctx, struct sm_info *sm_info) :	cwa_keyset->sdo_reference = crt_at->refs[0];
		ubyte[16] enc;
		ubyte[16] mac;

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1];
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
					if (name_member=="enc" || name_member=="mac")
						sink(format("  0x [%(%02x %)]", member));
					else
						sink.formatValue(member, fmt);
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception t) { /* todo: handle exception */ }
		}
	} // struct sm_cwa_keyset

	/*
	 * @struct sm_cwa_token_data
	 *	CWA token data:
	 *	- serial;
	 *	- 'small' random;
	 *	- 'big' random.
	 */
	struct sm_cwa_token_data {
		ubyte[8]  sn;
		ubyte[8]  rnd;
		ubyte[32] k;

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1];
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
					sink(format("  0x [%(%02x %)]", member));
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception t) { /* todo: handle exception */ }
		}
	} // sm_cwa_token_data

	/*
	 * @struct sm_cwa_session
	 *	CWA working SM session data:
	 *	- ICC and IFD token data;
	 *	- ENC and MAC session keys;
	 *	- SSC (SM Sequence Counter);
	 *	- 'mutual authentication' data.
	 */
	struct sm_cwa_session {
		sm_cwa_keyset                 cwa_keyset;
		sm_type_params_cwa            params;
		sm_cwa_token_data             icc; // card; Integrated Circuit(s) Card
		sm_cwa_token_data             ifd; // host; Interface Device
		ubyte[16]                     session_enc;
		ubyte[16]                     session_mac;
		ubyte[8]                      ssc;
		ubyte[SM_SMALL_CHALLENGE_LEN] host_challenge;
		ubyte[SM_SMALL_CHALLENGE_LEN] card_challenge;
		ubyte[72]                     mdata;
		size_t                        mdata_len;

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
			string[] ubyteArrays_SameHandling = [
				"session_enc",
				"session_mac",
				"ssc",
				"host_challenge",
				"card_challenge",
			];
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1];
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
					if (canFind(ubyteArrays_SameHandling, name_member))
						sink(format("  0x [%(%02x %)]", member));
					else if (name_member=="mdata")
						sink(format("  0x [%(%02x %)]", mdata[0..clamp(mdata_len,0,72)]));
					else
						sink.formatValue(member, fmt);
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception t) { /* todo: handle exception */ }
		}
	} // struct sm_cwa_session  sm_cwa_session.sizeof: 312

	/*
	 * @struct sm_dh_session
	 *	DH SM session data:
	 */
	struct sm_dh_session {
		sc_tlv_data g;
		sc_tlv_data N;
		sc_tlv_data ifd_p;
		sc_tlv_data ifd_y;
		sc_tlv_data icc_p;
		sc_tlv_data shared_secret;
		ubyte[16] session_enc;
		ubyte[16] session_mac;
		ubyte[32] card_challenge;
		ubyte[8] ssc;
	} // sm_dh_session.sizeof : 216

	/*
	 * @struct sc_info is the
	 *	placehold for the secure messaging working data:
	 *	- SM type;
	 *	- SM session state;
	 *	- command to execute by external SM module;
	 *	- data related to the current card context.
	 */
	struct sm_info {
		char[64]          config_section;
		uint              card_type;
		uint              cmd;       /* SM_CMD */
		void*             cmd_data;  /* typically a pointer to a command specific data structure, e.g. for pin related commandss: sc_pin_cmd_data* */
		uint              sm_type;   /* SM_TYPE */

		union anonymous {
			sm_gp_session   gp;
			sm_cwa_session  cwa;
			sm_dh_session   dh;

version(ENABLE_TOSTRING)
			void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
			{
				try {
					sink("\n{\n");
					foreach (i, ref member; this.tupleof) {
						string name_member = typeof(this).tupleof[i].stringof;
version(ENABLE_TOSTRING_SM_GP)
						if (name_member!="gp")  continue;
version(ENABLE_TOSTRING_SM_CWA)
						if (name_member!="cwa")  continue;
version(ENABLE_TOSTRING_SM_DH)
						if (name_member!="dh")  continue;
						string unqual_type = typeof(member).stringof[6..$-1];
						sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
						sink.formatValue(member, fmt);
						sink("\n");
					}
					sink("}\n");
				}
				catch (Exception t) { /* todo: handle exception */ }
			} // void toString
		} // union anonymous
		anonymous         session;

		sc_serial_number  serialnr;
		uint              security_condition; // unused as of Dec 2017
		sc_path           current_path_df;
		sc_path           current_path_ef;
		sc_aid            current_aid;
		ubyte*            rdata;
		size_t            rdata_len;

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
			string[] pointersOfInterest = [
//				"cmd_data",
				"rdata",
			];
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1];
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
//					if (name_member=="config_section") {
//						ptrdiff_t config_section_pos0 = indexOf(config_section, ['\0'], 0, No.caseSensitive);
////						sink(format("  [%(%s%)]", config_section[0..clamp(config_section_len,0,64)]));
//						sink(format(`  "%s"`, config_section[0..config_section_pos0].idup));
//					}
					if (name_member=="config_section")
						sink(format(`  "%s"`, fromStringz(config_section.ptr)));
					else
						sink.formatValue(member, fmt);
					string value_rep = format("%s", member);
//					sink(";  ");
					bool isDereferencable = (unqual_type[$-1]=='*' && unqual_type[0..$-1]!="void") && value_rep!="null";
//					sink(isDereferencable ? "YES": "NO"); //  ops:  231D380;  sc_card_operations*; YES
					if (isDereferencable && canFind(pointersOfInterest, name_member)) {
						if (name_member=="rdata")
							sink(format("  0x [%(%02x %)]", rdata[0..clamp(rdata_len,0,9999)])); // 9999 is an assumption of uppr limit
					}
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception t) { /* todo: handle exception */ }
		} // void toString
	} // struct sm_info

	/*
	 * @struct sm_card_response
	 *	data type to return card response.
	 */
	struct sm_card_response {
		int                num;
		ubyte[SC_MAX_APDU_BUFFER_SIZE] data;
		size_t             data_len;
		ubyte[8]           mac;
		size_t             mac_len;
		ubyte              sw1;
		ubyte              sw2;
		sm_card_response*  next;
		sm_card_response*  prev;

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
			string[] pointersOfInterest = [
//				"next",  // sameTypePointingMember
//			"prev",  // sameTypePointingMember
			];
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					mixin(head_foreach_Pointer_noSinkMember);
					if (canFind(["sw1", "sw2"], name_member))
						sink(format("0x%02X", member));
					else if (name_member=="data")
						sink(format("  0x [%(%02x %)]", data[0..clamp(data_len,0,SC_MAX_APDU_BUFFER_SIZE)]));
					else if (name_member=="mac")
						sink(format("  0x [%(%02x %)]",  mac[0..clamp(mac_len,0,8)]));
					else {
						if (isDereferencable)
							sink("0x");
						sink.formatValue(member, fmt);
					}
/+
					if (isDereferencable && canFind(pointersOfInterest, name_member)) {
						if      (name_member=="next")
							sink.formatValue(*next, fmt);
						else if (name_member=="prev")
							sink.formatValue(*prev, fmt);
					}
+/
					sink("\n");
				}
				sink("}\n");

//				if (next && canFind(pointersOfInterest, "next"))
//					sink.formatValue(*next, fmt);
			}
			catch (Exception t) { /* todo: handle exception */ }
		} // void toString
	} // struct sm_card_response

	extern(C) nothrow {
		alias sm_1_tf = int function(sc_card* card);
		alias sm_2_tf = int function(sc_card* card, sc_apdu* apdu, sc_apdu** sm_apdu);
		alias sm_3_tf = int function(sc_card* card, uint idx,       ubyte * buf, size_t count);
		alias sm_4_tf = int function(sc_card* card, uint idx, const(ubyte)* buf, size_t count);
	}

	/*
	 * @struct sm_card_operations
	 *	card driver handlers related to secure messaging (in 'APDU TRANSMIT' mode)
	 *	- 'open' - initialize SM session;
	 *	- 'encode apdu' - SM encoding of the raw APDU;
	 *	- 'decrypt response' - decode card answer;
	 *	- 'close' - close SM session.
	 */
	struct sm_card_operations {
		sm_1_tf  open;
		sm_2_tf  get_sm_apdu;
		sm_2_tf  free_sm_apdu;
		sm_1_tf  close;
		sm_3_tf  read_binary;
		sm_4_tf  update_binary;

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{ mixin(frame_noPointer_noArray_noUnion); }
	} // struct sm_card_operations

	/*
	 * @struct sm_module_operations
	 *	API to use external SM modules:
	 *	- 'initialize' - get APDU(s) to initialize SM session;
	 *	- 'get apdus' - get secured APDUs to execute particular command;
	 *	- 'finalize' - get APDU(s) to finalize SM session;
	 *	- 'module init' - initialize external module (allocate data, read configuration, ...);
	 *	- 'module cleanup' - free resources allocated by external module.
	 */
	struct sm_module_operations {
		extern (C) nothrow {
			int function(sc_context* ctx, sm_info* info, sc_remote_data* rdata)                                   initialize;
			int function(sc_context* ctx, sm_info* info, ubyte* init_data, size_t init_len, sc_remote_data* out_) get_apdus;
			int function(sc_context* ctx, sm_info* info, sc_remote_data* rdata, ubyte* out_, size_t out_len)      finalize;
			int function(sc_context* ctx, const(char)* data)                                                      module_init;
			int function(sc_context* ctx)                                                                         module_cleanup;
			int function(sc_context* ctx, sm_info* info, char* out_)                                              test;
		}

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{ mixin(frame_noPointer_noArray_noUnion); }
	} // struct sm_module_operations

	struct sm_module {
		char[128]            filename;
		void*                handle;
		sm_module_operations ops;

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1];
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
//					if (name_member=="filename") {
//						ptrdiff_t filename_pos0 = indexOf(filename, ['\0'], 0, No.caseSensitive);
////						sink(format("  [%(%s%)]", filename[0..clamp(filename_pos0,0,128)]));
//						sink(format(`  "%s"`, filename[0..filename_pos0].idup));
//					}
					if (name_member=="filename")
						sink(format(`  "%s"`, fromStringz(filename.ptr)));
					else
						sink.formatValue(member, fmt);
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception t) { /* todo: handle exception */ }
		} // void toString
	} // struct sm_module

	/* @struct sm_context
	 *	SM context -- top level of the SM data type
	 *	- SM mode ('ACL' or 'APDU TRANSMIT'), flags;
	 *	- working SM data;
	 *	- card operations related to SM in 'APDU TRANSMIT' mode;
	 *	- external SM module;
	 *	- 'lock'/'unlock' handlers to allow SM transfer in the locked card session.
	 */
	struct sm_context {
		char[64]            config_section;
		uint                sm_mode;  /* SM_MODE */
		uint                sm_flags; /* unused  */
		sm_info             info;
		sm_card_operations  ops;
		sm_module           module_;
		extern(C) nothrow c_ulong function() app_lock;
		extern(C) nothrow void    function() app_unlock;

version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1];
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
//					if (name_member=="config_section") {
//						ptrdiff_t config_section_pos0 = indexOf(config_section, ['\0'], 0, No.caseSensitive);
////						sink(format("  [%(%s%)]", config_section[0..clamp(config_section_len,0,64)]));
//						sink(format(`  "%s"`, config_section[0..config_section_pos0].idup));
//					}
					if (name_member=="config_section")
						sink(format(`  "%s"`, fromStringz(config_section.ptr)));
					else
						sink.formatValue(member, fmt);
					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception t) { /* todo: handle exception */ }
		} // void toString
	} // struct sm_context

	extern(C) nothrow @nogc {
		int sc_sm_parse_answer(sc_card*, ubyte*, size_t, sm_card_response*);
		int sc_sm_update_apdu_response(sc_card*, ubyte*, size_t, int, sc_apdu*);
		int sc_sm_single_transmit(sc_card*, sc_apdu*);
		/**
		 * @brief Stops SM and frees allocated ressources.
		 *
		 * Calls \a card->sm_ctx.ops.close() if available and \c card->sm_ctx.sm_mode
		 * is \c SM_MODE_TRANSMIT
		 *
		 * @param[in] card
		 *
		 * @return \c SC_SUCCESS or error code if an error occurred
		 */
		int sc_sm_stop(sc_card* card);
	} // extern (C)
} // version(ENABLE_SM)
