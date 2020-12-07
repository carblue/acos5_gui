/*
 * Function prototypes for pkcs15-init
 *
 * Copyright (C) 2002 Olaf Kirch <okir@suse.de>
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
#define PKCS15_INIT_H

Content covered by this file is ALL (except card specific get_???_ops functions) of header C/pkcs15init/pkcs15-init.h
It's functions are ALL (except those in scope version(PATCH_LIBOPENSC_EXPORTS)) exported from "libopensc.[so|dll]" binary
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

module pkcs15init.pkcs15init;

import core.stdc.config : c_ulong;
version(ENABLE_TOSTRING) {
	import std.string : fromStringz;
	import std.format;
	import std.algorithm.comparison : clamp;
	import std.algorithm.searching : canFind;

	import mixin_templates_opensc;
}

import libopensc.opensc : sc_card, sc_app_info;
import libopensc.pkcs15 : sc_pkcs15_card, sc_pkcs15_id, sc_pkcs15_auth_info, sc_pkcs15_object, sc_pkcs15_prkey_info, sc_pkcs15_prkey, sc_pkcs15_pubkey
	,sc_pkcs15_prkey_rsa, sc_pkcs15_tokeninfo, sc_pkcs15_der, sc_pkcs15_skey, sc_pkcs15_df;
import libopensc.types : sc_file, sc_path, sc_object_id, sc_aid, SC_MAX_PIN_SIZE;

import pkcs15init.profile : sc_profile;

enum DEFAULT_PRIVATE_KEY_LABEL = "Private Key";
enum DEFAULT_SECRET_KEY_LABEL  = "Secret Key";

enum SC_PKCS15INIT_X509_DIGITAL_SIGNATURE     = 0x0080UL;
enum SC_PKCS15INIT_X509_NON_REPUDIATION       = 0x0040UL;
enum SC_PKCS15INIT_X509_KEY_ENCIPHERMENT      = 0x0020UL;
enum SC_PKCS15INIT_X509_DATA_ENCIPHERMENT     = 0x0010UL;
enum SC_PKCS15INIT_X509_KEY_AGREEMENT         = 0x0008UL;
enum SC_PKCS15INIT_X509_KEY_CERT_SIGN         = 0x0004UL;
enum SC_PKCS15INIT_X509_CRL_SIGN              = 0x0002UL;

//struct sc_profile; /* opaque type */
//alias  sc_profile_t = sc_profile;

struct sc_pkcs15init_operations {
	extern(C) nothrow
	{
		/*
		 * Erase everything that's on the card
		 */
		int function(sc_profile*, sc_pkcs15_card*)  erase_card;

		/*
		 * New style API
		 */

		/*
		 * Card-specific initialization of PKCS15 meta-information.
		 * Currently used by the cflex driver to read the card's
		 * serial number and use it as the pkcs15 serial number.
		 */
		int function(sc_profile*, sc_pkcs15_card*)  init_card;

		/*
		 * Create a DF
		 */
		int function(sc_profile*, sc_pkcs15_card*, sc_file*) create_dir;

		/*
		 * Create a "pin domain". This is for cards such as
		 * the cryptoflex that need to put their pins into
		 * separate directories
		 */
		int function(sc_profile*, sc_pkcs15_card*,
				const(sc_pkcs15_id)*, sc_file**)  create_domain;

		/*
		 * Select a PIN reference
		 */
		int function(sc_profile*, sc_pkcs15_card*,
				sc_pkcs15_auth_info*)  select_pin_reference;

		/*
		 * Create a PIN object within the given DF.
		 *
		 * The pin_info object is completely filled in by the caller.
		 * The card driver can reject the pin reference; in this case
		 * the caller needs to adjust it.
		 */
		int function(sc_profile*, sc_pkcs15_card*, sc_file*,
				sc_pkcs15_object*,
				const(ubyte)*, size_t,
				const(ubyte)*, size_t)  create_pin;

		/*
		 * Select a reference for a private key object
		 */
		int function(sc_profile*, sc_pkcs15_card*,
				sc_pkcs15_prkey_info*)  select_key_reference;

		/*
		 * Create an empty key object.
		 * @index is the number key objects already on the card.
		 * @pin_info contains information on the PIN protecting
		 *		the key. NULL if the key should be
		 *		unprotected.
		 * @key_info should be filled in by the function
		 */
		int function(sc_profile*, sc_pkcs15_card*,
				sc_pkcs15_object*)  create_key;

		/*
		 * Store a key on the card
		 */
		int function(sc_profile*, sc_pkcs15_card*,
				sc_pkcs15_object*,
				sc_pkcs15_prkey*)  store_key;

		/*
		 * Generate key
		 */
		int function(sc_profile*, sc_pkcs15_card*,
				sc_pkcs15_object*,
				sc_pkcs15_pubkey*)  generate_key;

		/*
		 * Encode private/public key
		 * These are used mostly by the Cryptoflex/Cyberflex drivers.
		 */
		int function(sc_profile*, sc_card*,
				sc_pkcs15_prkey_rsa*,
				ubyte* , size_t*, int)  encode_private_key;

		int	function(sc_profile*, sc_card*,
				sc_pkcs15_prkey_rsa*,
				ubyte* , size_t*, int)  encode_public_key;

		/*
		 * Finalize card
		 * Ends the initialization phase of the smart card/token
		 * (actually this command is currently only for starcos spk 2.3
		 * cards).
		 */
		int function(sc_card*)  finalize_card;

		/*
		 * Delete object
		 */
		int function(sc_profile*, sc_pkcs15_card*,
				sc_pkcs15_object*, const(sc_path)*)  delete_object;

		/*
		 * Support of pkcs15init emulation
		 */
		int function(sc_profile*, sc_pkcs15_card*,
				sc_app_info*)  emu_update_dir;
		int function(sc_profile*, sc_pkcs15_card*,
				uint, sc_pkcs15_object*)  emu_update_any_df;
		int function(sc_profile*, sc_pkcs15_card*,
				sc_pkcs15_tokeninfo*)  emu_update_tokeninfo;
		int function(sc_profile*, sc_pkcs15_card*,
				sc_pkcs15_object*)  emu_write_info;
		int function(sc_pkcs15_card*, sc_profile*, sc_pkcs15_object*,
				sc_pkcs15_der*, sc_path*)  emu_store_data;

		int function(sc_profile*, sc_pkcs15_card*)  sanity_check;
	} // extern(C) nothrow

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{ mixin(frame_noPointer_noArray_noUnion); }
} // struct sc_pkcs15init_operations

/* Do not change these or reorder these */
enum SC_PKCS15INIT_ID_STYLE_NATIVE   = 0;
enum SC_PKCS15INIT_ID_STYLE_MOZILLA  = 1;
enum SC_PKCS15INIT_ID_STYLE_RFC2459  = 2;

enum SC_PKCS15INIT_SO_PIN    = 0;
enum SC_PKCS15INIT_SO_PUK    = 1;
enum SC_PKCS15INIT_USER_PIN  = 2;
enum SC_PKCS15INIT_USER_PUK  = 3;
enum SC_PKCS15INIT_NPINS     = 4;

enum SC_PKCS15INIT_MD_STYLE_NONE     = 0;
enum SC_PKCS15INIT_MD_STYLE_GEMALTO  = 1;

struct sc_pkcs15init_callbacks {
	extern(C) nothrow {
		/*
		 * Get a PIN from the front-end. The first argument is
		 * one of the SC_PKCS15INIT_XXX_PIN/PUK macros.
		 */
		int function(sc_profile*, int, const(sc_pkcs15_auth_info)*,
					const(char)*, ubyte*, size_t*)    get_pin;

		/*
		 * Get a transport/secure messaging key from the front-end.
		 */
		int function(sc_profile*, int, int,
					const(ubyte)*, size_t,
					ubyte*, size_t*)                  get_key;
	} // extern(C) nothrow

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{ mixin(frame_noPointer_noArray_noUnion); }
} // struct sc_pkcs15init_callbacks

struct sc_pkcs15init_initargs {
	const(ubyte)*  so_pin;
	size_t         so_pin_len;
	const(ubyte)*  so_puk;
	size_t         so_puk_len;
	const(char)*   so_pin_label;
	const(char)*   label;
	const(char)*   serial;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = [
			"so_pin",
			"so_puk",
			"so_pin_label",
			"label",
			"serial",
		];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				mixin(head_foreach_Pointer);
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
					if      (name_member=="so_pin")
						sink(format("  [%(%#x, %)]", so_pin[0..clamp(so_pin_len,0,SC_MAX_PIN_SIZE)]));
					else if (name_member=="so_puk")
						sink(format("  [%(%#x, %)]", so_puk[0..clamp(so_puk_len,0,SC_MAX_PIN_SIZE)]));
					else if (name_member=="so_pin_label")
						sink(format(`  "%s"`, fromStringz(so_pin_label)));
					else if (name_member=="label")
						sink(format(`  "%s"`, fromStringz(label)));
					else if (name_member=="serial")
						sink(format(`  "%s"`, fromStringz(serial)));
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
	} // void toString
} // struct sc_pkcs15init_initargs


struct sc_pkcs15init_pinargs {
	sc_pkcs15_id   auth_id;
	const(char)*   label;
	const(ubyte)*  pin;
	size_t         pin_len;

	sc_pkcs15_id   puk_id;
	const(char)*   puk_label;
	const(ubyte)*  puk;
	size_t         puk_len;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = [
			"label",
			"pin",
			"puk_label",
			"puk",
		];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				mixin(head_foreach_Pointer);
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
					if      (name_member=="label")
						sink(format(`  "%s"`, fromStringz(label)));
					else if (name_member=="pin")
						sink(format("  [%(%#x, %)]", pin[0..clamp(pin_len,0,SC_MAX_PIN_SIZE)]));
					else if (name_member=="puk_label")
						sink(format(`  "%s"`, fromStringz(puk_label)));
					else if (name_member=="puk")
						sink(format("  [%(%#x, %)]", puk[0..clamp(puk_len,0,SC_MAX_PIN_SIZE)]));
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
	} // void toString
}  // struct sc_pkcs15init_pinargs

struct sc_pkcs15init_keyarg_gost_params {
	ubyte gostr3410, gostr3411, gost28147;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{ mixin(frame_noPointer_noArray_noUnion); }
} // sc_pkcs15init_keyarg_gost_params

struct sc_pkcs15init_prkeyargs {
	/* TODO: member for private key algorithm: currently is used algorithm from 'key' member */
	sc_pkcs15_id     id;
	sc_pkcs15_id     auth_id;
	char*            label;
	ubyte*           guid;
	size_t           guid_len;
	c_ulong          usage;
	c_ulong          x509_usage;
	uint             flags;
	uint             access_flags;
	int              user_consent;

	union anonymous {
		sc_pkcs15init_keyarg_gost_params  gost;
	}
	anonymous        params;

	sc_pkcs15_prkey  key;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = [
			"label",
			"guid",
		];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				mixin(head_foreach_Pointer);
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
					if      (name_member=="label")
						sink(format(`  "%s"`, fromStringz(label)));
					else if (name_member=="guid")
						sink(format("  [%(%#x, %)]", guid[0..clamp(guid_len,0,99)]));
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
	} // void toString
} // struct sc_pkcs15init_prkeyargs

struct sc_pkcs15init_keygen_args {
	sc_pkcs15init_prkeyargs  prkey_args;
	const(char)*             pubkey_label;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{ mixin(frame_OneCstringPointerFormats_noArray_noUnion!("pubkey_label")); }
} // struct sc_pkcs15init_keygen_args

struct sc_pkcs15init_pubkeyargs {
	sc_pkcs15_id      id;
	sc_pkcs15_id      auth_id;
	const(char)*      label;
	c_ulong           usage;
	c_ulong           x509_usage;

	union anonymous {
		sc_pkcs15init_keyarg_gost_params  gost;
	}
	anonymous         params;

	sc_pkcs15_pubkey  key;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{ mixin(frame_OneCstringPointerFormats_noArray_noUnion!("label")); }
} // struct sc_pkcs15init_pubkeyargs

struct sc_pkcs15init_dataargs {
	sc_pkcs15_id   id;
	const(char)*   label;
	sc_pkcs15_id   auth_id;
	const(char)*   app_label;
	sc_object_id   app_oid;

	sc_pkcs15_der  der_encoded; /* Wrong name: is not DER encoded */

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = [
			"label",
			"app_label",
		];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				mixin(head_foreach_Pointer);
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
					if      (name_member=="label")
						sink(format(`  "%s"`, fromStringz(label)));
					else if (name_member=="app_label")
						sink(format(`  "%s"`, fromStringz(app_label)));
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
	} // void toString
} // struct sc_pkcs15init_dataargs

struct sc_pkcs15init_skeyargs {
	sc_pkcs15_id   id;
	sc_pkcs15_id   auth_id;
	const(char)*   label;
	c_ulong        usage;
	uint           flags;
	uint           access_flags;
	c_ulong        algorithm; /* User requested algorithm */
	c_ulong        value_len; /* User requested length */
	int            session_object; /* If nonzero. this is a session object, which will
                                      be cleared from card when the session is closed.*/
	int            user_consent;
	sc_pkcs15_skey key;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{ mixin(frame_OneCstringPointerFormats_noArray_noUnion!("label")); }
} // struct sc_pkcs15init_skeyargs

struct sc_pkcs15init_certargs {
	sc_pkcs15_id   id;
	const(char)*   label;
	int            update;

	c_ulong        x509_usage;
	ubyte          authority;
	sc_pkcs15_der  der_encoded;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{ mixin(frame_OneCstringPointerFormats_noArray_noUnion!("label")); }
} // struct sc_pkcs15init_certargs

enum P15_ATTR_TYPE_LABEL  = 0;
enum P15_ATTR_TYPE_ID     = 1;
enum P15_ATTR_TYPE_VALUE  = 2;


extern(C) nothrow @nogc :

version(PATCH_LIBOPENSC_EXPORTS) {
	sc_pkcs15_object* sc_pkcs15init_new_object(int, const(char)*,
					sc_pkcs15_id* , void*);
	void sc_pkcs15init_free_object(sc_pkcs15_object*);
}
void sc_pkcs15init_set_callbacks(sc_pkcs15init_callbacks*);
int  sc_pkcs15init_bind(sc_card* card, const(char)* opt_profile, const(char)* opt_card_profile,
				sc_app_info* app_info, sc_profile** profile);
void sc_pkcs15init_unbind(sc_profile*);
void	sc_pkcs15init_set_p15card(sc_profile*,
				sc_pkcs15_card*);
int  sc_pkcs15init_set_lifecycle(sc_card*, int);
int  sc_pkcs15init_erase_card(sc_pkcs15_card*,
				sc_profile*, sc_aid*);
/* XXX could this function be merged with ..._set_lifecycle ?? */
int  sc_pkcs15init_finalize_card(sc_card*,
				sc_profile*);
int  sc_pkcs15init_add_app(sc_card*,
				sc_profile*,
				sc_pkcs15init_initargs*);
int  sc_pkcs15init_store_pin(sc_pkcs15_card*,
				sc_profile*,
				sc_pkcs15init_pinargs*);
int  sc_pkcs15init_generate_key(sc_pkcs15_card*,
				sc_profile*,
				sc_pkcs15init_keygen_args*,
				uint keybits,
				sc_pkcs15_object**);
int  sc_pkcs15init_generate_secret_key(sc_pkcs15_card*,
				sc_profile*,
				sc_pkcs15init_skeyargs*,
				sc_pkcs15_object**);
int  sc_pkcs15init_store_private_key(sc_pkcs15_card*,
				sc_profile*,
				sc_pkcs15init_prkeyargs*,
				sc_pkcs15_object**);

version(PATCH_LIBOPENSC_EXPORTS)
int  sc_pkcs15init_store_split_key(sc_pkcs15_card*,
				sc_profile*,
				sc_pkcs15init_prkeyargs*,
				sc_pkcs15_object**,
				sc_pkcs15_object**);
int  sc_pkcs15init_store_public_key(sc_pkcs15_card*,
				sc_profile*,
				sc_pkcs15init_pubkeyargs*,
				sc_pkcs15_object**);
int	sc_pkcs15init_store_secret_key(sc_pkcs15_card*,
				sc_profile*,
				sc_pkcs15init_skeyargs*,
				sc_pkcs15_object**);
int  sc_pkcs15init_store_certificate(sc_pkcs15_card*,
				sc_profile*,
				sc_pkcs15init_certargs*,
				sc_pkcs15_object**);
int  sc_pkcs15init_store_data_object(sc_pkcs15_card*,
				sc_profile*,
				sc_pkcs15init_dataargs*,
				sc_pkcs15_object**);
/* Change the value of a pkcs15 attribute.
 * new_attrib_type can (currently) be either P15_ATTR_TYPE_LABEL or
 *   P15_ATTR_TYPE_ID.
 * If P15_ATTR_TYPE_LABEL, then *new_value is a struct sc_pkcs15_id;
 * If P15_ATTR_TYPE_ID, then *new_value is a char array.
 */
int  sc_pkcs15init_change_attrib(sc_pkcs15_card*,
				sc_profile*,
				sc_pkcs15_object*,
				int,
				void*,
				int);

version(PATCH_LIBOPENSC_EXPORTS)
int  sc_pkcs15init_add_object(sc_pkcs15_card*,
			sc_profile* profile,
			uint,
			sc_pkcs15_object*);

int  sc_pkcs15init_delete_object(sc_pkcs15_card*,
				sc_profile*,
				sc_pkcs15_object*);
/* Replace an existing cert with a new one, which is assumed to be
 * compatible with the corresponding private key (e.g. the old and
 * new cert should have the same public key).
 */
int  sc_pkcs15init_update_certificate(sc_pkcs15_card*,
				sc_profile*,
				sc_pkcs15_object*,
				const(ubyte)*,
				size_t);
int  sc_pkcs15init_create_file(sc_profile*,
				sc_pkcs15_card*, sc_file*);
int  sc_pkcs15init_update_file(sc_profile*,
				sc_pkcs15_card*, sc_file*, void*, uint);
int  sc_pkcs15init_authenticate(sc_profile*, sc_pkcs15_card*, sc_file*, int);

int  sc_pkcs15init_fixup_file(sc_profile*, sc_pkcs15_card*,
				sc_file *);

int  sc_pkcs15init_get_pin_info(sc_profile*, int, sc_pkcs15_auth_info*);
version(PATCH_LIBOPENSC_EXPORTS)
int  sc_profile_get_pin_retries(sc_profile*, int);

int  sc_pkcs15init_get_manufacturer(sc_profile*,
				const(char)**);
int  sc_pkcs15init_get_serial(sc_profile*, const(char)**);

int  sc_pkcs15init_set_serial(sc_profile*, const(char)*);
int  sc_pkcs15init_verify_secret(sc_profile*, sc_pkcs15_card*,
				sc_file*,  uint, int);
int  sc_pkcs15init_delete_by_path(sc_profile*,
				sc_pkcs15_card*, const(sc_path)*);

int  sc_pkcs15init_update_any_df(sc_pkcs15_card*, sc_profile*,
				sc_pkcs15_df*, int);

version(PATCH_LIBOPENSC_EXPORTS)
int  sc_pkcs15init_select_intrinsic_id(sc_pkcs15_card*, sc_profile*,
			int, sc_pkcs15_id*, void*);

/* Erasing the card structure via rm -rf */
int  sc_pkcs15init_erase_card_recursively(sc_pkcs15_card*,
				sc_profile*);
int  sc_pkcs15init_rmdir(sc_pkcs15_card*, sc_profile*,
				sc_file*);

/* Helper function for CardOS */
version(PATCH_LIBOPENSC_EXPORTS) {
	int  sc_pkcs15_create_pin_domain(sc_profile*, sc_pkcs15_card*,
					const(sc_pkcs15_id)*, sc_file**);
	int  sc_pkcs15init_get_pin_reference(sc_pkcs15_card*,
					sc_profile*, uint, int);
}

int  sc_pkcs15init_sanity_check(sc_pkcs15_card*, sc_profile*);

int  sc_pkcs15init_finalize_profile(sc_card* card, sc_profile* profile,
				sc_aid* aid);

version(PATCH_LIBOPENSC_EXPORTS)
int	sc_pkcs15init_unwrap_key(sc_pkcs15_card* p15card, sc_profile* profile,
		sc_pkcs15_object* key, u8* wrapped_key, size_t wrapped_key_len,
		sc_pkcs15init_skeyargs* keyargs, sc_pkcs15_object** res_obj);
