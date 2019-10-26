/*
 * Card profile information (internal)
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
#define _OPENSC_PROFILE_H

Content covered by this file is ALL! of header C/pkcs15init/profile.h
Without patching opensc, it's functions are NOT! exported from "libopensc.[so|dll]" binary
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

module pkcs15init.profile;

version(ENABLE_TOSTRING) {
	import std.string : fromStringz;
	import std.format;
	import std.algorithm.comparison : clamp;
	import std.algorithm.searching : canFind;

	import mixin_templates_opensc;
}

import libopensc.opensc : sc_card, sc_app_info;
import libopensc.types : sc_path, sc_file;
import libopensc.pkcs15 : sc_pkcs15_card, sc_pkcs15_auth_info, SC_PKCS15_DF, SC_PKCS15_DF_TYPE_COUNT, sc_pkcs15_id;
import scconf.scconf: scconf_list;
import pkcs15init.pkcs15init : sc_pkcs15init_operations;

enum SC_PKCS15_PROFILE_SUFFIX	= "profile";

/* Obsolete */
struct auth_info {
	auth_info*  next; // sameTypePointingMember
	uint        type;		/* CHV, AUT, PRO */
	uint        ref_;
	size_t      key_len;
	ubyte[32]   key;
} // struct auth_info

struct file_info {
	char*        ident;
	file_info*   next; // sameTypePointingMember
	sc_file*     file;
	uint         dont_free;
	file_info*   parent; // sameTypePointingMember

	/* Template support */
	file_info*   instance; // sameTypePointingMember
	sc_profile*  base_template;
	uint         inst_index;
	sc_path      inst_path;

  /* Profile extension dependent on the application ID (sub-profile).
	 * Sub-profile is loaded when binding to the particular application
	 * of the multi-application PKCS#15 card. */
	char*        profile_extension;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = [
			"ident",
//			"next",
			"file",
//			"parent",
			"instance",
			"base_template",
			"profile_extension",
		];
		try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					mixin(head_foreach_Pointer);
					if (isDereferencable && canFind(pointersOfInterest, name_member)) {
						if      (name_member=="ident")
							sink(format(`  "%s"`, fromStringz(ident)));
						else if (name_member=="next")
							sink.formatValue(*next, fmt);
						else if (name_member=="file")
							sink.formatValue(*file, fmt);
						else if (name_member=="parent")
							sink.formatValue(*parent, fmt);
						else if (name_member=="instance")
							sink.formatValue(*instance, fmt);
						else if (name_member=="base_template")
							sink.formatValue(*base_template, fmt);
						else if (name_member=="profile_extension")
							sink(format(`  "%s"`, fromStringz(profile_extension)));
					}
					sink("\n");
				}
				sink("}\n");
		}
		catch (Exception t) { /* todo: handle exception */ }
	} // void toString
} // struct file_info

/* For now, we assume the PUK always resides
 * in the same file as the PIN
 */
struct pin_info {
	int                  id;
	pin_info*            next; // sameTypePointingMember
	char*                file_name;		/* obsolete */
	uint                 file_offset;	/* obsolete */
	file_info*           file;				/* obsolete */

	sc_pkcs15_auth_info  pin;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = [
//			"next",
//			"file_name",
//			"file",
		];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				mixin(head_foreach_Pointer);
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
					if      (name_member=="next")
						sink.formatValue(*next, fmt);
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
	} // void toString
} // struct pin_info

struct sc_macro {
	char*         name;
	sc_macro*     next; // sameTypePointingMember
	scconf_list*  value;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = [
			"name",
//			"next", // segmentation fault
			"value",
		];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				mixin(head_foreach_Pointer);
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
					if      (name_member=="name")
						sink(format(`  "%s"`, fromStringz(name)));
					else if (name_member=="next")
						sink.formatValue(*next, fmt);
					else if (name_member=="value")
						sink.formatValue(*value, fmt);
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
	} // void toString
} // struct sc_macro
alias sc_macro_t = sc_macro;

/* Template support.
 *
 * Templates are EFs or entire hierarchies of DFs/EFs.
 * When instantiating a template, the file IDs of the
 * EFs and DFs are combined from the value given in the
 * profile, and the last octet of the pkcs15 ID.
 */
struct sc_template {
	char*         name;
	sc_template*  next; // sameTypePointingMember
	sc_profile*   data;
	file_info*    file;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = [
			"name",
//			"next",
			"data",
			"file",
		];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				mixin(head_foreach_Pointer);
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
					if      (name_member=="name")
						sink(format(`  "%s"`, fromStringz(name)));
					else if (name_member=="next")
						sink.formatValue(*next, fmt);
					else if (name_member=="data")
						sink.formatValue(*data, fmt);
					else if (name_member=="file")
						sink.formatValue(*file, fmt);
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
	} // void toString
} // struct sc_template
//alias sc_template_t = sc_template;

enum SC_PKCS15INIT_MAX_OPTIONS = 16;

struct sc_profile {
	char*                              name;
	char*[SC_PKCS15INIT_MAX_OPTIONS]   options;

	sc_card*                           card;
	char*                              driver;
	sc_pkcs15init_operations*          ops;
	void*                              dll;  /* handle for dynamic modules */

	file_info*                         mf_info;
	file_info*                         df_info;
	file_info*                         ef_list;
	sc_file*[SC_PKCS15_DF_TYPE_COUNT]  df;

	pin_info*                          pin_list;
	auth_info*                         auth_list;
	sc_template*                       template_list;
	sc_macro*                          macro_list;

	uint                               pin_domains;
	uint                               pin_maxlen;
	uint                               pin_minlen;
	uint                               pin_pad_char;
	uint                               pin_encoding;
	uint                               pin_attempts;
	uint                               puk_attempts;
	uint                               rsa_access_flags; /* used by pkcs15init/profile.c, e.g. DEF_PRKEY_RSA_ACCESS */
	uint                               dsa_access_flags;

	struct anonymous {
		uint  direct_certificates;
		uint  encode_df_length;
		uint  do_last_update;

		version(ENABLE_TOSTRING)
		void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
		{ mixin(frame_noPointer_noArray_noUnion); }
	} // struct anonymous
	anonymous                          pkcs15;

	/* PKCS15 information */
	sc_pkcs15_card*                    p15_spec; /* as given by profile */
	sc_pkcs15_card*                    p15_data; /* as found on card */
	/* flag to indicate whether the TokenInfo::lastUpdate field
	 * needs to be updated (in other words: if the card content
	 * has been changed) */
	int                                dirty;

	/* PKCS15 object ID style */
	uint                               id_style; /* SC_PKCS15INIT_ID_STYLE_NATIVE, SC_PKCS15INIT_ID_STYLE_MOZILLA, SC_PKCS15INIT_ID_STYLE_RFC2459 */

	/* Minidriver support style */
	uint                               md_style; /* SC_PKCS15INIT_MD_STYLE_NONE, ... */

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = [
			"name",
//			"card",
			"driver",
			"ops",
//			"dll",
//			"mf_info",
//			"df_info",
//			"ef_list",
//			"pin_list",
//			"auth_list",
//			"template_list",
			"macro_list",
//			"p15_spec",
//			"p15_data",
		];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				mixin(head_foreach_Pointer_noSinkMember);
				if (name_member=="options") {
					sink("  [");
					foreach (sub_member; options)
						if (sub_member)
							sink(format(`"%s", `, fromStringz(sub_member)));
						else
							sink("null, ");
					sink("]");
				}
/* */
				else if (name_member=="df") {
					sink(format("  [%(%#x, %)]", member));
					foreach (sub_member; df)
						if (sub_member) {
							sink.formatValue(*sub_member, fmt);
							break; // currently only print the first
						}
				}
/* */
				else {
					if (isDereferencable || isDereferencableVoid)
						sink("0x");
					sink.formatValue(member, fmt);
				}
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
					if      (name_member=="name")
						sink(format(`  "%s"`, fromStringz(name)));
					else if (name_member=="card")
						sink.formatValue(*card, fmt);
					else if (name_member=="driver")
						sink(format(`  "%s"`, fromStringz(driver)));
					else if (name_member=="ops")
						sink.formatValue(*ops, fmt);
					else if (name_member=="mf_info")
						sink.formatValue(*mf_info, fmt);
					else if (name_member=="df_info")
						sink.formatValue(*df_info, fmt);
					else if (name_member=="ef_list")
						sink.formatValue(*ef_list, fmt);
					else if (name_member=="pin_list")
						sink.formatValue(*pin_list, fmt);
					else if (name_member=="auth_list")
						sink.formatValue(*auth_list, fmt);
					else if (name_member=="template_list")
						sink.formatValue(*template_list, fmt);
					else if (name_member=="macro_list")
						sink.formatValue(*macro_list, fmt);
					else if (name_member=="p15_spec")
						sink.formatValue(*p15_spec, fmt);
					else if (name_member=="p15_data")
						sink.formatValue(*p15_data, fmt);
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
	} // void toString
} // struct sc_profile

version(PATCH_LIBOPENSC_EXPORTS) {
extern(C) :

sc_profile* sc_profile_new();
int  sc_profile_load(sc_profile*, const(char)*);
int  sc_profile_finish(sc_profile *, const(sc_app_info)*);
void sc_profile_free(sc_profile*);
int  sc_profile_build_pkcs15(sc_profile*);
void sc_profile_get_pin_info(sc_profile*, int, sc_pkcs15_auth_info*);
int  sc_profile_get_pin_id(sc_profile*, uint, int*);
int  sc_profile_get_file(sc_profile*, const(char)*, sc_file**);
int  sc_profile_get_file_by_path(sc_profile*, const(sc_path)*, sc_file**);
int  sc_profile_get_path(sc_profile*, const(char)*, sc_path*);
int  sc_profile_get_file_in(sc_profile*, const(sc_path)*, const(char)*, sc_file**);
int  sc_profile_instantiate_template(sc_profile*, const(char)*, const(sc_path)*,
			const(char)*, const(sc_pkcs15_id)*, sc_file**);
int  sc_profile_add_file(sc_profile*, const(char)*, sc_file*);
int  sc_profile_get_file_instance(sc_profile*, const(char)*, int, sc_file**);
int  sc_profile_get_pin_id_by_reference(sc_profile*, uint, int,
			sc_pkcs15_auth_info*);
int  sc_profile_get_parent(sc_profile* profile, const(char)*, sc_file**);
}
