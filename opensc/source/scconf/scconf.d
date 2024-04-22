/*
 * $Id$
 *
 * Copyright (C) 2002
 *  Antti Tapaninen <aet@cc.hut.fi>
 * Copyright (C) 2016- for the binding: Carsten Blüggel <bluecars@posteo.eu>
 *
 * Originally based on source by Timo Sirainen <tss@iki.fi>
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
#define _SC_CONF_H

Content covered by this file is ALL of header C/scconf/scconf.h
ALL extern(C) functions are exported from "libopensc.[so|dll]" binary (checked OpenSC-0.18.0)
TODO: void toString covers ALL! structs, but has to be checked/enabled, ALL! comments are retained from header
TODO inspect/overhaul all toString methods (somewhere there is still a bug):
  those that dereference pointers are subject to crashes if not checked for is null or if there is an opensc bug with non-null list termination (dangling pointers)
  watch out for infinite call chains: never follow pointers to next and previous etc.
  watch out for version dependant fields existing or not
  that use any kind of list types, with special care for those with (or leading to types with) 'sameTypePointingMember' etc.
  generalize using common code out-sourced to mixin_templates_opensc
TODO check for function attributes @nogc, nothrow, pure @system/@trusted. Never use @safe directly for a C function binding,
  but a wrapping function like e.g. libopensc.opensc.bytes2apdu may use @safe
; @trusted only after inspection source code !
*/


module scconf.scconf;

version(ENABLE_TOSTRING) {
	import std.string : fromStringz;
	import std.format;
	import std.algorithm.comparison : clamp;
	import std.algorithm.searching : canFind;

	import mixin_templates_opensc;
}

enum {
	SCCONF_BOOLEAN  = 11,
	SCCONF_INTEGER  = 12,
	SCCONF_STRING   = 13,
}

//typedef struct _scconf_block scconf_block; see below

struct scconf_list {
	scconf_list* next;
	char*        data;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = [
			"next", // sameTypePointingMember
			"data",
		];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				mixin(head_foreach_Pointer);
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
/*					if      (name_member=="next")
						sink.formatValue(*next, fmt);
					else*/ if (name_member=="data")
						sink(format(`  "%s"`, fromStringz(data)));
				}
				sink("\n");
			}
			sink("}\n");

			if (next && canFind(pointersOfInterest, "next"))
				sink.formatValue(*next, fmt);
		}
		catch (Exception e) { /* todo: handle exception */ }
	} // void toString
} // struct scconf_list
//alias _scconf_list = scconf_list;

enum {
	SCCONF_ITEM_TYPE_COMMENT = 0,  /* key = NULL, comment */
	SCCONF_ITEM_TYPE_BLOCK   = 1,  /* key = key, block */
	SCCONF_ITEM_TYPE_VALUE   = 2,  /* key = key, list */
}

struct scconf_item {
	scconf_item* next;
	int          type;
	char*        key;

	union anonymous {
		char*         comment;
		scconf_block* block;
		scconf_list*  list;
	} // union anonymous
	anonymous    value;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = [
			"next", // sameTypePointingMember ; uncomment this to exclude going further
			"key",
		];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				mixin(head_foreach_Pointer_noSinkMember);
				if (name_member=="value") {
					if      (type==SCCONF_ITEM_TYPE_COMMENT && value.comment!=null) {
						sink("  (char*) : 0x");
						sink.formatValue(value.comment, fmt);
						sink(format(`  "%s"`, fromStringz(value.comment)));
					}
					else if (type==SCCONF_ITEM_TYPE_BLOCK   && value.block!=null) {
						sink("  (scconf_block*) : 0x");
						sink.formatValue(  value.block, fmt);
						sink.formatValue(*(value.block), fmt);
					}
					else if (type==SCCONF_ITEM_TYPE_VALUE   && value.list!=null) {
						sink("  (scconf_list*) : 0x");
						sink.formatValue(  value.list, fmt);
						sink.formatValue(*(value.list), fmt);
					}
				}
				else {
					if (isDereferencable)
						sink("0x");
					sink.formatValue(member, fmt);
				}

				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
/*					if      (name_member=="next")
						sink.formatValue(*next, fmt);
					else*/ if (name_member=="key")
						sink(format(`  "%s"`, fromStringz(key)));
				}
				sink("\n");
			}
			sink("}\n");

			if (next && canFind(pointersOfInterest, "next"))
				sink.formatValue(*next, fmt);
		}
		catch (Exception e) { /* todo: handle exception */ }
	} // void toString
} // struct scconf_item
//alias _scconf_item = scconf_item;

struct _scconf_block {
	scconf_block* parent;
	scconf_list*  name;
	scconf_item*  items;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = [
//			"parent", // sameTypePointingMember ; carefull here, not tested !
			"name",     // has sameTypePointingMember
			"items",    // has sameTypePointingMember
		];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				mixin(head_foreach_Pointer);
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
					if      (name_member=="parent")
						sink.formatValue(*parent, fmt);
					else if (name_member=="name")
						sink.formatValue(*name, fmt);
					else if (name_member=="items")
						sink.formatValue(*items, fmt);
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
	} // void toString
} // struct _scconf_block
alias scconf_block = _scconf_block;


struct scconf_context {
	char*         filename;
	int           debug_;
	scconf_block* root;
	char*         errmsg;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const {
		string[] pointersOfInterest = [
			"filename",
//			"root",// has sameTypePointingMember
			"errmsg",
		];
		try {
			sink("\n{\n");
			foreach (i, ref member; this.tupleof) {
				mixin(head_foreach_Pointer);
				if (isDereferencable && canFind(pointersOfInterest, name_member)) {
					if      (name_member=="filename")
						sink(format(`  "%s"`, fromStringz(filename)));
					else if (name_member=="root")
						sink.formatValue(*root, fmt);
					else if (name_member=="errmsg")
						sink(format(`  "%s"`, fromStringz(errmsg)));
				}
				sink("\n");
			}
			sink("}\n");
		}
		catch (Exception e) { /* todo: handle exception */ }
	} // void toString
} // struct scconf_context


extern(C) @nogc nothrow /*pure*/ :


/** Allocate scconf_context
 * The filename can be NULL
 */
scconf_context* scconf_new(const(char)* filename);

/** Free scconf_context
 */
void scconf_free(scconf_context* config);

/** Parse configuration
 * Returns 1 = ok, 0 = error, -1 = error opening config file
 */
int scconf_parse(scconf_context* config);

/** Parse a static configuration string
 * Returns 1 = ok, 0 = error
 */
int scconf_parse_string(scconf_context* config, const(char)* string);

/** Write config to a file
 * If the filename is NULL, use the config->filename
 * Returns 0 = ok, else = errno
 */
int scconf_write(scconf_context* config, const(char)* filename);

/** Find a block by the item_name
 * If the block is NULL, the root block is used
 */
const(scconf_block)* scconf_find_block(const(scconf_context)* config, const(scconf_block)* block, const(char)* item_name);

/** Find blocks by the item_name
 * If the block is NULL, the root block is used
 * The key can be used to specify what the blocks first name should be
 */
scconf_block** scconf_find_blocks(const(scconf_context)* config, const(scconf_block)* block, const(char)* item_name, const(char)* key);

/** Get a list of values for option
 */
const(scconf_list)* scconf_find_list(const(scconf_block)* block, const(char)* option);

/** Return the first string of the option
 * If no option found, return def
 */
const(char)* scconf_get_str(const(scconf_block)* block, const(char)* option, const(char)* def);

/** Return the first value of the option as integer
 * If no option found, return def
 */
int scconf_get_int(const(scconf_block)* block, const(char)* option, int def);

/** Return the first value of the option as boolean
 * If no option found, return def
 */
int scconf_get_bool(const(scconf_block)* block, const(char)* option, int def);

/** Write value to a block as a string
 */
const(char)* scconf_put_str(scconf_block* block, const(char)* option, const(char)* value);

/** Write value to a block as an integer
 */
int scconf_put_int(scconf_block* block, const(char)* option, int value);

/** Write value to a block as a boolean
 */
int scconf_put_bool(scconf_block* block, const(char)* option, int value);

/** Add block structure
 * If the block is NULL, the root block is used
 */
scconf_block* scconf_block_add(scconf_context* config, scconf_block* block, const(char)* key, const(scconf_list)* name);

/** Copy block structure (recursive)
 */
scconf_block* scconf_block_copy(const(scconf_block)* src, scconf_block** dst);

/** Free block structure (recursive)
 */
void scconf_block_destroy(scconf_block* block);

/** Add item to block structure
 * If the block is NULL, the root block is used
 */
scconf_item* scconf_item_add(scconf_context* config, scconf_block* block, scconf_item* item, int type, const(char)* key, const(void)* data);

/** Copy item structure (recursive)
 */
scconf_item* scconf_item_copy(const(scconf_item)* src, scconf_item** dst);

/** Free item structure (recursive)
 */
void scconf_item_destroy(scconf_item* item);

/** Add a new value to the list
 */
scconf_list* scconf_list_add(scconf_list** list, const(char)* value);

/** Copy list structure
 */
scconf_list* scconf_list_copy(const(scconf_list)* src, scconf_list** dst);

/** Free list structure
 */
void scconf_list_destroy(scconf_list* list);

/** Return the length of an list array
 */
int scconf_list_array_length(const(scconf_list)* list);

/** Return the combined length of the strings on all arrays
 */
int scconf_list_strings_length(const(scconf_list)* list);

/** Return an allocated string that contains all
 * the strings in a list separated by the filler
 * The filler can be NULL
 */
char* scconf_list_strdup(const(scconf_list)* list, const(char)* filler);

/** Returns an allocated array of const char *pointers to
 * list elements.
 * Last pointer is NULL
 * Array must be freed, but pointers to strings belong to scconf_list
 */
const(char)** scconf_list_toarray(const(scconf_list)* list);
