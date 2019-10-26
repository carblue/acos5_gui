/*
 * Copyright (C) 2002-2014 Free Software Foundation, Inc.
 *
 * This file is part of LIBTASN1.
 *
 * LIBTASN1 is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * LIBTASN1 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with LIBTASN1; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

/**
 * libtasn1:Short_Description:
 *
 * GNU ASN.1 library
 */
/**
 * libtasn1:Long_Description:
 *
 * The Libtasn1 library provides Abstract Syntax Notation One (ASN.1, as
 * specified by the X.680 ITU-T recommendation) parsing and structures
 * management, and Distinguished Encoding Rules (DER, as per X.690)
 * encoding and decoding functions.
 */
/*
Written in the D programming language.
For git maintenance (ensure at least one congruent line with originating C header):
#define LIBTASN1_H
*/

module deimos.libtasn1;

import core.stdc.config : c_ulong, c_long;
import core.stdc.stdio : FILE;

extern (C) @nogc nothrow:

/**
 * ASN1_VERSION:
 *
 * Version of the library as a string.
 */
enum ASN1_VERSION = "4.14";

/**
 * ASN1_VERSION_MAJOR:
 *
 * Major version number of the library.
 */
enum ASN1_VERSION_MAJOR = 4;

/**
 * ASN1_VERSION_MINOR:
 *
 * Minor version number of the library.
 */
enum ASN1_VERSION_MINOR = 14;

/**
 * ASN1_VERSION_PATCH:
 *
 * Patch version number of the library.
 */
enum ASN1_VERSION_PATCH = 0;

/**
 * ASN1_VERSION_NUMBER:
 *
 * Version number of the library as a number.
 */
enum ASN1_VERSION_NUMBER = 0x040e00;


/*****************************************/
/* Errors returned by libtasn1 functions */
/*****************************************/
enum  /*ASN1_ERROR*/  : ubyte
{
    ASN1_SUCCESS = 0,
    ASN1_FILE_NOT_FOUND = 1,
    ASN1_ELEMENT_NOT_FOUND = 2,
    ASN1_IDENTIFIER_NOT_FOUND = 3,
    ASN1_DER_ERROR = 4,
    ASN1_VALUE_NOT_FOUND = 5,
    ASN1_GENERIC_ERROR = 6,
    ASN1_VALUE_NOT_VALID = 7,
    ASN1_TAG_ERROR = 8,
    ASN1_TAG_IMPLICIT = 9,
    ASN1_ERROR_TYPE_ANY = 10,
    ASN1_SYNTAX_ERROR = 11,
    ASN1_MEM_ERROR = 12,
    ASN1_MEM_ALLOC_ERROR = 13,
    ASN1_DER_OVERFLOW = 14,
    ASN1_NAME_TOO_LONG = 15,
    ASN1_ARRAY_ERROR = 16,
    ASN1_ELEMENT_NOT_EMPTY = 17,
    ASN1_TIME_ENCODING_ERROR = 18,
    ASN1_RECURSION = 19,
}

/*************************************/
/* Constants used in asn1_visit_tree */
/*************************************/
enum  /*ASN1_PRINT*/  : ubyte
{
    ASN1_PRINT_NAME = 1,
    ASN1_PRINT_NAME_TYPE = 2,
    ASN1_PRINT_NAME_TYPE_VALUE = 3,
    ASN1_PRINT_ALL = 4,
}

/*****************************************/
/* Constants returned by asn1_read_tag   */
/*****************************************/
enum  /*ASN1_CLASS*/  : ubyte
{
    ASN1_CLASS_UNIVERSAL = 0x00, /* old: 1 */
    ASN1_CLASS_APPLICATION = 0x40, /* old: 2 */
    ASN1_CLASS_CONTEXT_SPECIFIC = 0x80, /* old: 3 */
    ASN1_CLASS_PRIVATE = 0xC0, /* old: 4 */
    ASN1_CLASS_STRUCTURED = 0x20,
}

/*****************************************/
/* Constants returned by asn1_read_tag   */
/*****************************************/
enum  /*ASN1_TAG*/  : ubyte
{
    ASN1_TAG_BOOLEAN = 0x01,
    ASN1_TAG_INTEGER = 0x02,
    ASN1_TAG_SEQUENCE = 0x10,
    ASN1_TAG_SET = 0x11,
    ASN1_TAG_OCTET_STRING = 0x04,
    ASN1_TAG_BIT_STRING = 0x03,
    ASN1_TAG_UTCTime = 0x17,
    ASN1_TAG_GENERALIZEDTime = 0x18,
    ASN1_TAG_OBJECT_ID = 0x06,
    ASN1_TAG_ENUMERATED = 0x0A,
    ASN1_TAG_NULL = 0x05,
    ASN1_TAG_GENERALSTRING = 0x1B,
    ASN1_TAG_NUMERIC_STRING = 0x12,
    ASN1_TAG_IA5_STRING = 0x16,
    ASN1_TAG_TELETEX_STRING = 0x14,
    ASN1_TAG_PRINTABLE_STRING = 0x13,
    ASN1_TAG_UNIVERSAL_STRING = 0x1C,
    ASN1_TAG_BMP_STRING = 0x1E,
    ASN1_TAG_UTF8_STRING = 0x0C,
    ASN1_TAG_VISIBLE_STRING = 0x1A,
}

/**
 * asn1_node:
 *
 * Structure definition used for the node of the tree
 * that represents an ASN.1 DEFINITION.
 */
struct asn1_node_st; // @suppress(dscanner.style.phobos_naming_convention)
alias asn1_node       = asn1_node_st*;
alias asn1_node_const = const(asn1_node_st)*;

/**
 * ASN1_MAX_NAME_SIZE:
 *
 * Maximum number of characters of a name
 * inside a file with ASN1 definitions.
 */
enum ASN1_MAX_NAME_SIZE = 64;


/**
 * asn1_static_node:
 * @name: Node name
 * @type: Node typ
 * @value: Node value
 *
 * For the on-disk format of ASN.1 trees, created by asn1_parser2array().
 */
struct asn1_static_node // @suppress(dscanner.style.phobos_naming_convention)
{
    const(char)* name;  /* Node name */
    uint type;          /* Node type */
    const(void)* value; /* Node value */
}
//alias asn1_static_node_st = asn1_static_node;

/* List of constants for field type of node_asn  */
enum  /*ASN1_ETYPE*/  : uint
{
    ASN1_ETYPE_INVALID = 0,
    ASN1_ETYPE_CONSTANT = 1,
    ASN1_ETYPE_IDENTIFIER = 2,
    ASN1_ETYPE_INTEGER = 3,
    ASN1_ETYPE_BOOLEAN = 4,
    ASN1_ETYPE_SEQUENCE = 5,
    ASN1_ETYPE_BIT_STRING = 6,
    ASN1_ETYPE_OCTET_STRING = 7,
    ASN1_ETYPE_TAG = 8,
    ASN1_ETYPE_DEFAULT = 9,
    ASN1_ETYPE_SIZE = 10,
    ASN1_ETYPE_SEQUENCE_OF = 11,
    ASN1_ETYPE_OBJECT_ID = 12,
    ASN1_ETYPE_ANY = 13,
    ASN1_ETYPE_SET = 14,
    ASN1_ETYPE_SET_OF = 15,
    ASN1_ETYPE_DEFINITIONS = 16,
    ASN1_ETYPE_CHOICE = 18,
    ASN1_ETYPE_IMPORTS = 19,
    ASN1_ETYPE_NULL = 20,
    ASN1_ETYPE_ENUMERATED = 21,
    ASN1_ETYPE_GENERALSTRING = 27,
    ASN1_ETYPE_NUMERIC_STRING = 28,
    ASN1_ETYPE_IA5_STRING = 29,
    ASN1_ETYPE_TELETEX_STRING = 30,
    ASN1_ETYPE_PRINTABLE_STRING = 31,
    ASN1_ETYPE_UNIVERSAL_STRING = 32,
    ASN1_ETYPE_BMP_STRING = 33,
    ASN1_ETYPE_UTF8_STRING = 34,
    ASN1_ETYPE_VISIBLE_STRING = 35,
    ASN1_ETYPE_UTC_TIME = 36,
    ASN1_ETYPE_GENERALIZED_TIME = 37,
}


/**
 * ASN1_DELETE_FLAG_ZEROIZE:
 *
 * Used by: asn1_delete_structure2()
 *
 * Zeroize values prior to deinitialization.
 */
enum ASN1_DELETE_FLAG_ZEROIZE = 1;

/**
 * ASN1_DECODE_FLAG_ALLOW_PADDING:
 *
 * Used by: asn1_der_decoding2()
 *
 * This flag would allow arbitrary data past the DER data.
 */
enum ASN1_DECODE_FLAG_ALLOW_PADDING = 1;
/**
 * ASN1_DECODE_FLAG_STRICT_DER:
 *
 * Used by: asn1_der_decoding2()
 *
 * This flag would ensure that no BER decoding takes place.
 */
enum ASN1_DECODE_FLAG_STRICT_DER = 1 << 1;
/**
 * ASN1_DECODE_FLAG_ALLOW_INCORRECT_TIME:
 *
 * Used by: asn1_der_decoding2()
 *
 * This flag will tolerate Time encoding errors when in strict DER.
 */
enum ASN1_DECODE_FLAG_ALLOW_INCORRECT_TIME = 1 << 2;


/**
 * asn1_data_node_st:
 * @name: Node name
 * @value: Node value
 * @value_len: Node value size
 * @type: Node value type (ASN1_ETYPE_*)
 *
 * Data node inside a #asn1_node structure.
 */
struct asn1_data_node_st // @suppress(dscanner.style.phobos_naming_convention)
{
    const(char)* name; /* Node name */
    const(void)* value; /* Node value */
    uint value_len; /* Node value size */
    uint type; /* Node value type (ASN1_ETYPE_*) */
}

/***********************************/
/*  Fixed constants                */
/***********************************/

/**
 * ASN1_MAX_ERROR_DESCRIPTION_SIZE:
 *
 * Maximum number of characters
 * of a description message
 * (null character included).
 */
enum ASN1_MAX_ERROR_DESCRIPTION_SIZE = 128;

/***********************************/
/*  Functions definitions          */
/***********************************/

int asn1_parser2tree(const(char)* file, asn1_node* definitions, char* error_desc);

int asn1_parser2array(const(char)* inputFileName, const(char)* outputFileName,
        const(char)* vectorName, char* error_desc);

int asn1_array2tree(const(asn1_static_node)* array, asn1_node* definitions, char* errorDescription) pure;

void asn1_print_structure(FILE* out_, asn1_node_const structure, const(char)* name, int mode);

/**
 * Creates structure 'element' of type source_name (source_name defined in definitions).
 * After using 'element', in order to avoid a memory leak, 'element' must be deleted by
 * asn1_delete_structure (element);
*/
int asn1_create_element(asn1_node_const definitions, const(char)* source_name, asn1_node* element);

int asn1_delete_structure(asn1_node* structure);

int asn1_delete_structure2(asn1_node* structure, uint flags);

int asn1_delete_element(asn1_node structure, const(char)* element_name);

int asn1_write_value(asn1_node node_root, const(char)* name, const(void)* ivalue, int len);

int asn1_read_value(asn1_node_const root, const(char)* name, void* ivalue, int* len);

int asn1_read_value_type(asn1_node_const root, const(char)* name, void* ivalue, int* len, uint* etype);

int asn1_read_node_value(asn1_node_const node, asn1_data_node_st* data);

int asn1_number_of_elements(asn1_node_const element, const(char)* name, int* num);

int asn1_der_coding(asn1_node_const element, const(char)* name, void* ider, int* len, char* ErrorDescription);

int asn1_der_decoding2(asn1_node* element, const(void)* ider, int* max_ider_len, uint flags, char* errorDescription);

/**
 * Fill the structure 'element' with values of a DER encoding string. The structure must exist already, created by function asn1_create_element() .
 */
int asn1_der_decoding(asn1_node* element, const(void)* ider, int ider_len, char* errorDescription);

deprecated("Do not use. Use asn1_der_decoding() instead.") int asn1_der_decoding_element(
        asn1_node* structure, const(char)* elementName, const(void)* ider, int len, char* errorDescription);

int asn1_der_decoding_startEnd(asn1_node element, const(void)* ider, int ider_len,
        const(char)* name_element, int* start, int* end);

int asn1_expand_any_defined_by(asn1_node_const definitions, asn1_node* element);

int asn1_expand_octet_string(asn1_node_const definitions, asn1_node* element, const(char)* octetName,
        const(char)* objectName);

int asn1_read_tag(asn1_node_const root, const(char)* name, int* tagValue, int* classValue);

const(char)* asn1_find_structure_from_oid(asn1_node_const definitions, const(char)* oidValue);

const(char)* asn1_check_version(const(char)* req_version) pure;

const(char)* asn1_strerror(int error) pure;

void asn1_perror(int error);

enum ASN1_MAX_TAG_SIZE = 4;
enum ASN1_MAX_LENGTH_SIZE = 9;
enum ASN1_MAX_TL_SIZE = ASN1_MAX_TAG_SIZE + ASN1_MAX_LENGTH_SIZE;

c_long asn1_get_length_der(const(ubyte)* der, int der_len, int* len);

c_long asn1_get_length_ber(const(ubyte)* ber, int ber_len, int* len);

void asn1_length_der(c_ulong len, ubyte* der, int* der_len) pure;

/* Other utility functions. */

int asn1_decode_simple_der(uint etype, const(ubyte)* der, uint _der_len, const(ubyte)** str, uint* str_len);

int asn1_decode_simple_ber(uint etype, const(ubyte)* der, uint _der_len, ubyte** str, uint* str_len, uint* ber_len);

int asn1_encode_simple_der(uint etype, const(ubyte)* str, uint str_len, ubyte* tl, uint* tl_len);

asn1_node asn1_find_node(asn1_node_const pointer, const(char)* name);

int asn1_copy_node(asn1_node dst, const(char)* dst_name, asn1_node_const src, const(char)* src_name);

asn1_node asn1_dup_node(asn1_node_const src, const(char)* src_name);

/* Internal and low-level DER utility functions. */

int asn1_get_tag_der(const(ubyte)* der, int der_len, ubyte* cls, int* len, c_ulong* tag);

void asn1_octet_der(const(ubyte)* str, int str_len, ubyte* der, int* der_len);

int asn1_get_octet_der(const(ubyte)* der, int der_len, int* ret_len, ubyte* str, int str_size, int* str_len);

void asn1_bit_der(const(ubyte)* str, int bit_len, ubyte* der, int* der_len);

int asn1_get_bit_der(const(ubyte)* der, int der_len, int* ret_len, ubyte* str, int str_size, int* bit_len);

int asn1_get_object_id_der(const(ubyte)* der, int der_len, int* ret_len, char* str, int str_size);

/* Compatibility types */

/**
 * asn1_retCode:
 *
 * Type formerly returned by libtasn1 functions.
 *
 * Deprecated: 3.0: Use int instead.
 */
alias asn1_retCode = int;

/**
 * node_asn_struct:
 *
 * Compat #define.
 *
 * Deprecated: 3.0: Use #asn1_node instead.
 */
alias node_asn_struct = asn1_node_st;

/**
 * node_asn:
 *
 * Compat #define.
 *
 * Deprecated: 3.0: Use #asn1_node instead.
 */
alias node_asn = asn1_node_st;

/**
 * ASN1_TYPE:
 *
 * Compat #define.
 *
 * Deprecated: 3.0: Use #asn1_node instead.
 */
alias ASN1_TYPE = asn1_node;

/**
 * ASN1_TYPE_EMPTY:
 *
 * Compat #define.
 *
 * Deprecated: 3.0: Use NULL instead.
 */
enum ASN1_TYPE_EMPTY = null;

/**
 * static_struct_asn:
 *
 * Compat #define.
 *
 * Deprecated: 3.0: Use #asn1_static_node instead.
 */
alias static_struct_asn = asn1_static_node;

/**
 * ASN1_ARRAY_TYPE:
 *
 * Compat #define.
 *
 * Deprecated: 3.0: Use #asn1_static_node instead.
 */
alias ASN1_ARRAY_TYPE = asn1_static_node;

/**
 * asn1_static_node_t:
 *
 * Compat #define.
 *
 * Deprecated: 3.0: Use #asn1_static_node instead.
 */
alias asn1_static_node_t = asn1_static_node;

/**
 * node_data_struct:
 *
 * Compat #define.
 *
 * Deprecated: 3.0: Use #asn1_data_node_st instead.
 */
alias node_data_struct = asn1_data_node_st;

/**
 * ASN1_DATA_NODE:
 *
 * Compat #define.
 *
 * Deprecated: 3.0: Use #asn1_data_node_st instead.
 */
alias ASN1_DATA_NODE = asn1_data_node_st;
