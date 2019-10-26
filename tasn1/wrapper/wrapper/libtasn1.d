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
/*
Written in the D programming language.
For git maintenance (ensure at least one congruent line with originating C header):
#define LIBTASN1_H
*/

module wrapper.libtasn1;

public import deimos.libtasn1 : ASN1_VERSION, ASN1_VERSION_MAJOR, ASN1_VERSION_MINOR, ASN1_VERSION_PATCH,
    ASN1_VERSION_NUMBER, ASN1_SUCCESS, ASN1_FILE_NOT_FOUND,
    ASN1_ELEMENT_NOT_FOUND, ASN1_IDENTIFIER_NOT_FOUND, ASN1_DER_ERROR, ASN1_VALUE_NOT_FOUND,
    ASN1_GENERIC_ERROR, ASN1_VALUE_NOT_VALID, ASN1_TAG_ERROR,
    ASN1_TAG_IMPLICIT, ASN1_ERROR_TYPE_ANY, ASN1_SYNTAX_ERROR, ASN1_MEM_ERROR, ASN1_MEM_ALLOC_ERROR,
    ASN1_DER_OVERFLOW, ASN1_NAME_TOO_LONG, ASN1_ARRAY_ERROR, ASN1_ELEMENT_NOT_EMPTY,
    ASN1_TIME_ENCODING_ERROR,

    ASN1_PRINT_NAME, ASN1_PRINT_NAME_TYPE, ASN1_PRINT_NAME_TYPE_VALUE,
    ASN1_PRINT_ALL, ASN1_CLASS_UNIVERSAL, ASN1_CLASS_APPLICATION, ASN1_CLASS_CONTEXT_SPECIFIC,
    ASN1_CLASS_PRIVATE, ASN1_CLASS_STRUCTURED, ASN1_TAG_BOOLEAN, ASN1_TAG_INTEGER, ASN1_TAG_SEQUENCE,
    ASN1_TAG_SET, ASN1_TAG_OCTET_STRING, ASN1_TAG_BIT_STRING, ASN1_TAG_UTCTime,
    ASN1_TAG_GENERALIZEDTime, ASN1_TAG_OBJECT_ID, ASN1_TAG_ENUMERATED, ASN1_TAG_NULL,
    ASN1_TAG_GENERALSTRING, ASN1_TAG_NUMERIC_STRING, ASN1_TAG_IA5_STRING, ASN1_TAG_TELETEX_STRING,
    ASN1_TAG_PRINTABLE_STRING,
    ASN1_TAG_UNIVERSAL_STRING, ASN1_TAG_BMP_STRING, ASN1_TAG_UTF8_STRING,
    ASN1_TAG_VISIBLE_STRING, asn1_node_st, asn1_node, ASN1_MAX_NAME_SIZE, asn1_static_node,
    ASN1_ETYPE_INVALID, ASN1_ETYPE_CONSTANT, ASN1_ETYPE_IDENTIFIER, ASN1_ETYPE_INTEGER,
    ASN1_ETYPE_BOOLEAN, ASN1_ETYPE_SEQUENCE, ASN1_ETYPE_BIT_STRING, ASN1_ETYPE_OCTET_STRING,
    ASN1_ETYPE_TAG, ASN1_ETYPE_DEFAULT, ASN1_ETYPE_SIZE, ASN1_ETYPE_SEQUENCE_OF, ASN1_ETYPE_OBJECT_ID,
    ASN1_ETYPE_ANY, ASN1_ETYPE_SET, ASN1_ETYPE_SET_OF, ASN1_ETYPE_DEFINITIONS, ASN1_ETYPE_CHOICE,
    ASN1_ETYPE_IMPORTS, ASN1_ETYPE_NULL, ASN1_ETYPE_ENUMERATED, ASN1_ETYPE_GENERALSTRING,
    ASN1_ETYPE_NUMERIC_STRING, ASN1_ETYPE_IA5_STRING, ASN1_ETYPE_TELETEX_STRING, ASN1_ETYPE_PRINTABLE_STRING,
    ASN1_ETYPE_UNIVERSAL_STRING, ASN1_ETYPE_BMP_STRING,
    ASN1_ETYPE_UTF8_STRING, ASN1_ETYPE_VISIBLE_STRING, ASN1_ETYPE_UTC_TIME,
    ASN1_ETYPE_GENERALIZED_TIME,
    ASN1_DELETE_FLAG_ZEROIZE,
    ASN1_DECODE_FLAG_ALLOW_PADDING,
    ASN1_DECODE_FLAG_STRICT_DER,
    ASN1_DECODE_FLAG_ALLOW_INCORRECT_TIME, asn1_data_node_st, ASN1_MAX_ERROR_DESCRIPTION_SIZE,

    //    asn1_parser2tree,           // D overloaded
    //  asn1_parser2array, // think about a function asn1_parser2arrayD, that creates a D module file by using function asn1_parser2tree output
    //    asn1_array2tree,            // D overloaded
    //    asn1_print_structure,       // D overloaded
    //    asn1_create_element,        // D overloaded
    asn1_delete_structure,
    asn1_delete_structure2,
    //    asn1_delete_element,        // D overloaded
    asn1_write_value, // D overloaded
    //    asn1_read_value,            // D overloaded
    //    asn1_read_value_type,       // D overloaded
    asn1_read_node_value,
    //    asn1_number_of_elements,    // D overloaded
    //    asn1_der_coding,            // D overloaded
    //    asn1_der_decoding2,         // D overloaded
    //    asn1_der_decoding,          // D overloaded
    //  asn1_der_decoding_element
    //    asn1_der_decoding_startEnd, // D overloaded
    asn1_expand_any_defined_by, asn1_expand_octet_string, // TODO check overloading
    //    asn1_read_tag,              // D overloaded
    asn1_find_structure_from_oid, // TODO check overloading
    //    asn1_check_version,         // D overloaded
    asn1_strerror, asn1_perror, ASN1_MAX_TAG_SIZE, ASN1_MAX_LENGTH_SIZE,
    ASN1_MAX_TL_SIZE,

    //    asn1_get_length_der,        // D overload
    asn1_get_length_ber, // TODO check overloading
    //    asn1_length_der,            // D overloaded

    /* Other utility functions. */
    // TODO check overloading
    //    asn1_decode_simple_der,     // D overloaded
    asn1_decode_simple_ber,
    //    asn1_encode_simple_der,     // D overloaded
    asn1_find_node, asn1_copy_node, asn1_dup_node

    /* Internal and low-level DER utility functions. */
    //    asn1_get_tag_der,
    //    asn1_octet_der,
    //    asn1_get_octet_der,
    //    asn1_bit_der,
    //    asn1_get_bit_der,
    //    asn1_get_object_id_der,

    /* Compatibility types */
    //    asn1_retCode,
    //    node_asn_struct,
    //    node_asn,
    //    ASN1_TYPE,
    //    ASN1_TYPE_EMPTY,
    //    static_struct_asn,
    //    ASN1_ARRAY_TYPE,
    //    asn1_static_node_t,
    //    node_data_struct,
    //    ASN1_DATA_NODE
    ;

import core.stdc.config : c_ulong, c_long;
import std.string : toStringz, fromStringz;
import std.exception : assumeUnique; // assumeWontThrow, assertThrown, assertNotThrown;
import std.traits : Unqual;

nothrow
{

    /* overloading some functions between module deimos.libtasn1 and this module, "overload-set" */

    //alias asn1_parser2tree = deimos.libtasn1.asn1_parser2tree;

    /***********************************
 * Parse algorithm that extracts everything from an ASN.1 module definition file 'inFileNameDefinitions'
 * to an internal representation (IRdef) 'outDefinitions'.
 *
 * Another alternative to process an ASN.1 module definition file would be to use the utility 'asn1Parser',
 * which creates a C source file with definitions as an array, translate that to a D module and import it,
 * to be used with function 'asn1_array2tree':
 * $ asn1Parser -o tasn1_pkcs15.d -n tasn1_pkcs15_tab PKCS15.asn
 * Most of the tedious work can be done with sed:
 * `sed -i s/NULL/null/g tasn1_pkcs15.d`
 * `sed -i 's/"},$/".ptr },/g' tasn1_pkcs15.d`
 * The few remaining changes required can easily be done manually.
 *
 * Params:
 *      inFileNameDefinitions = the path/to/file from which to read ASN.1 definitions
 *      outDefinitions = get's populated with internal representation (IRdef)
 *      error_desc = get's populated if a parsing error occurs
 *
 * Returns: ASN1_SUCCESS  if the file has a correct syntax and every identifier is known,
 *          ASN1_ELEMENT_NOT_EMPTY  if definitions not NULL ???,
 *          ASN1_FILE_NOT_FOUND  if an error occured while opening file,
 *          ASN1_SYNTAX_ERROR  if the syntax is not correct,
 *          ASN1_IDENTIFIER_NOT_FOUND  if in the file there is an identifier that is not defined,
 *          ASN1_NAME_TOO_LONG  if in the file there is an identifier with more than ASN1_MAX_NAME_SIZE characters.
 *
 * See_Also:
 *     https://www.gnu.org/software/libtasn1/manual/libtasn1.html#ASN_002e1-syntax<br>
 *     https://www.gnu.org/software/libtasn1/manual/libtasn1.html#ASN_002e1-schema-functions
 *
 * Bugs: It happend to me with version 4.13, that the algorithm indefinitely allocated memory, resulting in a system crash,
 *       because the definition file included recursive definitions. Thus when using with untested definition files,
 *       it's wise to set ulimit -d  to a reasonable limit in the invoking shell.
 *       Testing of acceptable syntax is best done with utility tool, e.g.:  $ asn1Decoding  pkix.asn  der_file  PKIX1.Dss-Sig-Value
 *
 * Examples:
 * --------------------
 * asn1_node  outDefinitions;
 * string     errorDescription;
 * int  asn1_result = asn1_parser2tree("/path/to/pkix.asn", &outDefinitions, errorDescription);
 * if  (asn1_result != ASN1_SUCCESS)
 * {
 *     ... // exit(1);
 * }
 * --------------------
 */

    pragma(inline, true) int asn1_parser2tree(string inFileNameDefinitions,
            asn1_node* outDefinitions, out string error_desc)
    {
        static import deimos.libtasn1;

        char[ASN1_MAX_ERROR_DESCRIPTION_SIZE] errorDescription;
        immutable result = deimos.libtasn1.asn1_parser2tree(toStringz(inFileNameDefinitions),
                outDefinitions, &errorDescription[0]);
        error_desc = assumeUnique(fromStringz(&errorDescription[0]));
        return result;
    }

    //alias asn1_array2tree = deimos.libtasn1.asn1_array2tree;

    /**
 * Creates the structures needed to manage the ASN.1 definitions. inArrayDefinitions from module ? as created by utility 'asn1Parser' (asn1_parser2array()).
 *
 * Another alternative to process an ASN.1 module definition file would be to use the utility 'asn1Parser',
 * which creates a C source file with definitions as an array, translate that to a D module named ? (e.g. tasn1_pkcs15) and import it,
 * to be used with function 'asn1_array2tree':
 * $ asn1Parser -o tasn1_pkcs15.d -n tasn1_pkcs15_tab PKCS15.asn
 * Most of the tedious work can be done with sed:
 * `sed -i s/NULL/null/g tasn1_pkcs15.d`
 * `sed -i 's/"},$/".ptr },/g' tasn1_pkcs15.d`
 * The few remaining changes required can easily be done manually.
 *
 * Params:
 *      inArrayDefinitions = specify the array that contains ASN.1 declarations
 *      outDefinitions     = return the pointer to the structure created by *ARRAY ASN.1 declarations
 *      error_desc         = return the error description.
 * Returns:  ASN1_SUCCESS if structure was created correctly,
 *           ASN1_ELEMENT_NOT_EMPTY if outDefinitions isn't null,
 *           ASN1_IDENTIFIER_NOT_FOUND if in the file there is an identifier that is not defined (see error_desc for more information),
 *           ASN1_ARRAY_ERROR if the array inArrayDefinitions is wrong.
 */
    //pragma(inline, true)
    int asn1_array2tree(const(asn1_static_node)[] inArrayDefinitions, asn1_node* outDefinitions, out string error_desc) pure  // @suppress(dscanner.style.long_line)
    {
        static import deimos.libtasn1;

        char[ASN1_MAX_ERROR_DESCRIPTION_SIZE] errorDescription;
        immutable result = deimos.libtasn1.asn1_array2tree(&inArrayDefinitions[0], outDefinitions,
                &errorDescription[0]);
        error_desc = assumeUnique(fromStringz(&errorDescription[0]));
        return result;
    }

    /**
 */
    //pragma(inline, true)
    void asn1_print_structure(string outFileStructure, asn1_node inStructure, string whatFromStructure, int mode)
    {
        static import deimos.libtasn1;
        import std.stdio : File;

        try
        {
            auto f = File(outFileStructure, "w"); // open for writing
            deimos.libtasn1.asn1_print_structure(f.getFP(), inStructure, toStringz(whatFromStructure), mode);
        }
        catch (Exception e)
        { /* */ }
    }

    string noneScanner(int /*mode*/ , const(char)[] line)
    {
        return line.idup;
    }

    /* The "raw" output of libtasn1 is not really appealing. Perhaps add a scanner function, that can improve that
 type:OCT_STR may encode ascii, try that (e.g. dirRecord.aid),
 type:BIT_STR show the bit string,
 type:ENUMERATED and INTEGER: show in decimal within reasonable limits
 incorporates some OBJ_ID knowledge: espec. certificate (using ANY) will benefit from that
 GENERALIZED_TIME ?
 prettyprint: spaces, accentuation (bold)
 name:label -> name: label
 variable indentation?

 The Posix restriction only means: I don't know a standard, user-accessible/writable file location on Windows or otherOS
 */
    void asn1_visit_structure(out string[] outStructure, asn1_node inStructure,
            string whatFromStructure, int mode, /*ASN1_PRINT* */
            string function(int mode, const(char)[] line) scanner = null)
    {
        static import deimos.libtasn1;
        import std.stdio : File;
        import std.file : remove, tempDir;
        import std.path : buildPath;
        import std.string : splitLines;

        try
        {
            string fname = tempDir.buildPath(whatFromStructure); // "/tmp/" ~ whatFromStructure;
            auto f = File(fname, "w"); // open for writing
            string[] sarr = splitLines(whatFromStructure);
            foreach (string line; sarr)
                deimos.libtasn1.asn1_print_structure(f.getFP(), inStructure, toStringz(line), mode);
            f.close();
            f = File(fname, "r"); // open for reading
            foreach (const(char)[] line; f.byLine())
                outStructure ~= scanner is null ? line.idup : scanner(mode, line);
            f.close();
            remove(fname);
        }
        catch (Exception e)
        { /* */ }
    }

    /**
 * Creates structure 'element' of type source_name (source_name defined in definitions).
 * After using 'element', in order to avoid a memory leak, 'element' must be deleted by
 * asn1_delete_structure (element);
*/
    //pragma(inline, true)
    int asn1_create_element(asn1_node inDefinitions, string whatFromDefinitions, scope asn1_node* outStructureElement)
    {
        static import deimos.libtasn1;

        return deimos.libtasn1.asn1_create_element(inDefinitions, toStringz(whatFromDefinitions), outStructureElement);
    }

    //pragma(inline, true)
    int asn1_delete_element(asn1_node outStructure, string whichElementOfStructure)
    {
        static import deimos.libtasn1;

        return deimos.libtasn1.asn1_delete_element(outStructure, toStringz(whichElementOfStructure));
    }

    /+ probably not safe as the library may keep around a reference to a garbage collected C string handed over
/* parameter bitLen only to be used, if the type to be written is BIT STRING: bitLen then specifies how many bits have to be written
             disregardElementValueLen only to be used, if the type Unqual!T==char is used: when set to true, the len will be determined by strlen as for C string; dont set for BOOLEAN, OBJECT IDENTIFIER etc.
*/
//pragma(inline, true)
int  asn1_write_value(T) (asn1_node outStructure,
                          string whichElementOfStructure,
                          T[] elementValue, // except for string, if is(Unqual!T==char) then MUST include the terminating zero byte
                          int bitLen=0,
                          bool disregardElementValueLen=false) // set to true for is(Unqual!T==char), if an ordinary  C string is to be evaluated, which needs len==0 instead of len==elementValue.length
if (is(Unqual!T==ubyte) || is(Unqual!T==char))
{
    // TODO make this safe against wrong usage (bitLen spec. but type != BIT STRING)
    assert(elementValue !is null); // just in order to protect against unintended deletion
    static if (is(Unqual!T==char)) {
        if (disregardElementValueLen) {
            /* If is(T[]==string), then the terminating null must be added, otherwise it's assumed it's already there/in place */
            static if (is(T==immutable(char)))
                return  asn1_write_value (outStructure, toStringz(whichElementOfStructure), toStringz(elementValue), 0);
            else
                return  asn1_write_value (outStructure, toStringz(whichElementOfStructure), elementValue.ptr, 0);
        }
        else
            return  asn1_write_value (outStructure, toStringz(whichElementOfStructure), elementValue.ptr, cast(int)elementValue.length);
    }
    else
        return  asn1_write_value (outStructure, toStringz(whichElementOfStructure), elementValue.ptr, bitLen? bitLen : cast(int)elementValue.length);
}
+/

    /**
  outLen is in bytes except for BIT STRING
 */
    //pragma(inline, true)
    int asn1_read_value(T)(const asn1_node structureRoot, string whichElementOfStructure,
            scope T[] outValue, out int outLen) if (is(T == ubyte) || is(T == char))
    {
        static import deimos.libtasn1;

        int inoutLen = cast(int) outValue.length;
        immutable result = deimos.libtasn1.asn1_read_value(structureRoot,
                toStringz(whichElementOfStructure), outValue.ptr, &inoutLen); // signature changed from original: int  asn1_read_value (asn1_node root, ...
        outLen = inoutLen;
        return result;
    }

    //pragma(inline, true)
    int asn1_read_value_type(T)(const asn1_node structureRoot, string whichElementOfStructure,
            scope T[] outValue, out int outLen, out uint etype) if (is(T == ubyte) || is(T == char))
    {
        static import deimos.libtasn1;

        int inoutLen = cast(int) outValue.length;
        immutable result = deimos.libtasn1.asn1_read_value_type(structureRoot,
                toStringz(whichElementOfStructure), outValue.ptr, &inoutLen, &etype); // signature changed from original: int  asn1_read_value_type (asn1_node root, ...
        outLen = inoutLen;
        return result;
    }

    //pragma(inline, true)
    int asn1_number_of_elements(asn1_node structureElement, string whichElementSubStructureOfStructure, out int num)
    {
        static import deimos.libtasn1;

        return deimos.libtasn1.asn1_number_of_elements(structureElement,
                toStringz(whichElementSubStructureOfStructure), &num);
    }

    //pragma(inline, true)
    int asn1_der_coding(asn1_node structure, string whichElementOfStructure, scope ubyte[] outDer,
            out int outLen, out string error_desc)
    {
        static import deimos.libtasn1;

        char[ASN1_MAX_ERROR_DESCRIPTION_SIZE] errorDescription;
        int inoutLen = cast(int) outDer.length;
        immutable result = deimos.libtasn1.asn1_der_coding(structure,
                toStringz(whichElementOfStructure), outDer.ptr, &inoutLen, &errorDescription[0]);
        outLen = inoutLen;
        error_desc = assumeUnique(fromStringz(&errorDescription[0]));
        return result;
    }

    version (travis)
    {
    } // travis trusty has an old version of libtasn1 installed, without asn1_der_decoding2, thus fails to link to_der_decoding2
    else
    {
        //pragma(inline, true)
        int asn1_der_decoding2(asn1_node* structureElement, const(ubyte)[] inDer, out int der_len,
                uint flags, out string error_desc)
        {
            static import deimos.libtasn1;

            char[ASN1_MAX_ERROR_DESCRIPTION_SIZE] errorDescription;
            int inoutLen = cast(int) inDer.length;
            immutable result = deimos.libtasn1.asn1_der_decoding2(structureElement, inDer.ptr,
                    &inoutLen, flags, errorDescription.ptr);
            der_len = inoutLen;
            error_desc = assumeUnique(fromStringz(&errorDescription[0]));
            return result;
        }
    } // version(travis) else

    /**
 * Fill the structure 'element' with values of a DER encoding string. The structure must exist already, created by function asn1_create_element() .
 */
    //pragma(inline, true)
    int asn1_der_decoding(asn1_node* structureElement, const(ubyte)[] inDer, out string error_desc)
    {
        static import deimos.libtasn1;

        char[ASN1_MAX_ERROR_DESCRIPTION_SIZE] errorDescription;
        int result = deimos.libtasn1.asn1_der_decoding(structureElement, inDer.ptr,
                cast(int) inDer.length, errorDescription.ptr);
        error_desc = assumeUnique(fromStringz(&errorDescription[0]));
        return result;
    }

    //pragma(inline, true)
    int asn1_der_decoding_startEnd(asn1_node structure, const(ubyte)[] inDer,
            string whichElementOfStructure, out int start, out int end)
    {
        static import deimos.libtasn1;

        return deimos.libtasn1.asn1_der_decoding_startEnd(structure, inDer.ptr,
                cast(int) inDer.length, toStringz(whichElementOfStructure), &start, &end);
    }

    //pragma(inline, true)
    int asn1_read_tag(asn1_node structureRoot, string whichElementOfStructure, out int tagValue, out int classValue)
    {
        static import deimos.libtasn1;

        return deimos.libtasn1.asn1_read_tag(structureRoot, toStringz(whichElementOfStructure),
                &tagValue, &classValue);
    }

    //pragma(inline, true)
    string asn1_check_version(string req_version) pure
    {
        static import deimos.libtasn1;

        return fromStringz(deimos.libtasn1.asn1_check_version(toStringz(req_version)));
    }

    /** The same as asn1_strerror, but returning a D string instead of null-terminated "C string" */
    //pragma(inline, true)
    string asn1_strerror2(int error) pure
    {
        return fromStringz(asn1_strerror(error));
    }

    /* inDer: do point to L of TLV */
    //pragma(inline, true)
    c_long asn1_get_length_der(const(ubyte)[] inDer, out int lenDerLengthField)
    {
        static import deimos.libtasn1;

        return deimos.libtasn1.asn1_get_length_der(inDer.ptr, cast(int) inDer.length, &lenDerLengthField);
    }

    //pragma(inline, true)
    void asn1_length_der(c_ulong len, scope ubyte[] der, out int der_len) pure
    {
        static import deimos.libtasn1;

        int inoutLen = cast(int) der.length;
        deimos.libtasn1.asn1_length_der(len, der.ptr, &inoutLen);
        der_len = inoutLen;
    }

    /* Other utility functions. */

    //pragma(inline, true)
    int asn1_decode_simple_der(uint etype, const(ubyte)[] der, out ptrdiff_t posDer, out uint outLen)
    {
        static import deimos.libtasn1;

        const(ubyte)* str;
        int result = deimos.libtasn1.asn1_decode_simple_der(etype, der.ptr, cast(uint) der.length, &str, &outLen);
        posDer = result == ASN1_SUCCESS && str && str - der.ptr >= 0 && str - der.ptr < der.length ? str - der.ptr : -1;
        return result;
    }

    int asn1_encode_simple_der(uint etype, const(ubyte)[] inData, ref ubyte[ASN1_MAX_TL_SIZE] tl, out uint tl_len)
    {
        static import deimos.libtasn1;

        uint inoutTl_len = tl.length;
        int result = deimos.libtasn1.asn1_encode_simple_der(etype, inData.ptr,
                cast(uint) inData.length, tl.ptr, &inoutTl_len);
        tl_len = inoutTl_len;
        return result;
    }

} // nothrow

version (unittest)
{
    import std.stdio;
    import std.conv : hexString, to;
    import std.algorithm.comparison : equal;
    import std.exception : assumeWontThrow; // assumeUnique, assertThrown, assertNotThrown;
    import std.range.primitives : empty;
    import tasn1_pkcs15;

    /* add space after name:, type: and value:
       pretty-print BIT STRING
    */
    string someScanner(int mode, const(char)[] line)
    {
        import core.stdc.stdlib : strtoull;
        import core.bitop : bitswap;
        import std.string : indexOf;
        import std.math : pow;

        string res;
        try
        {
            ptrdiff_t pos = indexOf(line, "name:");
            if (pos == -1)
                return line.idup;
            res = assumeUnique(line[0 .. pos + 5]) ~ " " ~ assumeUnique(line[pos + 5 .. $]);
            if (mode > ASN1_PRINT_NAME)
            {
                pos = indexOf(res, "type:");
                if (pos != -1)
                    res = res[0 .. pos + 5] ~ " " ~ res[pos + 5 .. $];
            }
            if (mode > ASN1_PRINT_NAME_TYPE)
            {
                pos = indexOf(res, "value");
                if (pos != -1)
                {
                    import std.regex : regex, replaceFirst, matchFirst;

                    auto valueRegcolon = regex(r"  value(?:\(\d+\)){0,1}:");
                    auto valueRegBITSTRING = regex(r".*value(?:\((\d+)\)){1}: ([0-9A-Fa-f]{2,16}){1}.*"); // overall+2 captures: bitLen and value
                    res = replaceFirst(res, valueRegcolon, "$& "); // add the space after value...:
                    auto m = matchFirst(res, valueRegBITSTRING);
                    if (!m.empty && to!int(m[1]) <= 64 && m[2].length <= 16)
                    { // gdc selects bitswap(uint) but not bitswap(ulong) ?? why ??? https://travis-ci.org/carblue/tasn1/jobs/551326939
                        immutable ulong tmp = bitswap(strtoull(m[2].toStringz, null, 16) << 8 * (8 - m[2].length / 2));
                        res ~= "  ->  ";
                        foreach (i; 0 .. to!int(m[1]))
                            res ~= (tmp & pow(2, i)) ? "1" : "0";
                    }
                }
            }
            return res;
        }
        catch (Exception e)
        { /* todo: handle exception */ }
        return line.idup;
    }

    // for all unittests:
    asn1_node IRdef; // @suppress(dscanner.style.phobos_naming_convention)
    int asn1_result;
    string error_desc;
    char[ASN1_MAX_ERROR_DESCRIPTION_SIZE] errorDescription;
    int outLen;

    // some known DERencoded data:
    immutable(ubyte)[] der_DIR;
    immutable(ubyte)[] der_AuthenticationType;

    shared static this()
    {
//      asn1_result = asn1_parser2tree("PKCS15.asn", &IRdef, error_desc);
        asn1_result = asn1_array2tree(tasn1_pkcs15_tab, &IRdef, error_desc);

        assert(asn1_result == ASN1_SUCCESS);
        //        writeln("Return result for asn1_parser2tree (PKCS15.asn, &IRdef... : ", asn1_result);

        /* http://lapo.it/asn1js/  decoding the following der_DIR:
        Application 1 (3 elem)
          Application 15  ACOSPKCS-15v1.00
          Application 16  eCert
          Application 17 (4 byte) 3F004100

        The structure's name is "DIRRecord" in "PKCS15.asn":
        DIRRecord ::=   [APPLICATION 1] SEQUENCE {
            aid      [APPLICATION 15] OCTET STRING,
            label    [APPLICATION 16] UTF8String OPTIONAL,
            path     [APPLICATION 17] OCTET STRING,
            ddo      [APPLICATION 19] DDO OPTIONAL
        }

        DDO ::= SEQUENCE {
            oid        OBJECT IDENTIFIER,
            odfPath        Path OPTIONAL,
            tokenInfoPath  [0] Path OPTIONAL,
            unusedPath     [1] Path OPTIONAL
        }
        */
        der_DIR = cast(immutable(ubyte)[]) hexString!"61 1F 4F 10 41 43 4F 53 50
            4B 43 53 2D 31 35 76 31 2E 30 30 50 05 65 43 65 72 74 51 04 3F 00 41 00";

        /*
        SEQUENCE (3 elem)
          SEQUENCE (2 elem)
            UTF8String User                         "pinAuthObj.commonObjectAttributes.label"
            BIT STRING (2 bit) 11                   "pinAuthObj.commonObjectAttributes.flags"
          SEQUENCE (1 elem)
            OCTET STRING (1 byte) 01                "pinAuthObj.commonAuthenticationObjectAttributes.authId"
          [1] (1 elem)
            SEQUENCE (8 elem)
              BIT STRING (12 bit) 110011000000      "pinAuthObj.pinAttributes.pinFlags"
              ENUMERATED 1                          "pinAuthObj.pinAttributes.pinType"
              INTEGER 4                             "pinAuthObj.pinAttributes.minLength"
              INTEGER 8                             "pinAuthObj.pinAttributes.storedLength"
              INTEGER 8                             "pinAuthObj.pinAttributes.maxLength"
              [0] (1 byte) 01                       "pinAuthObj.pinAttributes.pinReference"
              OCTET STRING (1 byte) FF              "pinAuthObj.pinAttributes.padChar"
              SEQUENCE (1 elem)
                OCTET STRING (4 byte) 3F004100      "pinAuthObj.pinAttributes.path.path"

        name: pinAuthObj  type: SEQUENCE
          name: commonObjectAttributes  type: SEQUENCE
            name: label  type: UTF8_STR  value: User
            name: flags  type: BIT_STR  value(2): c0  ->  11
          name: commonAuthenticationObjectAttributes  type: SEQUENCE
            name: authId  type: OCT_STR  value: 01
          name: pinAttributes  type: SEQUENCE
            name: pinFlags  type: BIT_STR  value(12): cc00  ->  110011000000
            name: pinType  type: ENUMERATED  value: 0x01
            name: minLength  type: INTEGER  value: 0x04
            name: storedLength  type: INTEGER  value: 0x08
            name: maxLength  type: INTEGER  value: 0x08
            name: pinReference  type: INTEGER  value: 0x01
              name: NULL  type: DEFAULT  value: 0
            name: padChar  type: OCT_STR  value: ff
            name: path  type: SEQUENCE
              name: path  type: OCT_STR  value: 3f004100

        This is structure PKCS15.AuthenticationObjectPin, one of several selectable within AuthenticationType ::= CHOICE
        */
        der_AuthenticationType = cast(immutable(ubyte)[]) hexString!"30 34 30 0A 0C 04 55 73 65 72 03 02 06 C0 30 03 04
01 01 A1 21 30 1F 03 03 04 CC 00 0A 01 01 02 01 04 02 01 08 02 01 08 80 01 01 04 01 FF 30 06 04 04 3F 00 41 00";
    }
} // version(unittest)

/*nothrow*/
unittest
{ // read OCTET STRING, UTF8String, OPTIONAL handling, error returns
    //read the aid (OCTET STRING), ... value which is encoded within der_DIR

    asn1_node structure_DIRRecord;

    assert(ASN1_SUCCESS == asn1_create_element(IRdef, "PKCS15.DIRRecord", &structure_DIRRecord));
    scope (exit)
        asn1_delete_structure(&structure_DIRRecord);
    assert(ASN1_SUCCESS == asn1_der_decoding(&structure_DIRRecord, der_DIR, error_desc));

    ubyte[32] aid; // OCTET STRING; how to retrieve, how much memory must be preallocated ? Going to read an OCTET STRING !
    auto aid_expected = cast(immutable(ubyte)[]) "ACOSPKCS-15v1.00";
    assert(ASN1_SUCCESS == asn1_read_value(structure_DIRRecord, "aid", aid, outLen));
    assert(equal(aid_expected, aid[0 .. outLen]));

    ubyte[32] label; // UTF8String OPTIONAL
    auto label_expected = cast(immutable(ubyte)[]) "eCert";
    assert(ASN1_SUCCESS == asn1_read_value(structure_DIRRecord, "label", label, outLen));
    assert(equal(label_expected, label[0 .. outLen]));

    ubyte[16] path; // OCTET STRING
    auto path_expected = cast(immutable(ubyte)[]) hexString!"3F00 4100";
    assert(ASN1_SUCCESS == asn1_read_value(structure_DIRRecord, "path", path, outLen));
    assert(equal(path_expected, path[0 .. outLen]));

    // nonexisting, IRdef defined optional ddo.oid
    ubyte[32] ddo_oid;
    assert(ASN1_ELEMENT_NOT_FOUND == asn1_read_value(structure_DIRRecord, "ddo.oid", ddo_oid, outLen));

    // nonexisting, IRdef non-defined ddo.something
    ubyte[32] ddo_something;
    assert(ASN1_ELEMENT_NOT_FOUND == asn1_read_value(structure_DIRRecord, "ddo.something", ddo_something, outLen));

    // path again, but less memory allocated than required
    ubyte[2] path2;
    assert(ASN1_MEM_ERROR == asn1_read_value(structure_DIRRecord, "path", path2, outLen));
    assert(path_expected.length == outLen);
}

/*nothrow*/
unittest
{ // read UTF8String, BIT STRING, ENUMERATED, INTEGER, Context tagged handling
    static import deimos.libtasn1;

    //read some values
    asn1_node structure_AuthenticationType;

    assert(ASN1_SUCCESS == asn1_create_element(IRdef, "PKCS15.AuthenticationType", &structure_AuthenticationType));
    scope (exit)
        asn1_delete_structure(&structure_AuthenticationType);
    assert(ASN1_SUCCESS == asn1_der_decoding(&structure_AuthenticationType, der_AuthenticationType, error_desc));

    int lenDerLengthField; // @suppress(dscanner.suspicious.unmodified)
    immutable c_long lenDerLength = asn1_get_length_der(der_AuthenticationType[$ - 7 .. $], lenDerLengthField);
    assert(lenDerLength == 6);
    assert(lenDerLengthField == 1);

    ubyte[32] label;
    auto label_expected = cast(immutable(ubyte)[]) "User";
    assert(ASN1_SUCCESS == asn1_read_value(structure_AuthenticationType,
            "pinAuthObj.commonObjectAttributes.label", label, outLen));
    assert(equal(label_expected, label[0 .. outLen]));

    // label again, now reading from der directly:
    const(ubyte)* str;
    uint outLenU;
    immutable uint offset = 4; // the encoding of label in der_AuthenticationType starts here and occupies 6 bytes
    assert(ASN1_SUCCESS == deimos.libtasn1.asn1_decode_simple_der(ASN1_ETYPE_UTF8_STRING,
            der_AuthenticationType.ptr + offset, 6, &str, &outLenU));
    assert(equal(label_expected, str[0 .. outLenU]));

    // label again, D overload:
    ptrdiff_t posSimple;
    assert(ASN1_SUCCESS == asn1_decode_simple_der(ASN1_ETYPE_UTF8_STRING,
            der_AuthenticationType[offset .. offset + 6], posSimple, outLenU));
    //    assumeWontThrow(writefln("%s   %s", posSimple, outLenU));
    assert(equal(label_expected, der_AuthenticationType[offset + posSimple .. offset + posSimple + outLenU]));

    ubyte[1] flags; // for 2 bits
    auto flags_expected = cast(immutable(ubyte)[]) hexString!"C0"; // 0b11000000; flags private and modifiable are set
    assert(ASN1_SUCCESS == asn1_read_value(structure_AuthenticationType,
            "pinAuthObj.commonObjectAttributes.flags", flags, outLen));
    assert(outLen == 2); // outLen for BIT STRING is in bits
    assert(equal(flags_expected, flags[]));

    ubyte[2] pinFlags; // for 12 bits
    auto pinFlags_expected = cast(immutable(ubyte)[]) hexString!"CC 00"; // 0b11001100_00000000; flags sensitive, local, initialized and needs-padding are set
    assert(ASN1_SUCCESS == asn1_read_value(structure_AuthenticationType,
            "pinAuthObj.pinAttributes.pinFlags", pinFlags, outLen));
    assert(outLen == 12);
    assert(equal(pinFlags_expected, pinFlags[]));

    int start;
    int end;
    ubyte[] der; // can be left unspecified since 3.7
    auto pinFlags_encodingBytes_expected = cast(immutable(ubyte)[]) hexString!"03 03 04 CC 00";
    version (travis)
    {
    } // travis has an old version of libtasn1 installed, with asn1_der_decoding_startEnd behaving differently
    else
    {
        assert(ASN1_SUCCESS == asn1_der_decoding_startEnd(structure_AuthenticationType, der,
                "pinAuthObj.pinAttributes.pinFlags", start, end));
        assert(equal(pinFlags_encodingBytes_expected, der_AuthenticationType[start .. end + 1]));
    }
    ubyte[1] pinType; // ENUMERATED, won't reach 0x80 for negatives
    immutable pinType_expected = 1;
    assert(ASN1_SUCCESS == asn1_read_value(structure_AuthenticationType,
            "pinAuthObj.pinAttributes.pinType", pinType, outLen));
    assert(pinType_expected == pinType[0]);

    ubyte[1] minLength; // INTEGER, won't reach 0x80 for negatives
    immutable minLength_expected = 4;
    assert(ASN1_SUCCESS == asn1_read_value(structure_AuthenticationType,
            "pinAuthObj.pinAttributes.minLength", minLength, outLen));
    assert(minLength_expected == minLength[0]);

    ubyte[1] pinReference; // Reference (INTEGER 0..255), context tagged, migth reach 0x80 for negatives
    immutable pinReference_expected = 1;
    uint etype; // @suppress(dscanner.suspicious.unmodified)
    assert(ASN1_SUCCESS == asn1_read_value_type(structure_AuthenticationType,
            "pinAuthObj.pinAttributes.pinReference", pinReference, outLen, etype));
    assert(pinReference_expected == pinReference[0]);
    assert(ASN1_ETYPE_INTEGER == etype); // this info is from IRdef, not from der !

    int tagValue; // @suppress(dscanner.suspicious.unmodified)
    int classValue; // @suppress(dscanner.suspicious.unmodified)
    assert(ASN1_SUCCESS == asn1_read_tag(structure_AuthenticationType,
            "pinAuthObj.pinAttributes.pinReference", tagValue, classValue));
    assert(0 == tagValue);
    assert(ASN1_CLASS_CONTEXT_SPECIFIC == classValue);

    /*  uncomment and adapt, knowing the specific binary version installed; won't work in general for any version ! * /
    assert(equal(ASN1_VERSION, asn1_check_version (ASN1_VERSION))); // 4.13
    assert(equal(ASN1_VERSION, asn1_check_version ("4.12")));
/ * */
    assert(equal("", asn1_check_version("5.999"))); // will work only as long as latest binary version < 5.999
    assumeWontThrow(writeln("Binary libtasn1 version installed: ", asn1_check_version("")));

    int der_len;
    ubyte[] der2;
    asn1_length_der(127, der2, der_len);
    assert(1 == der_len);
    ubyte[3] der3;
    der_len = 0;
    asn1_length_der(128, der3, der_len);
    assert(2 == der_len);
    assert(equal([0x81, 0x80], der3[0 .. der_len]));
    der_len = 0;
    asn1_length_der(256, der3, der_len);
    assert(3 == der_len);
    assert(equal([0x82, 1, 0], der3[0 .. der_len]));

    auto tl_expected = cast(immutable(ubyte)[]) hexString!"04 81 80";
    ubyte[] inData = new ubyte[128];
    ubyte[ASN1_MAX_TL_SIZE] tl;
    uint tl_len; // @suppress(dscanner.suspicious.unmodified)
    assert(ASN1_SUCCESS == asn1_encode_simple_der(ASN1_ETYPE_OCTET_STRING, inData, tl, tl_len));
    assert(equal(tl_expected, tl[0 .. tl_len]));

    version (Posix)
    {
        string[] outStructure;
        asn1_visit_structure(outStructure, structure_AuthenticationType, "pinAuthObj",
                ASN1_PRINT_NAME_TYPE_VALUE, &someScanner);
        foreach (line; outStructure)
            assumeWontThrow(writeln(line));
    }
    //    int num;
    //    assert(ASN1_SUCCESS == asn1_number_of_elements (structure_AuthenticationType, "pinAuthObj", num));
    //    assumeWontThrow(writeln(num));
    // TODO read INTEGER requiring more than 1 byte !
    // TODO read a Reference value >= 0x80

}
