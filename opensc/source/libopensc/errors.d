/*
 * errors.h: OpenSC error codes
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2016-  for the binding: Carsten Blüggel <bluecars@posteo.eu>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
/*
Written in the D programming language.
For git maintenance (ensure at least one congruent line with originating C header):
#define _OPENSC_ERRORS_H

Content covered by this file is ALL of header C/libopensc/asn1.h
ALL extern(C) functions are exported from "libopensc.so|opensc.dll" binary, except those controlled by PATCH_LIBOPENSC_EXPORTS
*/

module libopensc.errors;

enum {
	SC_SUCCESS                             = 0,

	/* Errors related to reader operation */
	SC_ERROR_READER                        = -1100,
	SC_ERROR_NO_READERS_FOUND              = -1101,
	/* Unused: -1102 */
	/* Unused: -1103 */
	SC_ERROR_CARD_NOT_PRESENT              = -1104,
	SC_ERROR_CARD_REMOVED                  = -1105,
	SC_ERROR_CARD_RESET                    = -1106,
	SC_ERROR_TRANSMIT_FAILED               = -1107,
	SC_ERROR_KEYPAD_TIMEOUT                = -1108,
	SC_ERROR_KEYPAD_CANCELLED              = -1109,
	SC_ERROR_KEYPAD_PIN_MISMATCH           = -1110,
	SC_ERROR_KEYPAD_MSG_TOO_LONG           = -1111,
	SC_ERROR_EVENT_TIMEOUT                 = -1112,
	SC_ERROR_CARD_UNRESPONSIVE             = -1113,
	SC_ERROR_READER_DETACHED               = -1114,
	SC_ERROR_READER_REATTACHED             = -1115,
	SC_ERROR_READER_LOCKED                 = -1116,

	/* Resulting from a card command or related to the card*/
	SC_ERROR_CARD_CMD_FAILED               = -1200,
	SC_ERROR_FILE_NOT_FOUND                = -1201,
	SC_ERROR_RECORD_NOT_FOUND              = -1202,
	SC_ERROR_CLASS_NOT_SUPPORTED           = -1203,
	SC_ERROR_INS_NOT_SUPPORTED             = -1204,
	SC_ERROR_INCORRECT_PARAMETERS          = -1205,
	SC_ERROR_WRONG_LENGTH                  = -1206,
	SC_ERROR_MEMORY_FAILURE                = -1207,
	SC_ERROR_NO_CARD_SUPPORT               = -1208,
	SC_ERROR_NOT_ALLOWED                   = -1209,
	SC_ERROR_INVALID_CARD                  = -1210,
	SC_ERROR_SECURITY_STATUS_NOT_SATISFIED = -1211,
	SC_ERROR_AUTH_METHOD_BLOCKED           = -1212,
	SC_ERROR_UNKNOWN_DATA_RECEIVED         = -1213,
	SC_ERROR_PIN_CODE_INCORRECT            = -1214,
	SC_ERROR_FILE_ALREADY_EXISTS           = -1215,
	SC_ERROR_DATA_OBJECT_NOT_FOUND         = -1216,
	SC_ERROR_NOT_ENOUGH_MEMORY             = -1217,
	SC_ERROR_CORRUPTED_DATA                = -1218,
	SC_ERROR_FILE_END_REACHED              = -1219,
	SC_ERROR_REF_DATA_NOT_USABLE           = -1220,

	/* Returned by OpenSC library when called with invalid arguments */
	SC_ERROR_INVALID_ARGUMENTS             = -1300,
	/* Unused: -1301 */
	/* Unused: -1302 */
	SC_ERROR_BUFFER_TOO_SMALL              = -1303,
	SC_ERROR_INVALID_PIN_LENGTH            = -1304,
	SC_ERROR_INVALID_DATA                  = -1305,

	/* Resulting from OpenSC internal operation */
	SC_ERROR_INTERNAL                      = -1400,
	SC_ERROR_INVALID_ASN1_OBJECT           = -1401,
	SC_ERROR_ASN1_OBJECT_NOT_FOUND         = -1402,
	SC_ERROR_ASN1_END_OF_CONTENTS          = -1403,
	SC_ERROR_OUT_OF_MEMORY                 = -1404,
	SC_ERROR_TOO_MANY_OBJECTS              = -1405,
	SC_ERROR_OBJECT_NOT_VALID              = -1406,
	SC_ERROR_OBJECT_NOT_FOUND              = -1407,
	SC_ERROR_NOT_SUPPORTED                 = -1408,
	SC_ERROR_PASSPHRASE_REQUIRED           = -1409,
	SC_ERROR_INCONSISTENT_CONFIGURATION    = -1410,
	SC_ERROR_DECRYPT_FAILED                = -1411,
	SC_ERROR_WRONG_PADDING                 = -1412,
	SC_ERROR_WRONG_CARD                    = -1413,
	SC_ERROR_CANNOT_LOAD_MODULE            = -1414,
	SC_ERROR_OFFSET_TOO_LARGE              = -1415,
	SC_ERROR_NOT_IMPLEMENTED               = -1416,
	SC_ERROR_INVALID_TLV_OBJECT            = -1417,  // since v0.19.0
	SC_ERROR_TLV_END_OF_CONTENTS           = -1418,  // since v0.19.0

	/* Relating to PKCS #15 init stuff */
	SC_ERROR_PKCS15INIT                    = -1500,
	SC_ERROR_SYNTAX_ERROR                  = -1501,
	SC_ERROR_INCONSISTENT_PROFILE          = -1502,
	SC_ERROR_INCOMPATIBLE_KEY              = -1503,
	SC_ERROR_NO_DEFAULT_KEY                = -1504,
	SC_ERROR_NON_UNIQUE_ID                 = -1505,
	SC_ERROR_CANNOT_LOAD_KEY               = -1506,
	/* Unused: -1507 */
	SC_ERROR_TEMPLATE_NOT_FOUND            = -1508,
	SC_ERROR_INVALID_PIN_REFERENCE         = -1509,
	SC_ERROR_FILE_TOO_SMALL                = -1510,

	/* Related to secure messaging */
	SC_ERROR_SM                            = -1600,
	SC_ERROR_SM_ENCRYPT_FAILED             = -1601,
	SC_ERROR_SM_INVALID_LEVEL              = -1602,
	SC_ERROR_SM_NO_SESSION_KEYS            = -1603,
	SC_ERROR_SM_INVALID_SESSION_KEY        = -1604,
	SC_ERROR_SM_NOT_INITIALIZED            = -1605,
	SC_ERROR_SM_AUTHENTICATION_FAILED      = -1606,
	SC_ERROR_SM_RAND_FAILED                = -1607,
	SC_ERROR_SM_KEYSET_NOT_FOUND           = -1608,
	SC_ERROR_SM_IFD_DATA_MISSING           = -1609,
	SC_ERROR_SM_NOT_APPLIED                = -1610,
	SC_ERROR_SM_SESSION_ALREADY_ACTIVE     = -1611,
	SC_ERROR_SM_INVALID_CHECKSUM           = -1612,

	/* Errors that do not fit the categories above */
	SC_ERROR_UNKNOWN                       = -1900,
	SC_ERROR_PKCS15_APP_NOT_FOUND          = -1901,
}

extern(C) const(char)* sc_strerror(int sc_errno) @nogc nothrow pure @trusted;
