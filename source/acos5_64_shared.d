/*
 * Written in the D programming language, part of packages acos5_64/acos5_64_gui.
 * acos5_64_shared.d: Shared declarations, definitions.
 *
 * Copyright (C) 2016- : Carsten Blüggel <bluecars@posteo.eu>
 *
 * This application is free software; You can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation,
 * version 2.0 of the License.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this application; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335  USA
 */

/*
There is no topical reason why things are here, except this one:
Code/declarations required by both acos5_64 driver and tool acos5_64_gui
*/

module acos5_64_shared;

import core.stdc.config : c_ulong;
import std.algorithm.comparison : /*min, max, clamp, equal, mismatch,*/ among;
import std.conv : hexString;

import libopensc.opensc;// "dependencies" : "opensc": "==0.15.14",   : sc_card,SC_ALGORITHM_DES, SC_ALGORITHM_3DES, SC_ALGORITHM_AES; // to much to make sense listing // sc_format_path, SC_ALGORITHM_RSA, sc_print_path, sc_file_get_acl_entry
import libopensc.types;  // to much to make sense listing // sc_path, sc_atr, sc_file, sc_serial_number, SC_MAX_PATH_SIZE, SC_PATH_TYPE_PATH, sc_apdu, SC_AC_OP_GENERATE;
import libopensc.errors; // to much to make sense listing ?
import libopensc.log;
import libopensc.iso7816;


alias  ub2  = ubyte[2];
alias  ub8  = ubyte[8];
alias  ub16 = ubyte[16];
alias  ub24 = ubyte[24];
alias  ub32 = ubyte[32];
alias  uba  = ubyte[];


enum ubyte MAX_FCI_GET_RESPONSE_LEN = 86; //[EnumMembers!ISO7816_TAG_FCP_    ].fold!((a, b) => a + 2+TAG_FCP_len(b))(-12) +
										  //[EnumMembers!ISO7816_RFU_TAG_FCP_].fold!((a, b) => a + 2+TAG_FCP_len(b))(0); // Σ:86 //2(6F) [+4(80)] +8(82)+4(83) [+18(84)]+3(88)+3(8A)+10(8C)  [+4(8D) +34(AB)]
//pragma(msg, "compiling...MAX_FCI_GET_RESPONSE_LEN is: ", MAX_FCI_GET_RESPONSE_LEN);

immutable ubyte[/*33*/][5] seFIPS = [
	cast(immutable ubyte[/*33*/])hexString!"80 01 01 A4 06 83 01 01 95 01 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	cast(immutable ubyte[/*33*/])hexString!"80 01 02 A4 06 83 01 01 95 01 80 B4 09 80 01 02 83 01 02 95 01 30 B8 09 80 01 02 83 01 02 95 01 30",
	cast(immutable ubyte[/*33*/])hexString!"80 01 03 A4 06 83 01 81 95 01 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	cast(immutable ubyte[/*33*/])hexString!"80 01 04 A4 06 83 01 81 95 01 08 B4 09 80 01 02 83 01 02 95 01 30 B8 09 80 01 02 83 01 02 95 01 30",
	cast(immutable ubyte[/*33*/])hexString!"80 01 05 B4 09 80 01 02 83 01 02 95 01 30 B8 09 80 01 02 83 01 02 95 01 30 00 00 00 00 00 00 00 00",
];

immutable ubyte[/*48*/][1] se64K0 = [
	cast(immutable ubyte[/*48*/])hexString!"80 01 01 A4 06 83 01 01 95 01 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
];

immutable ubyte[/*48*/][4] se64K1 = [
	cast(immutable ubyte[/*48*/])hexString!"80 01 01 A4 06 83 01 81 95 01 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	cast(immutable ubyte[/*48*/])hexString!"80 01 02 B4 09 83 01 01 95 01 30 80 01 02 B8 09 83 01 01 95 01 30 80 01 02 A4 06 83 01 81 95 01 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	cast(immutable ubyte[/*48*/])hexString!"80 01 03 A4 06 83 01 01 95 01 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	cast(immutable ubyte[/*48*/])hexString!"80 01 04 A4 09 83 01 01 83 01 81 95 01 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
];

nothrow extern(C) {
alias  ft_cm_7_3_1_14_get_card_info =  int function(sc_card* card,
	const card_info_type  type,
	const ubyte           fileAtPos_PinRef_KeyRef,
	out ushort            SW1SW2,
	out ubyte             responseLen,
	out ubyte[]           response, //=null,
	c_ulong               apdu_flags=0 //, scope ubyte[]         command_bytes=null
	) /*@nogc nothrow pure*/ @safe;

alias  ft_acos5_64_short_select =  int function(sc_card* card,
    fci_se_info* info,
    ub2 fid,
    bool skip_seid_retrieval,
    ubyte[] outbuf = null);

// a wrapper for sc_update_binary
alias  ft_uploadHexfile =  int function(sc_card* card,
	const(char)* filePathName,
	uint idx,
	size_t count,
	c_ulong flags);

alias  ft_cry_____7_4_4___46_generate_keypair_RSA =  int function(sc_card* card, scope const ubyte[] lv_key_len_type_data) /*@safe*/;

alias  ft_control_generate_key =  int function(bool, bool=false, bool=true);

//alias  ft_aa_7_2_6_82_external_authentication = int function(sc_card* card, ubyte KeyID, scope sc_remote_data* rdata=null) @trusted;
//alias  ft_getTreeTypeFSy = tnTypePtry[] function();
} // nothrow extern(C)

/+
enum CRT_TAG : ubyte {
	HT      = 0xAA,   // Hash Template                 : AND:      Algorithm
	AT      = 0xA4,   // Authentication Template       : AND: UQB, Pin_Key,
	DST     = 0xB6,   // Digital Signature Template    : AND: UQB, Algorithm, KeyFile_RSA
	CT_asym = 0xB8+1, // Confidentiality Template      : AND: UQB, Algorithm       OR: KeyFile_RSA
	CT_sym  = 0xB8+0, // Confidentiality Template      : AND: UQB, Algorithm       OR: ID_Pin_Key_Local_Global, HP_Key_Session  ; OPT: Initial_Vector
	CCT     = 0xB4,   // Cryptographic Checksum Templ. : AND: UQB, Algorithm  ;    OR: ID_Pin_Key_Local_Global, HP_Key_Session  ; OPT: Initial_Vector
	NA      = 0x00,   // N/A unknown
}
//mixin FreeEnumMembers!CRT_TAG;

enum Usage {
	/* HT */
	None,
	/* AT 1*/
	Pin_Verify_and_SymKey_Authenticate,
	SymKey_Authenticate,
	Pin_Verify,
	/* DST 4*/
	Sign_PKCS1_priv,  // algo (10) can be infered; the key type RSA priv. must match what is stored in FileID parameter
	Verify_PKCS1_pub, // algo (10) can be infered; the key type RSA publ. must match what is stored in FileID parameter
	Sign_9796_priv,   // algo (11) can be infered; the key type RSA priv. must match what is stored in FileID parameter
	Verify_9796_pub,  // algo (11) can be infered; the key type RSA publ. must match what is stored in FileID parameter
	/* CT_asym 8*/
	Decrypt_PSO_priv,
	Decrypt_PSO_SMcommand_priv,
	Decrypt_PSO_SMresponse_priv,
	Decrypt_PSO_SMcommandResponse_priv,
	Encrypt_PSO_pub,
	Encrypt_PSO_SMcommand_pub,
	Encrypt_PSO_SMresponse_pub,
	Encrypt_PSO_SMcommandResponse_pub,
//		CT_asym: UQB_Possible(0xFF, [0x40/*PSO*/, 0x50/*PSO+SM in Command Data*/, 0x60/*PSO+SM in Response Data*/, 0x70/*PSO+SM in Command and Response Data*/]),
	/* CT_sym */

	/* CCT 16*/
	Session_Key_SM,
	Session_Key,
	Local_Key1_SM,
	Local_Key1,
}
//mixin FreeEnumMembers!Usage;
+/

enum EFDB : ubyte { // enum File Descriptor Byte, as acos knows them
	// DF types:
	MF                 = 0x3F,                          // == 0b0011_1111; common DF type mask == DF : (file_type_in_question & DF) == DF for this enum
	DF                 = ISO7816_FILE_TYPE_DF, //0x38,  // == 0b0011_1000; common DF type mask == DF : (file_type_in_question & DF) == DF for this enum
// Working EF:
	Transparent_EF     = ISO7816_FILE_TYPE_TRANSPARENT_EF,      // 1, SC_FILE_EF.SC_FILE_EF_TRANSPARENT==1 as wll
	Linear_Fixed_EF    = SC_FILE_EF.SC_FILE_EF_LINEAR_FIXED,    // 2,
	Linear_Variable_EF = SC_FILE_EF.SC_FILE_EF_LINEAR_VARIABLE, // 4,
	Cyclic_EF          = SC_FILE_EF.SC_FILE_EF_CYCLIC,          // 6,  rarely used
	// All following are Internal EF:
	RSA_Key_EF         = 0x09,  // == 0b1_001; ==  8+Transparent_EF,  not record based ( Update Binary )
	// There can be a maximum of 0x1F Global PINs, 0x1F Local PINs, 0x1F Global Keys, and 0x1F Local Keys at a given time. (1Fh==31)
	CHV_EF             = 0x0A,  // == 0b1_010; ==  8+Linear_Fixed_EF,     record based ( Update Record ) DF or MF shall contain only one CHV file. Each record in the CHV file will have a fixed length of 21 bytes each
	Sym_Key_EF         = 0x0C,  // == 0b1_100; ==  8+Linear_Variable_EF,  record based ( Update Record ) DF or MF shall contain only one sym file. Each record in the symmetric key file shall have a maximum of 37 bytes
	Purse_EF           = 0x0E,  // == 0b1_110; ==  8+Cyclic_EF,
	// Proprietary EF:
	SE_EF              = 0x1C,  // ==18h+Linear_Variable_EF,  record based ( Update Record ) DF or MF shall use only one SE File. An SE file can have up to 0x0F identifiable records. (0Fh==15)
}
//mixin FreeEnumMembers!EFDB;

bool is_DFMF(ubyte/*EFDB*/ fdb) pure nothrow @nogc @safe { return (fdb & ISO7816_FILE_TYPE_DF) == ISO7816_FILE_TYPE_DF; }

ubyte iEF_FDB_to_structure(EFDB FDB) {
	auto result = cast(ubyte)(FDB & 7);
	if (result.among(1,2,4,6))
		return result;
	else
		return 0; // the result for MF/DF
}

ushort /*bitLen*/ decode_key_RSA_ModulusBitLen(const ubyte acosCode) pure nothrow @nogc @safe
{
    assert(acosCode%2==0 && acosCode>=4 && acosCode<=32);
	return  acosCode*128;
}

enum SM_Extend : ubyte {
	SM_NONE,
	SM_CCT,            // Cryptographic Checksum Template
	SM_CCT_AND_CT_sym  // Cryptographic Checksum Template and Confidentiality Template ref. key for sym. algorithm
}
//mixin FreeEnumMembers!SM_Extend;

enum card_info_type : ubyte[3] {
	Serial_Number                = [ 0, 0,  6], // 6 is for ACOSV2 etc. only; for ACOS5-64 V3 (Nano) in FIPS-mode it will be replaced by 8
	count_files_under_current_DF = [ 1, 0,  0],
	File_Information             = [ 2, 0,  8], // the P2 value must be replaced as desired
	Get_Free_Space               = [ 4, 0,  2],
	Identify_Self                = [ 5, 0,  0],
	Card_OS_Version              = [ 6, 0,  8],
	/* available ony since ACOS5-64 V3: */
	ROM_Manufacture_Date         = [ 7, 0,  4],
	ROM_SHA1                     = [ 8, 0, 20],
	Operation_Mode_Byte_Setting  = [ 9, 0,  0],
	Verify_FIPS_Compliance       = [10, 0,  0],
	Get_Pin_Authentication_State = [11, 0,  1],
	Get_Key_Authentication_State = [12, 0,  1],
}

struct fci_se_info { // former cache_current_df_se_info
	/* DF specific: */
	ub8          sac_df;  /* SAC Security Attributes Compact: output of  read_8C_SAC_Bytes_to_ub8SC, always 8 bytes sac_len */
	SM_Extend[8] smex_df;
	ubyte[32]    sae;     /* SAE Security Attributes Expanded */
	uint         sae_len; /* sae length used */
	ub2          seid;    /* Security Environment file IDentifier

	/* Any File type: */
	ub8          sac;  /* current selected file's SAC  : output of  read_8C_SAC_Bytes_to_ub8SC, always 8 bytes sac_len */
	SM_Extend[8] smex; /* current selected file's */

//	sc_path   path_fid;
//	sc_path   path_seid;    /* path of SE file */
	ub2          fid;
	ubyte        fdb;  /* File Descriptor Byte */
	ubyte        NOR;  /* if applicable: Number Of Records */
	ubyte        MRL;  /* if applicable: Max. Record Length */
}

/+
struct fsData {
    ub8   fi; //fileInfo;
    ub16  path;

    fsData dup() nothrow { return this; }
}

alias  TreeTypeFSy = tree_k_ary.Tree!fsData; // 8 bytes + length of pathlen_max considered (, here SC_MAX_PATH_SIZE = 16) + 8 bytes SAC (file access conditions)
alias  tnTypePtry  = TreeTypeFSy.nodeType*;
alias  sitTypeFSy  = TreeTypeFSy.sibling_iterator; // sibling iterator type
alias   itTypeFSy  = TreeTypeFSy.pre_order_iterator; // iterator type

//bool        doCheckPKCS15 = true;
//tnTypePtry   appdf;
//tnTypePtry   prkdf;
//tnTypePtry   pukdf;
//itTypeFSy    iter_begin;
+/

