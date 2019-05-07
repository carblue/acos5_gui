/*
 * acos5_64_shared.d: Program acos5_64_gui's shared (with D driver) file, mostly types
 *
 * Copyright (C) 2018, 2019  Carsten Blüggel <bluecars@posteo.eu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335  USA.
 */

/* Written in the D programming language */

/*
 * There is no topical reason why things are here other than this one:
 * Code/declarations required by both acos5_64 driver and tool acos5_64_gui
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

/// The maximum length of response bytes possible for 'get response' after a 'select' command
enum ubyte MAX_FCI_GET_RESPONSE_LEN = 86; //[EnumMembers!ISO7816_TAG_FCP_    ].fold!((a, b) => a + 2+TAG_FCP_len(b))(-12) +
                                          //[EnumMembers!ISO7816_RFU_TAG_FCP_].fold!((a, b) => a + 2+TAG_FCP_len(b))(0); // Σ:86 //2(6F) [+4(80)] +8(82)+4(83) [+18(84)]+3(88)+3(8A)+10(8C)  [+4(8D) +34(AB)]
//pragma(msg, "compiling...MAX_FCI_GET_RESPONSE_LEN is: ", MAX_FCI_GET_RESPONSE_LEN);

//// mandytory SE file contents in FIPS mode
immutable ubyte[/*33*/][5] seFIPS = [
    cast(immutable ubyte[/*33*/])hexString!"80 01 01 A4 06 83 01 01 95 01 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
    cast(immutable ubyte[/*33*/])hexString!"80 01 02 A4 06 83 01 01 95 01 80 B4 09 80 01 02 83 01 02 95 01 30 B8 09 80 01 02 83 01 02 95 01 30",
    cast(immutable ubyte[/*33*/])hexString!"80 01 03 A4 06 83 01 81 95 01 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
    cast(immutable ubyte[/*33*/])hexString!"80 01 04 A4 06 83 01 81 95 01 08 B4 09 80 01 02 83 01 02 95 01 30 B8 09 80 01 02 83 01 02 95 01 30",
    cast(immutable ubyte[/*33*/])hexString!"80 01 05 B4 09 80 01 02 83 01 02 95 01 30 B8 09 80 01 02 83 01 02 95 01 30 00 00 00 00 00 00 00 00",
];

//// some temporary SE file contents in non-FIPS mode(64K), global SE file
immutable ubyte[/*48*/][1] se64K0 = [
    cast(immutable ubyte[/*48*/])hexString!"80 01 01 A4 06 83 01 01 95 01 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
];

//// some temporary SE file contents in non-FIPS mode(64K), local SE file
immutable ubyte[/*48*/][4] se64K1 = [
    cast(immutable ubyte[/*48*/])hexString!"80 01 01 A4 06 83 01 81 95 01 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
    cast(immutable ubyte[/*48*/])hexString!"80 01 02 B4 09 83 01 01 95 01 30 80 01 02 B8 09 83 01 01 95 01 30 80 01 02 A4 06 83 01 81 95 01 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
    cast(immutable ubyte[/*48*/])hexString!"80 01 03 A4 06 83 01 01 95 01 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
    cast(immutable ubyte[/*48*/])hexString!"80 01 04 A4 09 83 01 01 83 01 81 95 01 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
];

nothrow extern(C)
{

alias  ft_acos5_64_short_select =  int function(sc_card* card,
    ub2 fid,
    FCISEInfo* info = null,
    ubyte[] outbuf = null);

// a wrapper for sc_update_binary
alias  ft_uploadHexfile =  int function(sc_card* card,
    const(char)* filePathName,
    uint idx,
    size_t count,
    c_ulong flags);

alias  ft_cm_7_3_1_14_get_card_info =  int function(sc_card* card,
    const CardInfoType  type,
    const ubyte         fileAtPos_PinRef_KeyRef,
    out ushort          SW1SW2,
    out ubyte           responseLen,
    out ubyte[]         response, //=null,
    c_ulong             apdu_flags=0 //, scope ubyte[]         command_bytes=null
    ) /*@nogc nothrow pure*/ @safe;

alias  ft_cry_pso_7_4_3_8_2A_asym_encrypt_RSA =  int function(sc_card* card,
    const scope ubyte[] indata,
    scope ubyte[] encrypted_RSA) @trusted;

alias  ft_cry_____7_4_4___46_generate_keypair_RSA =
    int function(sc_card* card, const scope ubyte[] lv_key_len_type_data) /*@safe*/;

alias  ft_ctrl_generate_keypair_RSA =  int function(bool, bool=false, bool=true);

//alias  ft_aa_7_2_6_82_external_authentication = int function(sc_card* card, ubyte KeyID, scope sc_remote_data* rdata=null, const scope ubyte[] keyValueTDES=null) @trusted;

alias  ft_cry_mse_7_4_2_1_22_set =  int function(sc_card* card, const scope ubyte[] tlv_crt) @trusted;

alias  ft_cry_pso_7_4_3_6_2A_sym_encrypt =  int function(sc_card* card,
    const scope ubyte[] inData,
    scope ubyte[] outData,
    uint blockSize=8,
    bool doCBCmode=true /* otherwise handled as ECB */
    );

alias  ft_cry_pso_7_4_3_7_2A_sym_decrypt =  int function(sc_card* card,
    const scope ubyte[] inData,
    scope ubyte[] outData,
    uint blockSize=8,
    bool doCBCmode=true, /* otherwise handled as ECB */
    const scope ubyte[] tlv = null, // the same that was used for encryption; assuming that allows decryption as well
    ub2 fid = [ubyte(0),ubyte(0)] // any DF for that verification was done already
    );

} // nothrow extern(C)

/** enum for File Descriptor Byte (FDB); it's members are all the different file types, the card os knows about */
enum EFDB : ubyte  // enum File Descriptor Byte, as acos knows them
{
    // DF types:
    MF                 = 0x3F,                          // == 0b0011_1111;
    DF                 = ISO7816_FILE_TYPE_DF, //0x38,  // == 0b0011_1000;
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

/** returns true, if given a fdb parameter that represents type MF or DF, which are directories,
    returns false for any other fdb, which are 'real' files */
bool is_DFMF(ubyte/*EFDB*/ fdb) pure nothrow @nogc @safe {return (fdb & ISO7816_FILE_TYPE_DF) == ISO7816_FILE_TYPE_DF;}

/**
   all 'real' files (opposed to directories) have a distinguishing feature called structure (e.g. transparent, linear-fixed etc.)
     The first 4 enum members of EFDB (that represent files) are named according to the 4 structures available,
     the remaining (beginning with RSA_Key_EF, which are all internal EF) are named differently, but have a specific structure as well.
     The function returns for file types an ubyte, which equals the corresponding EFDB-structure-enum, or it returns 0 for MF/DF
*/
ubyte iEF_FDB_to_structure(EFDB FDB) nothrow
{
    auto result = cast(ubyte)(FDB & 7);
    if (result.among(1,2,4,6))
        return result;
    else
        return 0; // the result for MF/DF
}

/** The acos-internal code for RSA modulus length is bitLen/128; this function does the inverse/decode operation */
ushort /*bitLen*/ decode_key_RSA_ModulusBitLen(const ubyte acosCode) pure nothrow @nogc @safe
{
    assert(acosCode%2==0 && acosCode>=4 && acosCode<=32, "acosCode is not a valid encoding for ACOS5 RSA key's modulus bit length");
      return  acosCode*128;
}

/**
  Each byte in SAC (and/or SAE) (called Security Condition Byte SCB) relates to an operation, depending on file descriptor byte,
    or for SAE, defined within SAE bytes
    One of SCB's bits expresses whether that operation is forced to be executed under Secure Messaging (SM) conditions (yes/no).
    The mode of SM is selected by other bits of SCB (indirectly, via SE file). The end result of collecting all those SM-related
    infos is expressed by the 3 enum members.
    SCB and it's corresponding SM_Extend info are coupled by same position in storage variables: ubyte[8] sac <=> SM_Extend[8] smex
*/
enum SM_Extend : ubyte
{
    SM_NONE,           /// SM is not enforced/impossible
    SM_CCT,            /// SM is enforced, providing Authenticity, specified by a  Cryptographic Checksum Template
    SM_CCT_AND_CT_sym  /// SM is enforced, providing Authenticity and Confidentiality, specified by a  Cryptographic Checksum Template and Confidentiality Template (ref. key for sym. algorithm)
}
//mixin FreeEnumMembers!SM_Extend;

/** These bytes are used with the acos command Get Card Info; they select one of it's subcommands */
enum CardInfoType : ubyte[3]
{
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

/** FCI/file header data gets returned by select command. Some infos are collected in this structure */
struct FCISEInfo  // former cache_current_df_se_info
{
    /* DF specific: */
    ub8          sac_df;  /// SAC Security Attributes Compact: output of  read_8C_SAC_Bytes_to_ub8SC, always 8 bytes sac_len; should remember values of last encountered DF, but seems to be overwritten: check this
    SM_Extend[8] smex_df; /// if the bytes in sac_df have relevance for Secure Messaging, and if so, which SM_Extend        ; should remember values of last encountered DF, but seems to be overwritten: check this
    ubyte[32]    sae;     /// SAE Security Attributes Expanded
    uint         sae_len; /// sae length used
    ub2          seid;    /// Security Environment file IDentifier

    /* The following for all 'File/DF' types: */
    ub8          sac;  /// current selected file's SAC  : output of  read_8C_SAC_Bytes_to_ub8SC, always 8 bytes sac_len
    SM_Extend[8] smex; /// current selected file's SAC relevance for Secure Messaging, see smex_df */

//    sc_path   path_fid;
//    sc_path   path_seid;    /* path of SE file */
    ub2          fid;  /// File Id
    ubyte        fdb;  /// File Descriptor Byte
    ubyte        NOR;  /// if applicable: Number Of Records
    ubyte        MRL;  /// if applicable: Max. Record Length
}

