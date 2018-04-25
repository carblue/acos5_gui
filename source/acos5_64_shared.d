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
import std.algorithm.comparison : among;

import libopensc.opensc;
import libopensc.types;
import libopensc.errors;
import libopensc.log;
import libopensc.iso7816;

alias  ub2  = ubyte[2];
alias  ub8  = ubyte[8];
alias  ub16 = ubyte[16];
alias  ub24 = ubyte[24];
alias  uba  = ubyte[];


enum ubyte MAX_FCI_GET_RESPONSE_LEN = 86;

nothrow extern(C) {

alias  ft_cm_7_3_1_14_get_card_info = int function(sc_card* card,
    const card_info_type  type,
    const ubyte           fileAtPos_PinRef_KeyRef,
    out ushort            SW1SW2,
    out ubyte             responseLen,
    scope ubyte[]         response=null,
    c_ulong               apdu_flags=0,
    scope ubyte[]         command_bytes=null);

alias  ft_acos5_64_short_select = int function(sc_card* card,
    fci_se_info* info,
    ub2 fid,
    bool skip_seid_retrieval,
    ubyte[] outbuf = null);

alias  ft_uploadHexfile =  int function(sc_card* card,
    const(char)* filePathName,
    uint idx,
    size_t count,
    c_ulong flags);
} // nothrow extern(C)


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

enum SM_Extend : ubyte {
    SM_NONE,
    SM_CCT,            // Cryptographic Checksum Template
    SM_CCT_AND_CT_sym  // Cryptographic Checksum Template and Confidentiality Template ref. key for sym. algorithm
}
//mixin FreeEnumMembers!SM_Extend;

enum card_info_type : ubyte[3] {
    Serial_Number                = [ 0,0, 6], // 6 is for ACOSV2 only; for ACOSV3 (Nano) it will be replaced by 8
    count_files_under_current_DF = [ 1,0, 0],
    File_Information             = [ 2,0, 8], // the P2 value must be replaced as desired
    Get_Free_Space               = [ 4,0, 2],
    Identify_Self                = [ 5,0, 0],
    Card_OS_Version              = [ 6,0, 8],
/+ available ony since ACOSV3: +/
    ROM_Manufacture_Date         = [ 7,0, 4],
    ROM_SHA1                     = [ 8,0,20],
    Operation_Mode_Byte_Setting  = [ 9,0, 0],
    Verify_FIPS_Compliance       = [10,0, 0],
    Get_Pin_Authentication_State = [11,0, 1],
    Get_Key_Authentication_State = [12,0, 1],
/+ +/
}

struct fci_se_info {
    /* DF specific: */
    ub8          sac_df;  /* SAC : output of  read_8C_SAC_Bytes_to_ub8SC, always 8 bytes sac_len */
    SM_Extend[8] smex_df;
    ubyte[32]    sae;     /* SAE Security Attributes Expanded */
    uint         sae_len; /* sae length used */
    ub2          seid;

    /* Any File type: */
    ub8          sac;  /* current selected file's SAC  : output of  read_8C_SAC_Bytes_to_ub8SC, always 8 bytes sac_len */
    SM_Extend[8] smex; /* current selected file's */

    ub2          fid;  /* File Descriptor ID */
    ubyte        fdb;  /* File Descriptor Byte */
    ubyte        NOR;  /* if applicable: Number Of Records */
    ubyte        MRL;  /* if applicable: Max. Record Length */
}

uint/*bitLen*/ decode_key_RSA_ModulusBitLen(const ubyte code) pure nothrow @nogc @safe
{
    assert(code%2==0 && code>=4 && code<=32);
    return  code*128;
}
