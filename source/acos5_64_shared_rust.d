/*
 * acos5_64_shared_rust.d: Program acos5_64_gui's shared (with Rust driver) file, mostly types
 *
 * Copyright (C) 2019  Carsten Blüggel <bluecars@posteo.eu>
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

module acos5_64_shared_rust;

/*
 * Proprietary card_ctl calls
 */
//alias card_ctl_tf = int function(sc_card* card, c_ulong request, void* data);

enum uint SC_CARDCTL_ACOS5_GET_COUNT_FILES_CURR_DF   =  0x0000_0011; // data: size_t* (*mut usize),  get_count_files_curr_DF
enum uint SC_CARDCTL_ACOS5_GET_FILE_INFO             =  0x0000_0012; // data: CardCtlArray8*,  get_file_info
enum uint SC_CARDCTL_ACOS5_GET_FREE_SPACE            =  0x0000_0014; // data: uint* (*mut c_uint),  get_free_space
enum uint SC_CARDCTL_ACOS5_GET_IDENT_SELF            =  0x0000_0015; // data: uint* (*mut c_uint),  get_ident_self
enum uint SC_CARDCTL_ACOS5_GET_COS_VERSION           =  0x0000_0016; // data: CardCtlArray8*,  get_cos_version
/* available only since ACOS5-64 V3: */
enum uint SC_CARDCTL_ACOS5_GET_ROM_MANUFACTURE_DATE  =  0x0000_0017; // data: uint* (*mut c_uint),  get_manufacture_date
enum uint SC_CARDCTL_ACOS5_GET_ROM_SHA1              =  0x0000_0018; // data: CardCtlArray20*,  get_rom_sha1
enum uint SC_CARDCTL_ACOS5_GET_OP_MODE_BYTE          =  0x0000_0019; // data: uint* (*mut c_uint),  get_op_mode_byte
enum uint SC_CARDCTL_ACOS5_GET_FIPS_COMPLIANCE       =  0x0000_001A; // data: uint* (*mut c_uint),  get_fips_compliance
enum uint SC_CARDCTL_ACOS5_GET_PIN_AUTH_STATE        =  0x0000_001B; // data: CardCtlAuthState*,  get_pin_auth_state
enum uint SC_CARDCTL_ACOS5_GET_KEY_AUTH_STATE        =  0x0000_001C; // data: CardCtlAuthState*,  get_key_auth_state

enum uint SC_CARDCTL_ACOS5_UPDATE_FILES_HASHMAP      =  0x0000_0020; // data: null
enum uint SC_CARDCTL_ACOS5_GET_FILES_HASHMAP_INFO    =  0x0000_0021; // data: *mut CardCtlArray32,  get_files_hashmap_info

enum uint SC_CARDCTL_ACOS5_GENERATE_KEY_FILES_EXIST  =  0x0000_0022; // data: *mut CardCtl_generate_asym, do_generate_asym;  RSA files exist, sec_env setting excluded
enum uint SC_CARDCTL_ACOS5_GENERATE_KEY_FILES_CREATE =  0x0000_0023; // data: *mut CardCtl_generate_asym, do_generate_asym;  RSA files must be created, sec_env setting excluded
enum uint SC_CARDCTL_ACOS5_GENERATE_KEY_FILES_EXIST_MSE  =  0x0000_0024; // data: *mut CardCtl_generate_asym, do_generate_asym;  RSA files exist, sec_env setting included
enum uint SC_CARDCTL_ACOS5_GENERATE_KEY_FILES_CREATE_MSE =  0x0000_0025; // data: *mut CardCtl_generate_asym, do_generate_asym;  RSA files must be created, sec_env setting included

enum uint SC_CARDCTL_ACOS5_ENCRYPT_SYM               =  0x0000_0026; // data: *mut CardCtl_crypt_sym,  do_encrypt_sym
enum uint SC_CARDCTL_ACOS5_ENCRYPT_ASYM              =  0x0000_0027; // data: *mut CardCtl_crypt_asym, do_encrypt_asym; Signature verification with public key

//enum uint SC_CARDCTL_ACOS5_DECRYPT_SYM             =  0x0000_0028; // data: *mut CardCtl_crypt_sym,  do_decrypt_sym
////enum uint SC_CARDCTL_ACOS5_DECRYPT_ASYM          =  0x0000_0029; // data: *mut CardCtl_crypt_asym, do_decrypt_asym; is available via decipher

/* common types and general function(s) */

// struct for SC_CARDCTL_GET_FILE_INFO and SC_CARDCTL_GET_COS_VERSION
struct CardCtlArray8 {
    ubyte      reference;  // IN  indexing begins with 0, used for SC_CARDCTL_GET_FILE_INFO
    ubyte[8]   value;      // OUT
}

// struct for SC_CARDCTL_GET_ROM_SHA1
struct CardCtlArray20 {
    ubyte[20]  value;      // OUT
}

// struct for SC_CARDCTL_GET_PIN_AUTH_STATE and SC_CARDCTL_GET_KEY_AUTH_STATE
struct CardCtlAuthState {
    ubyte      reference;  // IN  pin/key reference, | 0x80 for local
    bool       value;      // OUT  bool	8 bit byte with the values 0 for false and 1 for true
}

// struct for SC_CARDCTL_GET_FILES_HASHMAP_INFO
struct CardCtlArray32 {
    ushort     key;        // IN   file_id
    ubyte[32]  value;      // OUT  in the order as acos5_64_gui defines // alias  TreeTypeFS = Tree_k_ary!ub32;
}

struct CardCtl_generate_crypt_asym {
    ubyte[512] data;
    size_t     data_len;
    ushort     file_id_priv;   // IN  if any of file_id_priv/file_id_pub is 0, then file_id selection will depend on profile,
    ushort     file_id_pub;    // IN  if both are !=0, then the given values are preferred
    ubyte[16]  exponent;       // public exponent
    bool       exponent_std;   // whether the default exponent 0x10001 shall be used and the exponent field disregarded; otherwise all 16 bytes from exponent will be used
    ubyte      key_len_code;   //
    ubyte      key_priv_type_code; // as required by cos5 Generate RSA Key Pair
    bool       perform_mse;    // IN parameter, whether MSE Manage Security Env. shall be done prior to generation
    bool       op_success;     // OUT parameter, whether generation succeeded
}
