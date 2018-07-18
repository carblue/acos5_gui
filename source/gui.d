/*
 * Written in the D programming language, part of package acos5_64_gui.
 * gui.d: Graphical User Interface file, based on IUP
 *
 * Copyright (C) 2018- : Carsten Blüggel <bluecars@posteo.eu>
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

module gui;

import std.stdio : write, writeln, writefln, stdout;
import std.algorithm.comparison : among;

import iup.iup_plusD;

import libintl : _, __;
import callbacks;
import importExport;

import key_asym :
r_AC_Delete_Create_RSADir,
r_acos_internal,
r_keyAsym_RSAmodulusLenBits,
r_keyAsym_crtModeGenerate,
r_keyAsym_usageGenerate,
r_keyAsym_Label,
r_keyAsym_Id,
r_keyAsym_fidAppDir,
r_fidRSAprivate,
r_fidRSApublic,

r_sizeNewRSAprivateFile,
r_sizeNewRSApublicFile,
r_change_calcPrKDF,
r_change_calcPuKDF,
r_keyAsym_authId,
r_valuePublicExponent,
r_statusInput,
r_keyAsym_usagePrKDF,
r_keyAsym_Modifiable,
r_AC_Update_PrKDF_PuKDF,
r_AC_Update_Delete_RSApublicFile,
r_AC_Update_Delete_RSAprivateFile,

matrixKeyAsym_dropcheck_cb,
matrixKeyAsym_drop_cb,
matrixKeyAsym_dropselect_cb,
matrixKeyAsym_edition_cb,
matrixKeyAsym_togglevalue_cb,
btn_RSA_cb,

toggle_RSA_cb
;

import key_sym; // matrixKeySym_dropcheck_cb


private Hbox create_cryptoki_slot_tokeninfo_tab() {
    Control[]  child_array1, child_array2;
    Matrix     matrix;
    Text       text;
//    Vbox       vbox1, vbox2;
//    List       list;

    matrix = new Matrix("slot_token");
    with (matrix) {
        SetInteger(IUP_NUMLIN,         43);
        SetInteger(IUP_NUMLIN_VISIBLE, 43);
        SetInteger(IUP_NUMCOL,          1);
        SetInteger(IUP_NUMCOL_VISIBLE,  1);
        SetAttribute(IUP_RESIZEMATRIX, IUP_YES);
//      SetAttribute("LIMITEXPAND",  IUP_YES);
        SetAttribute(IUP_READONLY,     IUP_YES);
//      SetAttribute("FLATSCROLLBAR",     IUP_YES);
//      SetAttribute("EDITNEXT",     "COL");
        SetIntegerId(IUP_WIDTH,   0,    240);
        SetIntegerId(IUP_WIDTH,   1,    130);
        SetInteger(IUP_HEIGHTDEF,  5);

        SetAttributeId2("", 0,  1,   __("value")); // SetAttributeId2("", 1,  1, "");

        SetAttributeId2("",  1,  0,   "Cryptoki version"); //  SetAttributeId2("",  7,  1, "CKF_REMOVABLE_DEVICE");
        SetAttributeId2("",  2,  0,   __("Cryptoki manufacturerID")); //         SetAttributeId2("",  3,  1, "-");
        SetAttributeId2("",  3,  0,   "Cryptoki flags bitfield"); //  SetAttributeId2("",  7,  1, "CKF_REMOVABLE_DEVICE");
        SetAttributeId2("",  4,  0,   "Cryptoki libraryDescription"); //         SetAttributeId2("",  3,  1, "-");
        SetAttributeId2("",  5,  0,   "Cryptoki libraryVersion"); //  SetAttributeId2("",  7,  1, "CKF_REMOVABLE_DEVICE");

        SetAttributeId2("",  6,  0,   "Slot id"); //                  SetAttributeId2("",  1,  1, "-");
        SetAttributeId2("",  7,  0,   __("Slot description")); //        SetAttributeId2("",  2,  1, "-");
        SetAttributeId2("",  8,  0,   __("Slot manufacturerID")); //         SetAttributeId2("",  3,  1, "-");
        SetAttributeId2("",  9,  0,   "Slot flag CKF_TOKEN_PRESENT"); //           SetAttributeId2("",  4,  1, "CKF_REMOVABLE_DEVICE");
        SetAttributeId2("", 10,  0,   "Slot flag CKF_REMOVABLE_DEVICE"); //           SetAttributeId2("",  5,  1, "CKF_REMOVABLE_DEVICE");
        SetAttributeId2("", 11,  0,   "Slot flag CKF_HW_SLOT"); //           SetAttributeId2("",  6,  1, "CKF_REMOVABLE_DEVICE");
        SetAttributeId2("", 12,  0,   "Slot hardware/firmware version"); //  SetAttributeId2("",  7,  1, "CKF_REMOVABLE_DEVICE");

        SetAttributeId2("", 13,  0,   __("Token label")); //              SetAttributeId2("",  8,  1, "-");
        SetAttributeId2("", 14,  0,   __("Token manufacturer")); //       SetAttributeId2("",  9,  1, "-");
        SetAttributeId2("", 15,  0,   "Token model"); //              SetAttributeId2("", 10,  1, "-");
        SetAttributeId2("", 16,  0,   "Token serialnr"); //           SetAttributeId2("", 11,  1, "-");

        SetAttributeId2("", 17,  0,   "Token flags bitfield (summary, below the details)"); //        SetAttributeId2("", 12,  1, "-");
        SetAttributeId2("", 18,  0,   "Token flag CKF_RNG"); //      SetAttributeId2("", 13,  1, "-");
        SetAttributeId2("", 19,  0,   "Token flag CKF_WRITE_PROTECTED"); //        SetAttributeId2("", 14,  1, "-");
        SetAttributeId2("", 20,  0,   "Token flag CKF_LOGIN_REQUIRED"); //         SetAttributeId2("", 15,  1, "-");
        SetAttributeId2("", 21,  0,   "Token flag CKF_USER_PIN_INITIALIZED"); //           SetAttributeId2("", 16,  1, "-");

        SetAttributeId2("", 22,  0,   "Token flag CKF_PROTECTED_AUTHENTICATION_PATH"); //             SetAttributeId2("", 17,  1, "-");
        SetAttributeId2("", 23,  0,   "Token flag CKF_DUAL_CRYPTO_OPERATIONS"); //    SetAttributeId2("", 18,  1, "-");
        SetAttributeId2("", 24,  0,   "Token flag CKF_TOKEN_INITIALIZED"); //    SetAttributeId2("", 19,  1, "-");
        SetAttributeId2("", 25,  0,   "Token flag CKF_SECONDARY_AUTHENTICATION"); //      SetAttributeId2("", 20,  1, "-");

        SetAttributeId2("", 26,  0,   "Token flag CKF_USER_PIN_COUNT_LOW"); // SetAttributeId2("", 21,  1, "-");
        SetAttributeId2("", 27,  0,   "Token flag CKF_USER_PIN_FINAL_TRY"); //      SetAttributeId2("", 22,  1, "-");
        SetAttributeId2("", 28,  0,   "Token flag CKF_USER_PIN_LOCKED"); //      SetAttributeId2("", 23,  1, "-");
        SetAttributeId2("", 29,  0,   "Token flag CKF_USER_PIN_TO_BE_CHANGED"); //        SetAttributeId2("", 24,  1, "-");

        SetAttributeId2("", 30,  0,   "Token flag CKF_SO_PIN_COUNT_LOW"); //   SetAttributeId2("", 25,  1, "-");
        SetAttributeId2("", 31,  0,   "Token flag CKF_SO_PIN_FINAL_TRY"); //   SetAttributeId2("", 25,  1, "-");
        SetAttributeId2("", 32,  0,   "Token flag CKF_SO_PIN_LOCKED"); //   SetAttributeId2("", 25,  1, "-");
        SetAttributeId2("", 33,  0,   "Token flag CKF_SO_PIN_TO_BE_CHANGED"); //   SetAttributeId2("", 25,  1, "-");

        SetAttributeId2("", 34,  0,   "Token flag CKF_ERROR_STATE"); //   SetAttributeId2("", 25,  1, "-");

        SetAttributeId2("", 35,  0,   "Token SessionCount cur/max"); //   SetAttributeId2("", 25,  1, "-");
        SetAttributeId2("", 36,  0,   "Token RwSessionCount cur/max"); //   SetAttributeId2("", 25,  1, "-");
        SetAttributeId2("", 37,  0,   "Token PinLen min/max"); //   SetAttributeId2("", 25,  1, "-");
        SetAttributeId2("", 38,  0,   "Token PublicMemory free/total"); //   SetAttributeId2("", 25,  1, "-");
        SetAttributeId2("", 39,  0,   "Token PrivateMemory free/total"); //   SetAttributeId2("", 25,  1, "-");
        SetAttributeId2("", 40,  0,   "Token hardware/firmware version"); //  SetAttributeId2("",  7,  1, "CKF_REMOVABLE_DEVICE");
        SetAttributeId2("", 41,  0,   "Token utcTime");
        SetAttributeId2("", 42,  0,   "Token has provision for FIPS 140-2 Level 3–Compliant Mode");
        SetAttributeId2("", 42,  1,   "No");
        SetAttributeId2("", 43,  0,   "Token is verified to operate in FIPS 140-2 Level 3–Compliant Mode");
        SetAttributeId2("", 43,  1,   "N/A");

        SetAttribute(IUP_TOGGLECENTERED,  IUP_YES);
        SetCallback(IUP_DROPCHECK_CB,  cast(Icallback) &slot_token_dropcheck_cb);
    }
    child_array1 ~= matrix;
    auto vbox1 = new Vbox(child_array1, FILL_TYPE.FILL_FRONT_AND_BACK);
    child_array2 ~= vbox1;

    text = new Text("cst_text");
    with (text) {
        SetInteger  (IUP_SIZE, 500);
        SetAttribute(IUP_MULTILINE, IUP_YES);
        SetInteger  (IUP_VISIBLELINES, 40);
        SetAttribute(IUP_WORDWRAP, IUP_YES);
    }
    child_array2 ~= text;

    auto hbox = new Hbox(child_array2, FILL_TYPE.FILL_FRONT_AND_BACK_AND_BETWEEN);
    hbox.SetAttribute(ICTL_TABTITLE, "Cryptoki/Slot/Token-Info");
    return hbox;
}

private Vbox create_opensc_conf_tab() {
    Control[] child_array;

    child_array ~= new Label(  "This page allows editing opensc.conf (and later acos5_64.profile). Root privileges will be required for storing"); // will be collected
    child_array ~= new Label(  "There are 2 modes how to handle Root privileges: Either enter admin password in this app, or in a shell for a command sudo patch -b /etc/opensc/opensc.conf conf.diff"); // will be collected

    auto vbox = new Vbox(new Vbox(child_array, FILL_TYPE.FILL_BETWEEN), new Fill);
    vbox.SetAttribute(ICTL_TABTITLE, "opensc.conf");
    return vbox;
}

private Hbox create_filesystem_tab() {
    Control[] child_array1, child_array2, child_array3;
    auto tree_fs = new Tree("tree_fs");
    with (tree_fs) {
        SetAttribute(IUP_SHOWTOGGLE, IUP_YES);

        SetCallback(IUP_SELECTION_CB, cast(Icallback) &selectbranchleaf_cb);
        SetCallback(IUP_EXECUTELEAF_CB, cast(Icallback) &executeleaf_cb);
//      SetCallback("RENAME_CB", cast(Icallback) &rename_cb);
        SetCallback(IUP_BRANCHCLOSE_CB, cast(Icallback) &branchclose_cb);
        SetCallback(IUP_BRANCHOPEN_CB, cast(Icallback) &branchopen_cb);
//      SetCallback("DRAGDROP_CB", cast(Icallback) &dragdrop_cb);
//      SetCallback(IUP_RIGHTCLICK_CB, cast(Icallback) &rightclick_cb);
////    SetCallback(IUP_K_ANY, cast(Icallback) &k_any_cb);

//      SetAttribute("FONT","COURIER_NORMAL");
//      SetAttribute("CTRL",IUP_YES);
//      SetAttribute("SHIFT",IUP_YES);
//      SetAttribute("ADDEXPANDED", "NO");
//      SetAttribute("SHOWDRAGDROP", IUP_YES);
////    SetAttribute("SHOWRENAME", IUP_YES);

    }

    child_array1 ~= tree_fs;

    auto toggle1 = new Toggle("toggle_op_file_possible_suppress", __("Suppress rare operations like delete, de-/activate"));
    toggle1.SetAttributeVALUE(IUP_ON);
    toggle1.SetCallback(IUP_ACTION, cast(Icallback) &toggle_op_file_possible_suppress_cb);
    child_array2 ~= toggle1;
    auto toggle2 = new Toggle("toggle_auto_read", __("Perform 'Read operation' automatically, if applicable and doesn't require authorization (except SM related)"));
    toggle2.SetAttributeVALUE(IUP_ON);
    toggle2.SetCallback(IUP_ACTION, cast(Icallback) &toggle_auto_read_cb);
    child_array2 ~= toggle2;

    auto list = new List("list_op_file_possible");
    with (list) {
        SetInteger  (IUP_SIZE, 100);
        SetAttribute(IUP_DROPDOWN, IUP_YES);
        SetInteger  (IUP_VISIBLEITEMS, 7);
//  final void   SetAttributeId(const(char)* name, int id, const(char)* value) @nogc {         IupSetAttributeId(_ih, name, id, value); }
//        SetAttributeId("", 1, "Read");
        SetAttribute("1", "Read");
        SetAttribute("2", "Update");
        SetAttribute("3", "---");
        SetAttribute("4", "Deactivate/Invalidate");
        SetAttribute("5", "Activate/Rehabilitate");
        SetAttribute("6", "Terminate/Lock");
        SetAttribute("7", "Delete Self");
        SetAttribute("8", null);
//      SetAttribute(IUP_VALUE, "1");
        SetCallback(IUP_VALUECHANGED_CB, &list_op_file_possible_val_changed_cb);
    }
    child_array3 ~= list;
/+
    auto btn_do = new Button("btn_do",  __("Update local CHV-File"));
    btn_do.SetCallback(IUP_ACTION, &btn_do_cb);
//    btn_do.SetAttribute(IUP_TIP, __("The action performed depends on the radio button setting"));
    child_array3 ~= btn_do;
+/
    auto hbox1 = new Hbox(child_array3, FILL_TYPE.FILL_FRONT_AND_BACK_AND_BETWEEN);
    child_array2 ~= hbox1;

    child_array2 ~= new Label("Read-Result (hexadecimal; content ending with 4 zero bytes indicates: There were possibly more zero bytes, subject to 'zero byte truncation')");

    auto text1 = new Text("fs_text");
    with (text1) {
        SetAttribute(IUP_SIZE, "650");
        SetAttribute(IUP_MULTILINE, IUP_YES);
        SetAttribute(IUP_VISIBLELINES, "10");
        SetAttribute(IUP_WORDWRAP, IUP_YES);
    }
    child_array2 ~= text1;

    auto toggle3 = new Toggle("toggle_auto_decode_asn1", __("Perform 'Read operation result ASN.1-decoding' automatically for transparent files (for RSA: openssh format)"));
    toggle3.SetAttributeVALUE(IUP_ON);
    toggle3.SetCallback(IUP_ACTION, cast(Icallback) &toggle_auto_decode_asn1_cb);
    child_array2 ~= toggle3;

    auto text2 = new Text("fs_text_asn1");
    with (text2) {
        SetAttribute(IUP_SIZE, "650");
        SetAttribute(IUP_MULTILINE, IUP_YES);
        SetAttribute(IUP_VISIBLELINES, "30");
        SetAttribute(IUP_WORDWRAP, IUP_YES);

        SetAttribute(IUP_READONLY, IUP_YES);
    }
    child_array2 ~= text2;

    child_array1 ~= new Vbox(child_array2, FILL_TYPE.FILL_BETWEEN);

    auto hbox = new Hbox(child_array1, FILL_TYPE.FILL_FRONT_AND_BACK_AND_BETWEEN);
    hbox.SetAttribute(ICTL_TABTITLE, "file system (read only)");
    return hbox;
}

private Vbox create_ssh_tab() {
/*
remember to inform:
/etc/ssh/ssh_config or user's config file requires an entry like
PKCS11Provider /usr/lib/opensc-pkcs11.so   or
PKCS11Provider /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
so that ssh client is informed to look for keys via PKCS#11 in a card/token and which library to use for that (where to find it)

https://help.github.com/articles/testing-your-ssh-connection/
ssh -T git@github.com

If PKCS11Provider is not specified, the command will be
ssh -I /path/to/opensc-pkcs11.so -T git@github.com
*/
    auto vbox = new Vbox();
    vbox.SetAttribute(ICTL_TABTITLE, "ssh");
    return vbox;
}

private Vbox create_KeyASym_tab() {
    Control[]  child_array, child_array_toggles;

    auto text1 = new Text("gkpRSA_text");
    with (text1) {
        SetAttribute(IUP_SIZE, "800");
        SetAttribute(IUP_MULTILINE, IUP_YES);
        SetAttribute(IUP_VISIBLELINES, "8");
        SetAttribute(IUP_WORDWRAP, IUP_YES);
    }
    child_array ~= text1;

/*
https://webserver2.tecgraf.puc-rio.br/iup/en/elem/iupradio.html
A toggle that is a child of an IupRadio automatically receives a name when its is mapped into the native system.  (since 3.16)
Currently IupFlatButton with TOGGLE=YES, IupToggle, and IupGLToggle are affected when inside a IupRadio.
The IGNORERADIO can be used in any of these children types to disable this functionally. (since 3.21)
*/
    auto toggle1 = new Toggle("toggle_RSA_PrKDF_PuKDF_change", __("PrKDF/PuKDF only: Change some administrative (PKCS#15) data, but no change concerning RSA key pair content (select by key pair id)"));
    child_array_toggles ~= toggle1;
    auto toggle2 = new Toggle("toggle_RSA_key_pair_delete", __("RSA key pair: Delete key pair files (select by key pair id)"));
    child_array_toggles ~= toggle2;
    auto toggle3 = new Toggle("toggle_RSA_key_pair_regenerate", __("RSA key pair: Regenerate RSA key pair content in existing files (select by key pair id)"));
    child_array_toggles ~= toggle3;
    auto toggle4 = new Toggle("toggle_RSA_key_pair_create_and_generate", __("RSA key pair: Create new RSA key pair files and generate RSA key pair content"));
    child_array_toggles ~= toggle4;
    auto toggle5 = new Toggle("toggle_RSA_key_pair_try_sign", __("RSA key pair: Sign SHA1/SHA256 hash (select key pair id)  Use to test the signing capability for selected id, output to stdout"));
    child_array_toggles ~= toggle5;

    foreach (i,toggle; child_array_toggles) {
        toggle.SetAttributeVALUE(i==0? IUP_ON : IUP_OFF);
        toggle.SetCallback(IUP_ACTION, cast(Icallback) &toggle_RSA_cb);
    }
    child_array  ~= new Radio("radioKeyAsym", new Vbox(child_array_toggles, FILL_TYPE.FILL_FRONT_AND_BACK_AND_BETWEEN));
/*
https://webserver2.tecgraf.puc-rio.br/iup/en/elem/iupradio.html
Attributes:
EXPAND (non inheritable): The default value is "YES".
VALUE (non inheritable): name identifier of the active toggle. The name is set by means of IupSetHandle. In Lua you can also use the element reference directly. When consulted if the toggles are not mapped into the native system the return value may be NULL or invalid.
VALUE_HANDLE (non inheritable): Changes the active toggle. The value passed must be the handle of a child contained in the radio. When consulted if the toggles are not mapped into the native system the return value may be NULL or invalid. (since 3.0)
*/
    auto text2 = new Text("hash_to_be_signed");
    with (text2) {
        SetAttribute(IUP_SIZE, "500");
        SetAttribute(IUP_READONLY, IUP_YES);
        SetStringVALUE("0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20  Content to be signed: 20/32 bytes");
    }
    child_array ~= text2;

    auto text3 = new Text();
    with (text3) {
        SetAttribute(IUP_SIZE, "500");
        SetAttribute(IUP_READONLY, IUP_YES);
        SetStringVALUE("Integer entry for private key usage/capability: 2(decrypt) +4(sign) +8(signRecover) +32(unwrap) +512(nonRepudiation)");
    }
    child_array ~= text3;

/*  Matrix("matrixKeyAsym") is designed to work in "normal" mode !
IupMatrix
It has two modes of operation: normal and callback mode.
In normal mode, string values are stored in attributes for each cell.
In callback mode these attributes are ignored and the cells are filled with strings returned by the "VALUE_CB" callback.
So the existence of this callback defines the matrix operation mode.
*/
    auto matrix = new Matrix("matrixKeyAsym");
    with (matrix) {
        SetInteger(IUP_NUMLIN,         r_AC_Delete_Create_RSADir);
        SetInteger(IUP_NUMLIN_VISIBLE, r_AC_Delete_Create_RSADir);
        SetInteger(IUP_NUMCOL,          2);
        SetInteger(IUP_NUMCOL_VISIBLE,  2);
        SetAttribute(IUP_RESIZEMATRIX, IUP_YES);
//      SetAttribute("LIMITEXPAND",  IUP_YES);
        SetAttribute(IUP_READONLY,     IUP_NO);
//      SetAttribute("FLATSCROLLBAR",     IUP_YES);
//      SetAttribute("EDITNEXT",     "COL");
        SetIntegerId(IUP_WIDTH,   0,    400);
        SetIntegerId(IUP_WIDTH,   1,    130);
        SetIntegerId(IUP_WIDTH,   2,    230);
        SetInteger(IUP_HEIGHTDEF, 6);

        SetAttributeId2("",  0,                         0,   __("RSA key pair and PrKDF, PuKDF attributes"));
        SetAttributeId2("",  0,                         1,   __("value"));
        SetAttributeId2("",  0,                         2,   __("Stored where? (private key file should be unreadable)"));
        SetAttributeId2("",  r_acos_internal,           0,   __("Acos key generation settings"));

        SetAttributeId2("",  r_keyAsym_RSAmodulusLenBits,          0,   __("Modulus bitLength"));
        SetAttributeId2("",  r_keyAsym_RSAmodulusLenBits,          2,   __("keypair files, PrKDF, PuKDF"));
        SetAttributeId2("",  r_keyAsym_crtModeGenerate, 0,   __("    Private key stored acc. ChineseRemainderTheorem ?"));
        SetAttributeId2("",  r_keyAsym_crtModeGenerate, 2,   __("CRT contents do or don't exist in private key file"));
        SetAttributeId2("",  r_keyAsym_usageGenerate,   0,   __("    Private key core capability (4)sign, (2)decrypt, (6)sign+decrypt (enter as int, shown as text)"));
        SetAttributeId2("",  r_keyAsym_usageGenerate,   2,   __("private key file"));
        SetAttributeId2("",  r_keyAsym_Label,            0,   __("Key pair label"));
        SetAttributeId2("",  r_keyAsym_Label,            2,   __("PrKDF, PuKDF"));
        SetAttributeId2("",  r_keyAsym_Id,               0,   __("Key pair id (1 byte hex. 01..FF)"));
        SetAttributeId2("",  r_keyAsym_Id,               2,   __("PrKDF, PuKDF"));

        SetAttributeId2("",  r_keyAsym_fidAppDir,               0,   __("File id of enclosing directory (2 bytes hex.)"));
        SetAttributeId2("",  r_keyAsym_fidAppDir,               2,   __("PrKDF, PuKDF"));
        SetAttributeId2("",  r_fidRSAprivate,           0,   __("File id of private key (2 bytes hex.)"));
        SetAttributeId2("",  r_fidRSAprivate,           2,   __("PrKDF, public key file"));
        SetAttributeId2("",  r_fidRSApublic,            0,   __("File id of public key (2 bytes hex.)"));
        SetAttributeId2("",  r_fidRSApublic,            2,   __("PuKDF, private key file"));
        SetAttributeId2("",  r_sizeNewRSAprivateFile,   0,   __("Private key file size (bytes) required / available"));
        SetAttributeId2("",  r_sizeNewRSAprivateFile,   2,   __("Header (FCI) of private key file"));
        SetAttributeId2("",  r_sizeNewRSApublicFile,    0,   __("Public key file size (bytes) required / available"));
        SetAttributeId2("",  r_sizeNewRSApublicFile,    2,   __("Header (FCI) of public key file"));
        SetAttributeId2("",  r_change_calcPrKDF,        0,   __("PrKDF change calc. (How many bytes more or less will be required to store the changes)")); //  / unused available A/A
        SetAttributeId2("",  r_change_calcPrKDF,        1,   "?");
        SetAttributeId2("",  r_change_calcPuKDF,        0,   __("PuKDF change calc. (How many bytes more or less will be required to store the changes)")); //  / does it fit into file size? A/A
        SetAttributeId2("",  r_change_calcPuKDF,        1,   "?");
        SetAttributeId2("",  r_keyAsym_authId,        0,   __("authId (that protects private key; 1 byte hex. 01..FF)"));
        SetAttributeId2("",  r_keyAsym_authId,        2,   __("PrKDF"));
        SetAttributeId2("",  r_valuePublicExponent,     0,   __("Public exponent e (a prime, default 0x10001; max 16 bytes hex., leading zero bytes trimmed)  0x"));
        SetAttributeId2("",  r_valuePublicExponent,     2,   __("public key file"));
        SetAttributeId2("",  r_statusInput,             0,   __("Status of input (whether all required info/limits are okay for the operation"));
        SetAttributeId2("",  r_statusInput,             1,  "No");
        SetRGBId2(IUP_BGCOLOR, r_statusInput, 1,  255, 0, 0);
        SetAttributeId2("",  r_keyAsym_usagePrKDF, 0,   __("Private key usage PrKDF (enter as int, 2.. max 558, shown as text)"));
        SetAttributeId2("",  r_keyAsym_usagePrKDF, 2,   __("PrKDF"));
//        SetAttributeId2("",  r_usageRSApublicKeyPuKDF,  0,   __("Public key usage PuKDF (enter as int, 1.. max 209, shown as text)"));
//        SetAttributeId2("",  r_usageRSApublicKeyPuKDF,  2,   __("PuKDF"));
        SetAttributeId2("",  r_keyAsym_Modifiable,       0,   __("Key pair is modifiable?"));
        SetAttributeId2("",  r_keyAsym_Modifiable,       2,   __("PrKDF, PuKDF"));

        SetAttributeId2("",  r_AC_Update_PrKDF_PuKDF,   0,   __("Access Control condition for Update: PrKDF / PuKDF (SCB hex shown; 0x00 means unrestricted)"));
        SetAttributeId2("",  r_AC_Update_Delete_RSAprivateFile,0,   __("Access Control condition for Update / Delete: Private key file"));
        SetAttributeId2("",  r_AC_Update_Delete_RSApublicFile, 0,   __("Access Control condition for Update / Delete: Public key file"));
        SetAttributeId2("",  r_AC_Delete_Create_RSADir,        0,   __("Access Control condition for Create / Delete: Enclosing DF"));
        SetAttribute(IUP_TOGGLECENTERED, IUP_YES);


        SetCallback(IUP_DROPCHECK_CB,  cast(Icallback)&matrixKeyAsym_dropcheck_cb);
        SetCallback(IUP_DROP_CB,       cast(Icallback)&matrixKeyAsym_drop_cb);
        SetCallback(IUP_DROPSELECT_CB, cast(Icallback)&matrixKeyAsym_dropselect_cb);
        SetCallback(IUP_EDITION_CB,    cast(Icallback)&matrixKeyAsym_edition_cb);
        SetCallback(IUP_TOGGLEVALUE_CB,cast(Icallback)&matrixKeyAsym_togglevalue_cb);
//        SetCallback(IUP_CLICK_CB,      cast(Icallback)&matrixKeyAsym_click_cb);
    }
    child_array ~= matrix;

    auto btn_RSA = new Button("btn_RSA",  __("PrKDF/PuKDF only: Change some administrative (PKCS#15) data")); // this(string CN, const(char)* title)
    btn_RSA.SetCallback(IUP_ACTION, &btn_RSA_cb);
    btn_RSA.SetAttribute(IUP_TIP, __("The action performed depends on the radio button setting"));
    Control[] child_array3;
    child_array3 ~= btn_RSA;
/* * /
    auto btn_RSA_checkPRKDF_PUKDF = new Button("btn_RSA_checkPRKDF_PUKDF",  __("for debugging only: btn_RSA_checkPRKDF_PUKDF")); // this(string CN, const(char)* title)
    btn_RSA_checkPRKDF_PUKDF.SetCallback(IUP_ACTION, &btn_RSA_checkPRKDF_PUKDF_cb);
    child_array3 ~= btn_RSA_checkPRKDF_PUKDF;
/ * */
    child_array ~= new Hbox(child_array3, FILL_TYPE.FILL_FRONT_AND_BACK);

    auto vbox = new Vbox(child_array/*, FILL_TYPE.FILL_FRONT_AND_BACK_AND_BETWEEN*/);
    vbox.SetAttribute(ICTL_TABTITLE, "KeyAsym (RSA)");
    return vbox;
}

private Vbox create_KeySym_tab() {
    Control[]  child_array, child_array_toggles;

    auto toggle1 = new Toggle("toggle_sym_SKDF_change", __("SKDF only: Change some administrative (PKCS#15) data, but no change concerning key content (select by keyRef)"));
    child_array_toggles ~= toggle1;
    auto toggle2 = new Toggle("toggle_sym_update", __("Update/Write a key file record (excluding the special keys for Secure Messaging #1 amd #2)"));
    child_array_toggles ~= toggle2;
    auto toggle4 = new Toggle("toggle_sym_updateSMkeyHost", __("Update/Write record #1 for SM (keyHost for ExtAuth; some restrictions apply; the same must be in opensc as key...mac)"));
    auto toggle3 = new Toggle("toggle_sym_updateSMkeyCard", __("Update/Write record #2 for SM (keyCard for IntAuth; some restrictions apply; the same must be in opensc as key...enc)"));
    child_array_toggles ~= toggle3;
    child_array_toggles ~= toggle4;

    foreach (i,toggle; child_array_toggles) {
        toggle.SetAttributeVALUE(i==0? IUP_ON : IUP_OFF);
//        toggle.SetCallback(IUP_ACTION, cast(Icallback) &toggle_RSA_cb);
    }
    child_array  ~= new Radio("radioKeySym", new Vbox(child_array_toggles, FILL_TYPE.FILL_FRONT_AND_BACK_AND_BETWEEN));

    auto matrix = new Matrix("matrixKeySym");
    with (matrix) {
        SetInteger(IUP_NUMLIN,         r_keySym_fidAppDir);
        SetInteger(IUP_NUMLIN_VISIBLE, r_keySym_fidAppDir);
        SetInteger(IUP_NUMCOL,          2);
        SetInteger(IUP_NUMCOL_VISIBLE,  2);
        SetAttribute(IUP_RESIZEMATRIX, IUP_YES);
//      SetAttribute("LIMITEXPAND",  IUP_YES);
        SetAttribute(IUP_READONLY,     IUP_NO);
//      SetAttribute("FLATSCROLLBAR",     IUP_YES);
//      SetAttribute("EDITNEXT",     "COL");
        SetIntegerId(IUP_WIDTH,   0,    400);
        SetIntegerId(IUP_WIDTH,   1,    130);
        SetIntegerId(IUP_WIDTH,   2,    230);
        SetInteger(IUP_HEIGHTDEF, 6);


//        SetIntegerId(IUP_HEIGHT, r_keySym_IntAutStore, 0);

        SetAttributeId2("",  0,                         0,   __("AES/3DES key and SKDF attributes"));
        SetAttributeId2("",  0,                         1,   __("value"));
        SetAttributeId2("",  0,                         2,   __("Stored where? (key file should be unreadable)"));

        SetAttributeId2("",  r_keySym_global_local,     0,   __("Key file is local to an appDF? (0/No, then it's MF's global key file)  This identifies the key file  to work with"));
        SetAttributeId2("",  r_keySym_global_local,     2,   "");

        SetAttributeId2("",  r_keySym_Id,               0,   __("Key file's Id"));
        SetAttributeId2("",  r_keySym_Id,               2,   "SKDF");

//        SetAttributeId2("",  r_keySym_recordNo,         0,   __("Key file's record number  to work with (1-31 max.)  new/append/existing"));
//        SetAttributeId2("",  r_keySym_recordNo,         1,   "1");
////      SetAttributeId2("",  r_keySym_recordNo,         2,   ""));
//        SetAttributeId2("",  r_keySym_keyRef,           0,   __("Key file's keyRef"));
//        SetAttributeId2("",  r_keySym_keyRef,           2,   "SKDF");

        SetAttributeId2("",  r_keySym_Label,            0,   __("label"));
        SetAttributeId2("",  r_keySym_Label,            2,   "SKDF");

        SetAttributeId2("",  r_keySym_Modifiable,       0,   __("keySym_Modifiable"));
        SetAttributeId2("",  r_keySym_Modifiable,       2,   "SKDF");


        SetAttributeId2("",  r_keySym_usageSKDF,               0,   __("keySym_usageSKDF"));
        SetAttributeId2("",  r_keySym_usageSKDF,               2,   "SKDF");

        SetAttributeId2("",  r_keySym_authId,           0,   __("keySym_authId"));
        SetAttributeId2("",  r_keySym_authId,           2,   "SKDF");

        SetAttributeId2("",  r_keySym_algoType,         0,   __("Algorithm type selection AES or one of DES, 3DES_128bit, 3DES_192bit"));
        SetAttributeId2("",  r_keySym_algoType,         2,    "SKDF, keySym file");

        SetAttributeId2("",  r_keySym_keyLenBits,        0,   __("Key bitLength"));
//        SetAttributeId2("",  r_keySym_keyLenBits,        1,    "192");
        SetAttributeId2("",  r_keySym_keyLenBits,        2,    "SKDF, keySym file");

        SetAttributeId2("",  r_keySym_algoStore,       0,   __("keySym_algoStore"));
        SetAttributeId2("",  r_keySym_algoStore,       1,    "0xab");
        SetAttributeId2("",  r_keySym_algoStore,       2,    "SKDF, keySym file");

        SetAttributeId2("",  r_keySym_ExtAutStore,           0,   __("keySym_ExtAutStore"));
        SetAttributeId2("",  r_keySym_ExtAutStore,           1,    "1");
        SetAttributeId2("",  r_keySym_ExtAutStore,           2,    "keySym file");

        SetAttributeId2("",  r_keySym_ExtAut_ErrorCounterYN,     0,   __("keySym_ExtAut_ErrorCounterYN  No means no error limit in ExtAut, using symbolic value 0xFF"));
        SetAttributeId2("",  r_keySym_ExtAut_ErrorCounterYN,     1,    "1");
        SetAttributeId2("",  r_keySym_ExtAut_ErrorCounterYN,     2,    "keySym file");

        SetAttributeId2("",  r_keySym_ExtAut_ErrorCounterValue,  0,   __("keySym_ExtAut_ErrorCounterValue 1..14"));
        SetAttributeId2("",  r_keySym_ExtAut_ErrorCounterValue,  1,    "8");
        SetAttributeId2("",  r_keySym_ExtAut_ErrorCounterValue,  2,    "keySym file");

        SetAttributeId2("",  r_keySym_IntAutStore,           0,   __("keySym_IntAutStore"));
        SetAttributeId2("",  r_keySym_IntAutStore,           1,    "1");
        SetAttributeId2("",  r_keySym_IntAutStore,           2,    "keySym file");

        SetAttributeId2("",  r_keySym_IntAut_UsageCounterYN,     0,   __("keySym_IntAut_UsageCounterYN"));
        SetAttributeId2("",  r_keySym_IntAut_UsageCounterYN,     1,    "1");
        SetAttributeId2("",  r_keySym_IntAut_UsageCounterYN,     2,    "keySym file");

        SetAttributeId2("",  r_keySym_IntAut_UsageCounterValue,  0,   __("keySym_IntAut_UsageCounterValue"));
        SetAttributeId2("",  r_keySym_IntAut_UsageCounterValue,  1,    "FFFE");
        SetAttributeId2("",  r_keySym_IntAut_UsageCounterValue,  2,    "keySym file");

        SetAttributeId2("",  r_keySym_valueStore,              0,   __("Key's value"));
        SetAttributeId2("",  r_keySym_valueStore,              1,    "0102030405060708090A0B0C0D0E0F101112131415161718");
        SetAttributeId2("",  r_keySym_valueStore,              2,    "keySym file");

        SetAttributeId2("",  r_keySym_ByteStringStore,              0,   __("This will be written to file/record"));
//        SetAttributeId2("",  r_keySym_ByteStringStore,              1,    "0102030405060708090A0B0C0D0E0F101112131415161718");
        SetAttributeId2("",  r_keySym_ByteStringStore,              2,    "keySym file");

        SetAttributeId2("",  r_keySym_fid,              0,   __("Id of keySym File selected"));
//        SetAttributeId2("",  r_keySym_fid,              1,   "4102");
//        SetAttributeId2("",  r_keySym_fid,     2,   __(""));

        SetAttributeId2("",  r_keySym_fidAppDir,        0,   __("Id of enclosing DF (appDF or MF)"));
//        SetAttributeId2("",  r_keySym_fidAppDir,        1,   "4100");
//        SetAttributeId2("",  r_keySym_fidAppDir,     2,   __(""));


        SetAttribute(IUP_TOGGLECENTERED, IUP_YES);

        SetCallback(IUP_DROPCHECK_CB,  cast(Icallback)&matrixKeySym_dropcheck_cb);
        SetCallback(IUP_DROP_CB,       cast(Icallback)&matrixKeySym_drop_cb);
        SetCallback(IUP_DROPSELECT_CB, cast(Icallback)&matrixKeySym_dropselect_cb);
        SetCallback(IUP_EDITION_CB,    cast(Icallback)&matrixKeySym_edition_cb);
        SetCallback(IUP_TOGGLEVALUE_CB,cast(Icallback)&matrixKeySym_togglevalue_cb);

//        SetCallback(IUP_CLICK_CB,      cast(Icallback)&matrixKeySym_click_cb);
    }
    child_array ~= matrix;

    auto vbox = new Vbox(child_array/*, FILL_TYPE.FILL_FRONT_AND_BACK_AND_BETWEEN*/);
    vbox.SetAttribute(ICTL_TABTITLE, "KeySym (AES/3DES)");
    return vbox;
}

private Vbox create_sanityCheck_tab() {
    Control[]  child_array;

    auto text1 = new Text("sanity_overview_text");
    with (text1) {
        SetInteger(IUP_SIZE, 900);
        SetAttribute(IUP_MULTILINE, IUP_YES);
        SetInteger(IUP_VISIBLELINES, 8);
        SetAttribute(IUP_WORDWRAP,  IUP_YES);
    }
    child_array ~= text1;

    auto matrix = new Matrix("matrixsanity");
    with (matrix) {
        SetInteger(IUP_NUMLIN,         3);
        SetInteger(IUP_NUMLIN_VISIBLE, 3);
        SetInteger(IUP_NUMCOL,         2);
        SetInteger(IUP_NUMCOL_VISIBLE, 2);
        SetAttribute(IUP_RESIZEMATRIX, IUP_YES);
//      SetAttribute("LIMITEXPAND",  IUP_YES);
        SetAttribute(IUP_READONLY,     IUP_NO);
//      SetAttribute("FLATSCROLLBAR",     IUP_YES);
//      SetAttribute("EDITNEXT",     "COL");
        SetIntegerId(IUP_WIDTH,   0,    250);
        SetIntegerId(IUP_WIDTH,   1,    130);
        SetIntegerId(IUP_WIDTH,   2,    400);
        SetInteger(IUP_HEIGHTDEF, 6);

        SetAttributeId2("",  0,   0,   __("Attributes"));
        SetAttributeId2("",  0,   1,   __("value"));
        SetAttributeId2("",  0,   2,   __("Meaning"));
        SetAttributeId2("",  1,   0,   __("Card type from match ATR"));
        SetAttributeId2("",  1,   2,   __("16003: ACOS5-64 V2.00 (Card/CryptoMate64);  16004: ACOS5-64 V3.00 (Card/CryptoMate Nano)"));

        SetAttributeId2("",  2,   0,   __("Card OS version major/minor from command 'Get Card Info'"));
        SetAttributeId2("",  2,   2,   __("Reflects both: Card type and Operation Mode Byte setting"));
        SetAttributeId2("",  3,   0,   __("Operation Mode Byte setting from command 'Get Card Info'"));
        SetAttributeId2("",  3,   2,   __("Non-retrievable for ACOS5-64 V2.00"));
        SetAttribute(IUP_TOGGLECENTERED, IUP_YES);

//        SetCallback(IUP_DROPCHECK_CB,  cast(Icallback)&matrixSanity_dropcheck_cb);
//        SetCallback(IUP_DROP_CB,       cast(Icallback)&matrixSanity_drop_cb);
//        SetCallback(IUP_DROPSELECT_CB, cast(Icallback)&matrixSanity_dropselect_cb);
//        SetCallback(IUP_EDITION_CB,    cast(Icallback)&matrixSanity_edition_cb);
//        SetCallback(IUP_TOGGLEVALUE_CB,cast(Icallback)&matrixSanity_togglevalue_cb);
//        SetCallback(IUP_CLICK_CB,      cast(Icallback)&matrixSanity_click_cb);
    }
    child_array ~= matrix;

    auto text2 = new Text("sanity_text");
    with (text2) {
        SetInteger(IUP_SIZE, 900);
        SetAttribute(IUP_MULTILINE, IUP_YES);
        SetInteger(IUP_VISIBLELINES, 30);
        SetAttribute(IUP_WORDWRAP, IUP_YES);
    }
    child_array ~= text2;

    auto btn_sanity = new Button("btn_sanity",  __("Perform sanity check"));
    btn_sanity.SetCallback(IUP_ACTION, &btn_sanity_cb);
//    btn_sanity.SetAttribute(IUP_TIP, __("The action performed depends on the radio button setting"));
    Control[] child_array3;
    child_array3 ~= btn_sanity;
    child_array ~= new Hbox(child_array3, FILL_TYPE.FILL_FRONT_AND_BACK);

    auto vbox = new Vbox(child_array, FILL_TYPE.FILL_BETWEEN);
    vbox.SetAttribute(ICTL_TABTITLE, "sanityCheck");
    return vbox;
}


private Vbox create_importExport_tab() {
    Control[]  child_array;

    auto text1 = new Text("importExport_text");
    with (text1) {
        SetAttribute(IUP_SIZE, "800");
        SetAttribute(IUP_MULTILINE, IUP_YES);
        SetAttribute(IUP_VISIBLELINES, "16");
        SetAttribute(IUP_WORDWRAP, IUP_YES);
    }
    child_array ~= text1;

    auto btn_exportArchive = new Button("exportArchive",  __("exportArchive"));
    btn_exportArchive.SetCallback(IUP_ACTION, &btn_exportArchive_cb);
//    btn_exportArchive.SetAttribute(IUP_TIP, __("The action performed depends on the radio button setting"));
    child_array ~= btn_exportArchive;
//    Control[] child_array3;
//    child_array3 ~= btn_RSA;
/* * /
    auto btn_RSA_checkPRKDF_PUKDF = new Button("btn_RSA_checkPRKDF_PUKDF",  __("for debugging only: btn_RSA_checkPRKDF_PUKDF")); // this(string CN, const(char)* title)
    btn_RSA_checkPRKDF_PUKDF.SetCallback(IUP_ACTION, &btn_RSA_checkPRKDF_PUKDF_cb);
    child_array3 ~= btn_RSA_checkPRKDF_PUKDF;
/ * */
//    child_array ~= new Hbox(child_array3, FILL_TYPE.FILL_FRONT_AND_BACK);

    auto vbox = new Vbox(child_array, FILL_TYPE.FILL_BETWEEN);
    vbox.SetAttribute(ICTL_TABTITLE, "Import/Export");
    return vbox;
}


Dialog create_dialog_dlg0() {
    /* Example of i18n usage */
    auto btn_exit    = new Button(  __("Exit")); // __("Beenden")
////  btn_exit.SetCallback(IUP_ACTION, &dlg0_exit);
    btn_exit.SetAttribute(IUP_TIP, __("more to come"));

    auto hbox = new Hbox([ btn_exit ], FILL_TYPE.FILL_FRONT_AND_BACK_AND_BETWEEN);

    Control[] child_array = [
        create_cryptoki_slot_tokeninfo_tab,
        create_filesystem_tab,
        create_KeyASym_tab,
        create_KeySym_tab,
        create_importExport_tab,
//      create_ssh_tab,
//      create_sanityCheck_tab,
//      create_opensc_conf_tab,
    ];
    auto tabs = new Tabs("tabCtrl", child_array);
//  tabs.SetAttribute(ICTL_TABTYPE, ICTL_TOP); // Default is "TOP"

    auto lbl_statusbar = new Label("statusbar", "statusbar");
    lbl_statusbar.SetAttribute(IUP_EXPAND, IUP_HORIZONTAL);
    lbl_statusbar.SetAttribute(IUP_PADDING, "10x5");

    auto vbox = new Vbox(/*new Fill, */ hbox /*, new Fill*/, tabs, lbl_statusbar);
    auto dialog = new Dialog("dlg0", true, vbox);
    dialog.SetAttribute(IUP_TITLE, __("tool for driver acos5_64"));
    dialog.SetAttribute(IUP_MARGIN, "2x2");
    return dialog;
}
