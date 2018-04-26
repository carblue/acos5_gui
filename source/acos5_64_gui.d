/*
 * Written in the D programming language, part of package acos5_64_gui.
 * acos5_64_gui.d: main file
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


/*
This program MUST NOT be used in parallel to using libacos5_64.so in other ways like through opensc-pkcs11.so
as it may alter the selected file unexpected by other software!
TODO check about countermeasures like locking etc. provided by PKCS#11
*/

module acos5_64_gui;


import core.memory : GC;
import core.runtime : Runtime;
import core.stdc.config : c_long, c_ulong;
import core.stdc.stdlib : EXIT_SUCCESS, EXIT_FAILURE, exit, getenv; //, div_t, div, malloc, free;
import core.stdc.locale : setlocale, LC_ALL;
//import core.stdc.stdio : printf;
import std.stdio : write, writeln, writefln, stdout;
//import std.typecons;
import std.string : fromStringz, toStringz, representation;
import std.algorithm.searching;
import std.algorithm.comparison;
import std.conv : to;
//import std.concurrency;
//import core.thread;

/*
import deimos.openssl.crypto : CRYPTO_cleanup_all_ex_data;
import deimos.openssl.conf;
import deimos.openssl.evp;
import deimos.openssl.err;
*/
/*
import deimos.openssl.rsa;
import deimos.openssl.sha;
import deimos.openssl.rand;
import deimos.openssl.bn : BN_num_bits;
//import deimos.openssl.ossl_typ : RSA_METHOD;
//import deimos.openssl.evp : EVP_PKEY_RSA / *6* /;
*/

import libopensc.opensc;
import libopensc.types;
import libopensc.errors;
import libopensc.log;

import libintl : _, __;
version(I18N)
import libintl : bindtextdomain, textdomain, bind_textdomain_codeset;

import iup.iup_plusD;

//import deimos.p11; "dependencies" : "p11:deimos": "~>0.0.3", // it's an alternative for "dependencies" : "pkcs11": "~>2.40.0-alpha.3"
import pkcs11;

import gui : create_dialog_dlg0;
import util_opensc : lh, card, util_connect_card, populate_tree_fs, acos5_64_short_select; // , uploadHexfile
import util_pkcs11 : pkcs11_check_return_value, pkcs11_get_slot;



string blankPaddingTrimmed(ubyte[] buf) {
return "";
}

version(unittest) {}
else
int main(string[] args) {

version(I18N) {
    /* Setting the i18n environment */
    setlocale (LC_ALL, "");
    cast(void) bindtextdomain ("acos5_64_gui", getenv("PWD"));
    cast(void) textdomain ("acos5_64_gui");
    /*printf("bind_textdomain_codeset: %s\n",*/cast(void) bind_textdomain_codeset("acos5_64_gui", "UTF-8");//);
}
    /* connect to card  and release all resources (opensc/driver when leaving the following scope */
    {
        string debug_file = "/tmp/opensc-debug.log";

        sc_context*         ctx;
        sc_context_param_t  ctx_param = { 0, "acos5_64_gui " };
        if (sc_context_create(&ctx, &ctx_param))
            return EXIT_FAILURE;
//        assert(ctx);
//        writeln(*ctx);

version(OPENSC_VERSION_LATEST)
        ctx.flags |= SC_CTX_FLAG_ENABLE_DEFAULT_DRIVER;
        ctx.debug_ = SC_LOG_DEBUG_NORMAL/*verbose*/;
        sc_ctx_log_to_file(ctx, toStringz(debug_file));
        if (sc_set_card_driver(ctx, "acos5_64"))
            return EXIT_FAILURE;

        int rc; // used for any return code except Cryptoki return codes, see next decl
        rc = util_connect_card(ctx, &card, null/*opt_reader*/, 0/*opt_wait*/, 1 /*do_lock*/, SC_LOG_DEBUG_NORMAL/*verbose*/);
        mixin (log!(__FUNCTION__, " error of util_connect_card: %d", "rc"));
//        writeln("PASSED: util_connect_card");
        scope(exit) {
            if (card) {
    			if (! Runtime.unloadLibrary(lh))
    				exit(1);
version(Windows) {}
else {
	version(unittest) {}
	else {
				if (! Runtime.terminate())
					exit(1);
	}
}

				sc_unlock(card);
				sc_disconnect_card(card);
			}
            if (ctx)
                sc_release_context(ctx);
//            {
//                auto f = File(debug_file, "w"); // open for writing, i.e. Create an empty file for output operations. If a file with the same name already exists, its contents are discarded and the file is treated as a new empty file.
//            }
        } // scope(exit)
        if (rc || !card)
            return EXIT_FAILURE;

        IupOpenD();
        IupControlsOpen(); // without this, no Matrix etc. will be visible
        version(Windows)  IupSetGlobal("UTF8MODE", "YES");

        /* Shows dialog */
        create_dialog_dlg0.Show; // this does the mapping; it's here because some things can be done only after mapping
        populate_tree_fs();
/+
        import std.range : chunks;
        ubyte[6] certPath = [0x3F, 0x00, 0x41, 0x00, 0x41, 0x20];
        foreach (ubyte[2] fid2; chunks(certPath[], 2))
            rc= acos5_64_short_select(card, null, fid2, false);
//        ubyte[8] pin = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
//        int tries_left;
//        rc = sc_verify(card, SC_AC.SC_AC_CHV, 0x81, pin.ptr, pin.length, &tries_left);
        assert(rc==0);//  return EXIT_FAILURE;

	    rc = uploadHexfile(card, "/path/to/cert.hex", 0, 1664, 0);
//        assert(rc==0);//  return EXIT_FAILURE;
+/
    } // connect to card
    AA["fs_text_asn1"].SetAttributeVALUE("");
    AA["fs_text"].SetAttributeVALUE("");
    AA["fs_text"].SetString("APPEND", " ");
    AA["fs_text"].SetString("APPEND", "The translation feature is used currently for the button text Exit only.\n");
    AA["fs_text"].SetString("APPEND", "It translates to Beenden in german\n");
    AA["fs_text"].SetString("APPEND", `
A remark upfront: While ACOS supports SFI (Short File Identifier), it's used neither by opensc, nor by the driver or this app. Only regular FID (File Identifier) 2 Bytes long are used !
Also, pathes are used only as absolute pathes, thus beginning at root FID 0x3F00. A path may consist of max 8 FID components (opensc limitation), but it's recommended to use only max 5 FID components,
an acos limitation: Access control information of files/directories in deeper levels of the file system hierarchy don't get stored ! Thus You would go unprotected there.

It's warmly recommended to have only distinct FIDs within the card file system. This can be respected even with multiple PKCS#15 applications by specific entries in EF.DIR, replacing the mandatory standard FIDs.
The reason is, that acos has a putative smart file search algorithm if a file doesn't get found immediately. Thus with duplicate FIDs there is a potential to select and possibly operate on a different file than intended.
Also, the driver does track the current position of file selection in order to minimize the number of selections required to get to a new selected target. In rare cases, a disoriented tracking by duplicated FID may lead to
problems finding a file (if only a FID but no absolute path is given as select target; in the past opensc sometimes did that) !
Sadly, there is no means to detect explicitely, where the acos internal file selection points to !
It's better to not find a file than find the wrong file, but the acos putative smart file search algorithm can't be disabled.


The semantic/meaning of files is either implicitely known to acos (by File Descriptor Byte FDB) or
known to this application (by file introspection for transparent files) or
unknown (visualized by a dot image symbol).
Symbol images and last text component in each node's text further contain semantic information, if available.

There are 2 kind of trees maintained by this application:
1. Tne file system tree with it's visual representation of hierarchical file structure.
2. The 'PKCS#15 file tree' (a subset of file system tree), which is visualized by 'sheet of paper' images (blank or written)
   and comprises those files, that are detected/introspected and verified to be mentioned in PKCS#15 file structure.
   Only files with 'sheet of paper'-image are known to PKCS#15/opensc (+ the internal Elementary Files of type Pin, Symkey and SecEnv,
   which are shown without any image at all: They (usually all 3, maybe except Symkey) are core files for security and access control in each directory.
   written-'sheet of paper'-image files are organizational (object directory) files.
   blank-'sheet of paper'-image files are the leaf files containing specific objects like RSA, certificate etc. .

Also, some files are mandatory for a PKCS#15 file structure and have (acc. standard) a meaning by file id, which are:
3F00 : MF, the file system root
2F00 : EF.DIR
5031 : EF.OD  in each application directory
5032 : EF.CardInfo  in each application directory

Usually, there should be no (unknown meaning) dot-symbol files, except You know what they are for.
Those existing in this example are:
5155, 4129: Leftovers from ACOS client kit, subject to removal where possible and still to be compatible with ACS ACOS5-64 driver.
3901-3908 and 4300 + it's sub-files: Temporary dot-symbol files for testing purposes

The checkbox/toggle is not meant to be used by the user: It just visualizes, whether a file is 'activated' and thus subject to acos access control,
recommended for all files for security reasons.

The access control information is visualized (indirectly) by contents of the Dropdown/ComboBox:
Each file/direcory has 7 bits (Security Attributes Compact SAC) in it's header/meta data storing access control information, different for diverging file descriptor bytes.
thus the maximum of entries in the ComboBox is 7, reduced depending on the "Suppress rare operations"-Checkbox and all operations removed, that are inhibited for that file.
The complete picture of Access Control involves directory file (for delete permission) as well and maybe also Security Attributes Expanded SAE and of course the directory's SecEnv
(Security Environment File). Anyway, what the ComboBox offers, are those operation (groups), that are not forbidden, but they may be subject to further authorization
according to access control (most notably by Pin entry for User or Security Officer (global Pin))
The handling of access control condition 'Secure Messaging required' is handled transparently if no Pin Authorization is involved in the access control,
otherwise, same as for other cases You will be asked for Pin entry if required.

If the Dropdown offers Read-Operation only, this is (depending on Checkbox "Perform 'Read operation' automatically", the sole operation done automatically.
In this sense, the page offers read-only access to the file system.
Any other operation, including writing-to-the-card-operations, require explicit control by clicking button "do it"
Usually all those 'explicit' operations involve some kind of authorization.

Also, You should know this about Pins:
1. opensc is able to cache pin entries for repeated usage (e.g. 10 times) without user consent: This is controlled by the userConsent entry in EF.AOD.
   This is convenient, but my not be what You want. Set userConsent to 1 then.
2. Whether we like it or not, some mainstream applications like Thunderbird/Firefox ask for the user pin upfront, once a cryptographic module shall be loaded,
   even if it's not required. Worse, there is no information, what the revealed credential is used for.
   This practice absolutely dissatisfies me, and that's why I tend to not rely on the user pin as a security feature and why the acos5_64 driver offers an
   additional level of control against 'misuse' of private RSA keys: By opensc.conf settings, a graphical popup for additional user consent may be enabled,
   which pops up when a private RSA key shall be used for signing or decrypting, effectively giving control from case to case.
   This is a warmly recommended feature (though not enabled by default currently; diable that only temporarily for pkcs11-tool --test).
  `);

//version(all) {
    {
        // this one-liner enables operating with the module specified
        PKCS11.load("opensc-pkcs11.so");
        scope(exit)  PKCS11.unload();
        // Now PKCS#11 functions can be called, but as latest opensc-pkcs11.so implements Cryptoki API v2.20
        // and the headers cover API v2.40 as well, take care not to use/call anything unavailable !
        CK_RV rv;
        /* We aren't going to access the Cryptoki library from multiple threads simultaneously */
        CK_C_INITIALIZE_ARGS  init_args; // = {cast()NULL_PTR, NULL_PTR, NULL_PTR, NULL_PTR, CKF_OS_LOCKING_OK, NULL_PTR};
        init_args.flags = CKF_OS_LOCKING_OK;

        if ((rv= C_Initialize(&init_args)) != CKR_OK) { // CKR_ARGUMENTS_BAD, CKR_CANT_LOCK, CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_NEED_TO_CREATE_THREADS, CKR_OK.
            writeln("Failed to initialze Cryptoki");
            return EXIT_FAILURE;
        }
        scope(exit)
            C_Finalize(NULL_PTR);

        CK_INFO  info;
        pkcs11_check_return_value(rv= C_GetInfo(&info), "get info");
//        writeln("cryptokiVersion.major: ", info.cryptokiVersion.major);
//        writeln("cryptokiVersion.minor: ", info.cryptokiVersion.minor);
        AA["slot_token"].SetStringId2("",  1,  1, info.cryptokiVersion.major.to!string~"."~info.cryptokiVersion.minor.to!string);

        // TODO replace the pos-hack by blankPaddingTrimmed for all blank-padded strings
        ptrdiff_t pos = clamp(countUntil(info.manufacturerID[], [ubyte(32),ubyte(32)]), 0,32);
        AA["slot_token"].SetStringId2("",  2,  1, cast(string)info.manufacturerID.ptr[0..pos]);
        //    AA["slot_token"].SetIntegerId2("", 3,  1, cast(int)info.flags);

        pos = clamp(countUntil(info.libraryDescription[], [ubyte(32),ubyte(32)]), 0,32);
        AA["slot_token"].SetStringId2("",  4,  1, cast(string)info.libraryDescription.ptr[0..pos]);
        AA["slot_token"].SetStringId2("",  5,  1, info.libraryVersion.major.to!string~"."~info.libraryVersion.minor.to!string);

        CK_SLOT_ID  slotID = pkcs11_get_slot();
//        writeln("slotID: ", slotID);
        AA["slot_token"].SetIntegerId2("",  6,  1, cast(int)slotID);

        CK_SLOT_INFO  slotInfo;
        pkcs11_check_return_value(rv= C_GetSlotInfo(slotID, &slotInfo), "get slot info");
        pos = clamp(countUntil(slotInfo.slotDescription[], [ubyte(32),ubyte(32)]), 0,64);
//        writeln ("slotDescription: ", (cast(char*)slotInfo.slotDescription.ptr)[0..pos]);
        AA["slot_token"].SetStringId2("",  7,  1, cast(string)slotInfo.slotDescription.ptr[0..pos]);
        pos = clamp(countUntil(slotInfo.manufacturerID[], [ubyte(32),ubyte(32)]), 0,32);
//        writeln ("manufacturerID:  ", (cast(char*)slotInfo.manufacturerID.ptr)[0..pos]);
        AA["slot_token"].SetStringId2("",  8,  1, cast(string)slotInfo.manufacturerID.ptr[0..pos]);
//        writeln ("flags:           ", slotInfo.flags);
        if (slotInfo.flags & CKF_TOKEN_PRESENT)     AA["slot_token"].SetIntegerId2("",  9,  1,  1);
        if (slotInfo.flags & CKF_REMOVABLE_DEVICE)  AA["slot_token"].SetIntegerId2("", 10,  1,  1);
        if (slotInfo.flags & CKF_HW_SLOT)           AA["slot_token"].SetIntegerId2("", 11,  1,  1);
//        writefln("hardwareVersion: %s.%s", slotInfo.hardwareVersion.major, slotInfo.hardwareVersion.minor);
//        writefln("firmwareVersion: %s.%s", slotInfo.firmwareVersion.major, slotInfo.firmwareVersion.minor);
        AA["slot_token"].SetStringId2("", 12,  1, slotInfo.hardwareVersion.major.to!string~"."~slotInfo.hardwareVersion.minor.to!string~" / "~
                                              slotInfo.firmwareVersion.major.to!string~"."~slotInfo.firmwareVersion.minor.to!string);
        CK_TOKEN_INFO tokenInfo;
        pkcs11_check_return_value(rv= C_GetTokenInfo(slotID, &tokenInfo), "get token info");

//    pos = clamp(/*countUntil(tokenInfo.label[], 0/ *[ubyte(32),ubyte(32)]* /)*/32, 0,32);
//        writeln ("token.label:     ", (cast(char*)tokenInfo.label.ptr)[0..pos]);
//writefln ("token.label: 0x[%(%02X %)]: ", tokenInfo.label); // token.label: 0x[55 73 65 72 20 28 0C 12 43 54 4D 36 34 5F 43 30 43 36 34 30 36 38 38 31 43 37 29 20 20 20 20 20]:
        pos = clamp(countUntil(tokenInfo.label[], [ubyte(32),ubyte(32)]), 0,32);
        AA["slot_token"].SetStringId2("", 13,  1, cast(string)tokenInfo.label.ptr[0..pos]);

        pos = clamp(countUntil(tokenInfo.manufacturerID[], [ubyte(32),ubyte(32)]), 0,32);
        AA["slot_token"].SetStringId2("", 14,  1, cast(string)tokenInfo.manufacturerID.ptr[0..pos]);
        pos = clamp(countUntil(tokenInfo.model[], [ubyte(32),ubyte(32)]), 0,16);
        AA["slot_token"].SetStringId2("", 15,  1, cast(string)tokenInfo.model.ptr[0..pos]);
        pos = clamp(countUntil(tokenInfo.serialNumber[], [ubyte(32),ubyte(32)]), 0,16);
        AA["slot_token"].SetStringId2("", 16,  1, cast(string)tokenInfo.serialNumber.ptr[0..pos]);
        AA["slot_token"].SetIntegerId2("",17,  1, cast(int)tokenInfo.flags);

        if (tokenInfo.flags & CKF_RNG)                   AA["slot_token"].SetIntegerId2("", 18,  1,  1);
        if (tokenInfo.flags & CKF_WRITE_PROTECTED)       AA["slot_token"].SetIntegerId2("", 19,  1,  1);
        if (tokenInfo.flags & CKF_LOGIN_REQUIRED)        AA["slot_token"].SetIntegerId2("", 20,  1,  1);
        if (tokenInfo.flags & CKF_USER_PIN_INITIALIZED)  AA["slot_token"].SetIntegerId2("", 21,  1,  1);

        if (tokenInfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH) AA["slot_token"].SetIntegerId2("", 22,  1,  1);
        if (tokenInfo.flags & CKF_DUAL_CRYPTO_OPERATIONS)        AA["slot_token"].SetIntegerId2("", 23,  1,  1);
        if (tokenInfo.flags & CKF_TOKEN_INITIALIZED)             AA["slot_token"].SetIntegerId2("", 24,  1,  1);
        if (tokenInfo.flags & CKF_SECONDARY_AUTHENTICATION)      AA["slot_token"].SetIntegerId2("", 25,  1,  1);

        if (tokenInfo.flags & CKF_USER_PIN_COUNT_LOW)            AA["slot_token"].SetIntegerId2("", 26,  1,  1);
        if (tokenInfo.flags & CKF_USER_PIN_FINAL_TRY)            AA["slot_token"].SetIntegerId2("", 27,  1,  1);
        if (tokenInfo.flags & CKF_USER_PIN_LOCKED)               AA["slot_token"].SetIntegerId2("", 28,  1,  1);
        if (tokenInfo.flags & CKF_USER_PIN_TO_BE_CHANGED)        AA["slot_token"].SetIntegerId2("", 29,  1,  1);

        if (tokenInfo.flags & CKF_SO_PIN_COUNT_LOW)              AA["slot_token"].SetIntegerId2("", 30,  1,  1);
        if (tokenInfo.flags & CKF_SO_PIN_FINAL_TRY)              AA["slot_token"].SetIntegerId2("", 31,  1,  1);
        if (tokenInfo.flags & CKF_SO_PIN_LOCKED)                 AA["slot_token"].SetIntegerId2("", 32,  1,  1);
        if (tokenInfo.flags & CKF_SO_PIN_TO_BE_CHANGED)          AA["slot_token"].SetIntegerId2("", 33,  1,  1);

        ////    if (tokenInfo.flags & CKF_ERROR_STATE)                   AA["slot_token"].SetIntegerId2("", 34,  1,  1); // since version 2.30 ?
/+ +/
        AA["slot_token"].SetStringId2("", 35,  1, tokenInfo.ulSessionCount.to!string~" / "~tokenInfo.ulMaxSessionCount.to!string);
        AA["slot_token"].SetStringId2("", 36,  1, tokenInfo.ulRwSessionCount.to!string~" / "~tokenInfo.ulMaxRwSessionCount.to!string);
        AA["slot_token"].SetStringId2("", 37,  1, tokenInfo.ulMinPinLen.to!string~" / "~tokenInfo.ulMaxPinLen.to!string);

        ////    AA["slot_token"].SetStringId2("", 38,  1, (cast(float)tokenInfo.ulFreePublicMemory/1024).to!string~" / "~(cast(float)tokenInfo.ulTotalPublicMemory/1024).to!string);
        ////    AA["slot_token"].SetStringId2("", 39,  1, (cast(float)tokenInfo.ulFreePrivateMemory/1024).to!string~" / "~(cast(float)tokenInfo.ulTotalPrivateMemory/1024).to!string);
        AA["slot_token"].SetStringId2("", 40,  1, tokenInfo.hardwareVersion.major.to!string~"."~tokenInfo.hardwareVersion.minor.to!string~" / "~
                                              tokenInfo.firmwareVersion.major.to!string~"."~tokenInfo.firmwareVersion.minor.to!string);
    //    pos = clamp(countUntil(tokenInfo.utcTime[], [ubyte(32),ubyte(32)]), 0,16);
        AA["slot_token"].SetStringId2("", 41,  1, cast(string)tokenInfo.utcTime.ptr[0..16]);
    }
//} // version(all)

    AA["dlg0"].Update;
//    AA["tabCtrl"].SetInteger("VALUEPOS", 1); // why does this crash?
    GC.collect();
    /* start iteration */
    IupMainLoop();

    IupClose();
    return EXIT_SUCCESS;
}
