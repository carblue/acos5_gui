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


//import core.stdc.stdlib : strtol;
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
//import std.uni;
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

import util_general;
import gui : create_dialog_dlg0;
import util_opensc : lh, card, util_connect_card, populate_tree_fs, TreeTypeFS, fs, PKCS15_FILE_TYPE; //, acos5_64_short_select, uploadHexfile
import util_pkcs11 : pkcs11_check_return_value, pkcs11_get_slot;
import generateKeyPair_RSA;


void dummy_function(sc_context* ctx) /*@safe*/ {
    writeln("This is going to be printed from @safe code: ", *ctx);
}

string blankPaddingTrimmed(ubyte[] buf) {
return "";
}

//version(unittest) {}
//else
int main(string[] args) {

version(I18N) {
    /* import std.demangle : demangle;  Error when compiling with dmd and -dip1000, originating in iup_plusD.d, import std.string : toStringz, fromStringz, empty;
    Warnung: undefinierter Verweis auf »_D3std6string__T10stripRightTAyaZQrFNaNiNfNkQpZQs«
    Warnung: undefinierter Verweis auf »_D3std6string__T10stripRightTAyaZQrFNaNiNfNkQpZQs«
    writeln(demangle("_D3std6string__T10stripRightTAyaZQrFNaNiNfNkQpZQs")); // "pure @nogc @safe immutable(char)[] std.string.stripRight!(immutable(char)[]).stripRight(return immutable(char)[])" */
    /* Setting the i18n environment */
    setlocale (LC_ALL, "");
    cast(void) bindtextdomain ("acos5_64_gui", getenv("PWD"));
    cast(void) textdomain ("acos5_64_gui");
    /*printf("bind_textdomain_codeset: %s\n",*/cast(void) bind_textdomain_codeset("acos5_64_gui", "UTF-8");//);
}

    /* connect to card  and release all resources (opensc/driver when leaving the following scope */
    {
        string debug_file = "/tmp/opensc-debug.log";

        int rc; // used for any return code except Cryptoki return codes, see next decl
        sc_context*         ctx;
        sc_context_param_t  ctx_param = { 0, "acos5_64_gui " };
        if ((rc= sc_context_create(&ctx, &ctx_param)) != SC_SUCCESS)
            return EXIT_FAILURE;
        if (ctx is null)
            return EXIT_FAILURE;
//        writeln(*ctx);
//(() /*@safe*/ { dummy_function(ctx);})();

        ctx.flags |= SC_CTX_FLAG_ENABLE_DEFAULT_DRIVER;
        ctx.debug_ = SC_LOG_DEBUG_NORMAL/*verbose*/;
        sc_ctx_log_to_file(ctx, toStringz(debug_file));
        if (sc_set_card_driver(ctx, "acos5_64"))
            return EXIT_FAILURE;

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

        populate_tree_fs(); // populates PrKDF, PuKDF (and dropdown key pair id),

        /* assuming there is 1 aooDF only */
        TreeTypeFS.nodeType* appdf = fs.preOrderRange(fs.begin(), fs.end()).locate!"a[6]==b"(PKCS15_FILE_TYPE.PKCS15_APPDF);
//      assert(appdf);

        /* initialze the publisher/observer system for GenerateKeyPair_RSA_tab */
        sizeNewRSAModulusBits   = new Pub_noCB2!_sizeNewRSAModulusBits  (r_sizeNewRSAModulusBits,   AA["matrixRsaAttributes"]); // 1
        storeAsCRTRSAprivate    = new Pub_noCB2!_storeAsCRTRSAprivate   (r_storeAsCRTRSAprivate,    AA["matrixRsaAttributes"]); // 2
        usageRSAprivateKeyACOS  = new Pub_noCB2!_usageRSAprivateKeyACOS (r_usageRSAprivateKeyACOS,  AA["matrixRsaAttributes"]); //3
        usageRSAprivateKeyPrKDF = new Pub_noCB2!_usageRSAprivateKeyPrKDF(r_usageRSAprivateKeyPrKDF, AA["matrixRsaAttributes"]); //16
        usageRSApublicKeyPuKDF  = new Pub_noCB2!_usageRSApublicKeyPuKDF (r_usageRSApublicKeyPuKDF,  AA["matrixRsaAttributes"]); //17
        keyPairLabel            = new Pub_noCB2!(_keyPairLabel,string)  (r_keyPairLabel,            AA["matrixRsaAttributes"]);
        keyPairModifiable       = new Pub_noCB2!_keyPairModifiable      (r_keyPairModifiable,       AA["matrixRsaAttributes"]);
        authIdRSAprivateFile    = new Pub_noCB2!_authIdRSAprivateFile   (r_authIdRSAprivateFile,    AA["matrixRsaAttributes"], true);

        valuePublicExponent   = new PubA16!_valuePublicExponent     (r_valuePublicExponent,   AA["matrixRsaAttributes"]); // 14

        keyPairId             = new Pub_noCB2!_keyPairId            (r_keyPairId,             AA["matrixRsaAttributes"], true); // 5
        fidRSADir             = new Pub_noCB2!_fidRSADir            (r_fidRSADir,             AA["matrixRsaAttributes"], true); // 6
        fidRSAprivate         = new PubA2!_fidRSAprivate            (r_fidRSAprivate, AA["matrixRsaAttributes"]); // 7
        fidRSApublic          = new PubA2!_fidRSApublic             (r_fidRSApublic, AA["matrixRsaAttributes"]); // 8
//r_keyPairLabel, // 4
//r_keyPairId, // 5
        sizeNewRSAprivateFile = new Obs_sizeNewRSAprivateFile       (r_sizeNewRSAprivateFile, AA["matrixRsaAttributes"]); // 9
        sizeNewRSApublicFile  = new Obs_sizeNewRSApublicFile        (r_sizeNewRSApublicFile,  AA["matrixRsaAttributes"]); // 10
        statusInput           = new Obs_statusInput                 (r_statusInput,           AA["matrixRsaAttributes"]); // 15
        size_change_calcPrKDF = new Obs_size_change_calcPrKDF       (r_size_change_calcPrKDF, AA["matrixRsaAttributes"]);

//// dependencies
        fidRSAprivate        .connect(&sizeNewRSAprivateFile.watch); // just for show (sizeCurrentRSAprivateFile) reason
        sizeNewRSAModulusBits.connect(&sizeNewRSAprivateFile.watch);
        storeAsCRTRSAprivate .connect(&sizeNewRSAprivateFile.watch);

        fidRSApublic         .connect(&sizeNewRSApublicFile.watch);  // just for show (sizeCurrentRSApublicFile) reason
        sizeNewRSAModulusBits.connect(&sizeNewRSApublicFile.watch);

        keyPairId            .connect(&size_change_calcPrKDF.watch);
        keyPairLabel         .connect(&size_change_calcPrKDF.watch);
        authIdRSAprivateFile .connect(&size_change_calcPrKDF.watch);
        keyPairModifiable    .connect(&size_change_calcPrKDF.watch);

        fidRSADir            .connect(&statusInput.watch);
        fidRSAprivate        .connect(&statusInput.watch);
        fidRSApublic         .connect(&statusInput.watch);

//// values to start with
        fidRSADir            .set(appdf is null? 0 : ub22integral(appdf.data[2..4]), true);
/*
        keyPairId            .set(3, true);
        fidRSAprivate        .set([cast(int) strtol("41F1", null, 16), 0], true);
        fidRSApublic         .set([cast(int) strtol("4133", null, 16), 0], true);
        sizeNewRSAModulusBits.set(4096, true);
*/
        storeAsCRTRSAprivate. set(true, true);
        usageRSAprivateKeyACOS.set(6,   true); // this is only for acos-generation
        ubyte[16]  pe = [0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,1];
        valuePublicExponent  .set(pe,   true);
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
//        assert(rc==1664 /*lenWritten*/);//  return EXIT_FAILURE;
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

    AA["cst_text"].SetString("APPEND", `
Some remarks:
The tool works with 1 slot currently only, which is the first one found with a token present ! (There may be more slots with tokens present;
 the first one usually has Slot id : 0; later, there will be a selection for other present tokens)

The version of PKCS#15 / ISO 7816-15 supported by opensc versions 17/18 is PKCS#15 v1.1 / ISO 7816-15:2004

Relating to tab 'filesystem':
Toggle: Perform 'Read operation' automatically, if applicable and doesn't require authorization (except SM related):
This means: The read operation will be done automatically if not disallowed by file access permission and if
- No pin verification nor key authentication is required by file access condition, except
  if the file access condition is 'key to be authenticated' and that key is authenticated (automatically) already
  (like it may be configured for SM-protected files if the external authentication key is the key referred to here and
   external authentication was successful; SM-protected file operations invoke external authentication automatically), then do read automatically.

The tool aims at shielding the possibly complex access conditions of files (and commands) from the user and just ask for the required permission(s).
In order to check that, 2 file headers get printed, the enclosing DF's header and the header of the selected file/DF.
`);

    AA["gkpRSA_text"].SetString("APPEND", `
This page is dedicated to 'manipulating/handling' anything about RSA key pair content and/or files, as well as EF(PrKDF) and EF(PuKDF) content.
The basic requirement merely is, that the files PrKDF and PuKDF do exist and are known to opensc (by respective entries in EF(ODF)). PrKDF and PuKDF files may be empty though.

PKCS#15 tells, what EF(PrKDF) and EF(PuKDF) are for: They contain essential information about existing private/public RSA key files as a kind of directory type.
Any operation done on this page will likely have to update these files to be up to date.
ACOS stores a RSA key pair as 2 distinct files within the card's filesystem: A RSA public key file (for modulus N and public exponent e + 5 administrative bytes) and
a RSA private key file (for modulus N and private exponent d + 5 administrative bytes; there is an option to store instead of d the components according to Chinese Remainder Theorem CRT).
Also note the reason, why there is 'Private key usage ACOS' and 'Private key usage PrKDF' and how they are different. The only combinations that make sense, are there:
Private key usage:                           ACOS            PrKDF
Intention: sign (SHA1/SHA256)                sign            sign (,signRecover,nonRepudiation)
Intention: sign (SHA512)                     decrypt,sign    sign (,signRecover,nonRepudiation)
Intention: decrypt,sign (not recommended)    decrypt,sign    decrypt,sign (...)
Intention: decrypt                           decrypt         decrypt (,unwrap)

The primary choice among 3 alternatives is, what to do (choosable within the following radio buttons)
A - Don't change anything stored in the RSA key pair files, thus modifiable is only: "Key pair label", "Key pair id", "authId", within reasonable limits "Private key usage PrKDF" and "Public key usage PuKDF", "Key pair is modifiable?"
B - Do remove a RSA key pair (delete files and adapt EF(PrKDF) and EF(PuKDF).
C - The RSA key pair files do exist already and get reused: Do regenerate the RSA key pair.
D - The RSA key pair files don't exist: Do create new RSA key pair files sized as required and generate the RSA key pair. The file ids are not freely choosable but dictated by the acos5_64.profile file.

Choices C and B allow to change everything (for B there is the limit what fits into the existing files, possibly limiting modulus bits and/or the CRT choice).
Depending on the primary choice, the following table 'RSA key pair generation attributes' will have varying fields blocked as read-only. The table works Excel-like, i.e. recalculating depending fields and status.
In order to keep the code simple, not all 'impossible' options (e.g. from Drop-Down choices selectable) get blocked rigth away, but all entries constantly get checked afterwards whether they are appropriate for the selected primary choice operation, signaling the overall status by color.
E.g. for choice D, a red status may occur, if EF(PrKDF) and/or EF(PuKDF) aren't sized sufficiently to hold new content to be added, or for choice C, if the required storage size of private/public key files is larger then available.

Wrong usage of opensc tools or bug(s) in opensc may lead to 'exploding' EF(PuKDF) file size in that undesirably the modulus gets stored within EF(PuKDF). That may be repaired with the A choice



The files themselves (create/delete) are handled in tab filesystem.

Useful commands for the command line:
$ pkcs15-tool --list-keys

RSA key pair generation can be done in several ways:
(a) By opensc tools (or by PKCS#11 functions C_CreateObject files and C_GenerateKeyPair and update EF(PrKDF) and EF(PuKDF) manually).
    This method lacks full control of acos key pair generation parameters (like CRT style yes/no, sign_only/decrypt_only/sign_and_decrypt.
    The driver handles these possible decisions for this method by hard-coded defaults (CRT yes, sign_and_decrypt).
    pkcs15-init --generate-key rsa/3072 --auth-id 01 --id 46 -vvvv

(b) By this tool with full control of acos key pair generation parameters, and I believe, the algorithm is superior with better user feed back.
    Also, a private key guaranteed to be able to sign or decrypt only, can be generated with method (b) only. This is an additional safety level over declaring in PrKDF/PuKDF only, what the keys are going to be used for: A private key acos-generated e.g. for signing only, can't by design be used for anything else than signing, no matter what PrKDF states (possibly differently; though that should match of course).

The simplest use of this facility is to just replace an existing key pair, i.e. nothing changes from what goes into existing PrKDF/PuKDF entry (also no size-required change), except changing CRT yes/no (as long as it still fits within size limit) and/or changing private/public key usage is allowed:
Enter all 'RSA key pair generation attributes' required (except Key pair label which will not change from existing). They will be checked and used for generation of new key pair in existing files.
There is a checkbox for that intent, but this is not allowed if a certificate refers to this key as the cert would be rendered useless then (thus first delete the cert)

Reminder: The acos command for signing is rather limited in that it does accept only SHA1 and SHA256 hashes. It detects the digest algo from input hash length, generates the digestInfo, ASN.1 encodes and applies the padding selected (PKCS#1 or ISO) and finally signs. Any other hash to be signed (e.g. SHA512 used by Thunderbird) or different padding scheme will rely on driver code which must use acos command 'decrypt' (raw RSA exponentiation) in order to sign. I.e. the key for that must be generated with setting 'private key usage ACOS sign+decrypt !
In order to perform this workaround, the key must be generated as sign+decrypt (dual functionality is not recommended, but there is no way out here). In that case (You want a fully capable key for signing only), don't declare to PrKDF, that the key actually is capable to decrypt as well and opensc will use it for signing only. Merely the driver will switch to try 'decrypt' (there is no way to retrieve whether the key actually is capable of and will allow that) for signing if required, and it will do so in a safe way: Only DigestInfo content for a couple of digest algorithms with valid PKCS#1 padding will be allowed to be signed this way.

The following table works akin Excel does, i.e. deoending on input values, others are calculated based on hidden formulas.
E.g. 'Key pair id' is the input value having the longest chain of recalculation (and also is a special field capable to overwrite other 'input' values: It reads PrKDF and PuKDF for the matching id, resulting in file ids of private and public keys overwritten - and then updating everything depending on that  almost all other fields to 'current' values (all except file id directory and CRT, which is non-retrievable),
The general principle is: The value entered is taken as fixed, all others may change, even if those seem to be (otherwise are) input values only: E.g. Key pair id' also sets RSAModulusBits to the value of the respective key pair referenced, i.e. the order of inputs is significant !
This page assumes, that the directory for the new/existing RSA key pair does exist already, otherwise first create it in tab 'filesystem'

Note on using the RSA keys for signing:
The driver won't sign everything, but only what is valid according to RSASSA-PKCS1-v1_5, where digestAlgorithm may be SHA1 or SHA256.
As the padding will be done by the tools like pkcs11-tool, the following command will work (pin is 12345678 ascii here, the key with id 04 used):
cat data | pkcs11-tool --id 04 -s -p 12345678 -m RSA-PKCS --module /usr/lib/opensc-pkcs11.so > data.sig
if the data file contains exactly:
30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14               + 20 arbitrary bytes  or
30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20   + 32 arbitrary bytes

which is the ASN.1 DER-encoding of
      DigestInfo ::= SEQUENCE {
          digestAlgorithm DigestAlgorithm,
          digest OCTET STRING
      }

If the key to be used for signing was generated using 'Private key usage ACOS'='decrypt, sign', a lot more digestAlgorithm are allowed, and data like this is allowed:
30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40   + 64 arbitrary bytes
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
//    AA["tabCtrl"].SetInteger("VALUEPOS", 1); // why does this (setting the tab od) crash?
    GC.collect();
    /* start event loop */
    IupMainLoop();

    IupClose();
    return EXIT_SUCCESS;
}
