/*
 * key_asym.d: Program acos5_64_gui's 'RSA key pair handling' file
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
privateV3:
3033300F0C064341726F6F74030206C0040101300E0401010303062040010101020101A110300E300804063F00410041F102020C00 303430100C074341696E746572030206C0040101300E0401020303062040010101020102A110300E300804063F00410041F202020D00
3033300F0C064341726F6F74030206C0040101300E04010103030620400101FF020101A110300E300804063F00410041F102020C00

3034300F0C064341726F6F74030206C0040101300F0401010303062040030203B8020101A110300E300804063F00410041F102021000 303530100C074341696E746572030206C0040101300F0401020303062040030203B8020102A110300E300804063F00410041F202021000303930140C0B446563727970745369676E030206C0040101300F0401030303062040030203B8020103A110300E300804063F00410041F3020210003034300F0C0662616C6F6F6E030206C0040101300F0401040303062000030203B8020104A110300E300804063F00410041F402020C00
public V3:
3030300C0C064341726F6F7403020640300E0401010303060200010101020101A110300E300804063F004100413102020C003031300D0C074341696E74657203020640300E0401020303060200010101020102A110300E300804063F004100413202020D00

I think of a working PKCS#11 application as of a quite complex machinery:
This is the call stack:

PKCS#11 application like acos5_64_gui, calls
    function in opensc-pkcs11.so
          function in libopensc.so
              function in libacos4_64.so, the driver and SM module
                  function in libopensc.so and/or
                  libopensc.so or libacos4_64.so issues a byte sequence which is a valid ACS acos5 operating system command
                      the acos5 command operates on a card/token file's data or
                                        sets acos5 internal state like pointer to currently selected file or pin/key verified/authenticated state etc. or
                                        performs cryptographic operations like sign, decrypt, keypairgen, encrypt hash, mac etc.

The point of failure may (as always) be bugs in the software of course, but in the beginning of using a card, its more likely, that the reason for a failure is
from data on the card/token, which is not as expected by opensc/driver or not conformant to PKCS#15 / ISO/IEC 7816-15 !
Drivers expectations not fulfilled/met very likely will end in an Assertion failure in debug build, which is a way to deliberately terminate a process in those circumstances.

In the extreme case, a single bit set wrongly on card may prevent the sotware from working at all or the card being inaccessible or unmodifiable forever.
Or bits set wrongly may render the card insecure.

In order to help with that, the driver is able to perform extensive and sophisticated sanity checks and log the results to opensc-debug.log: accessible via function sc_pkcs15init_sanity_check

UNKNOWN/INFO: The op mode byte setting. If it is an ACOS5-64 V3 card/token (whether in FIPS mode or not), additional checks will be applied and discrepancy to FIPS requirements stated
PASS: MF, the root directory, does exist, otherwise the card header block will be read and logged, then terminate sanity_check
PASS FIPS: MF is activated (LifeCycleStatusInteger==5==user mode)
FAIL FIPS: MF has no SecurityAttributeExpanded SAE as required by FIPS, or it's content deviates from requirements
PASS: MF header has an associated SecurityEnvironmentFile (0003) declared and that does exist

00a40000024100
00c0000032
00200081083132333435363738
002201 B60A80011081024134950180
002201 B60A800110810241F4950140
00460000021804
*/

module key_asym;

import core.memory : GC;
import core.stdc.stdlib : exit;
import std.stdio;
import std.exception : assumeWontThrow, assumeUnique;
import std.conv: to, hexString;
import std.format;
import std.range : iota, chunks, indexed;
import std.range.primitives : empty, front;//, back;
import std.array : array;
import std.algorithm.comparison : among, clamp, equal, min, max;
import std.algorithm.searching : canFind, countUntil, all, any, find;
import std.algorithm.mutation : remove;
//import std.algorithm.iteration : uniq;
//import std.algorithm.sorting : sort;
//import std.typecons : Tuple, tuple;
import std.string : /*chomp, */  toStringz, fromStringz, representation;
import std.signals;

import libopensc.opensc;
import libopensc.types;
import libopensc.errors;
import libopensc.log;
import libopensc.iso7816;

import pkcs15init.profile : sc_profile;
import libopensc.pkcs15 : sc_pkcs15_card, sc_pkcs15_bind, sc_pkcs15_unbind, sc_pkcs15_auth_info;
import pkcs15init.pkcs15init : sc_pkcs15init_bind, sc_pkcs15init_unbind, sc_pkcs15init_set_callbacks, sc_pkcs15init_delete_by_path,
    sc_pkcs15init_callbacks, sc_pkcs15init_set_callbacks, sc_pkcs15init_authenticate;

import iup.iup_plusD;

import libintl : _, __;

import util_general;// : ub22integral;
import acos5_64_shared;
import pub;

import util_opensc : connect_card, readFile/*, decompose*/, PKCS15Path_FileType, pkcs15_names,
    PKCS15_FILE_TYPE, fs, PRKDF, PUKDF, AODF, SKDF,
    PKCS15_ObjectTyp, errorDescription, PKCS15, appdf, tnTypePtr,
    aid, is_ACOSV3_opmodeV3_FIPS_140_2L3, is_ACOSV3_opmodeV3_FIPS_140_2L3_active,
    my_pkcs15init_callbacks, tlv_Range_mod, file_type, getIdentifier;

import acos5_64_shared_rust : CardCtl_generate_crypt_asym, SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES_EXIST, SC_CARDCTL_ACOS5_ENCRYPT_ASYM;
//SC_CARDCTL_ACOS5_GET_COUNT_FILES_CURR_DF, SC_CARDCTL_ACOS5_GET_FILE_INFO, CardCtlArray8, CardCtlArray32;

//import asn1_pkcs15 : CIO_RSA_private, CIO_RSA_public, CIO_Auth_Pin, encodeEntry_PKCS15_PRKDF, encodeEntry_PKCS15_PUKDF;
import wrapper.libtasn1;
import pkcs11;

private import key_sym : nextUniqueKeyId;

// tag types
//PubA16
struct _valuePublicExponent{}   // publicExponentRSA
//Obs
struct _keyAsym_usagePuKDF{}
struct _sizeNewRSAprivateFile{}
struct _sizeNewRSApublicFile{}

//ubyte[9] pinbuf;

tnTypePtr   prkdf;
tnTypePtr   pukdf;

int  nextUniqueId; //= nextUniqueKeyId();
int  nextUniquePairNo;


enum /* matrixKeyAsymRowName */
{
    r_keyAsym_Id = 1,             // dropdown
    r_keyAsym_Label,
    r_keyAsym_Modifiable,         // toggle
    r_keyAsym_usagePrKDF,
//  r_keyAsym_usagePuKDF,         // hidden
    r_keyAsym_authId,             // readonly

    r_keyAsym_RSAmodulusLenBits,  // dropdown
    r_valuePublicExponent,

    r_acos_internal,              // readonly
    r_keyAsym_crtModeGenerate,    // toggle
    r_keyAsym_usageGenerate,

    r_fidRSAprivate,              // readonly
    r_fidRSApublic,               // readonly
    r_keyAsym_fidAppDir,          // readonly

    r_change_calcPrKDF,           // readonly
    r_change_calcPuKDF,           // readonly

    r_sizeNewRSAprivateFile,      // readonly
    r_sizeNewRSApublicFile,       // readonly

    r_statusInput,                // readonly

    r_AC_Update_PrKDF_PuKDF,            // readonly
    r_AC_Update_Delete_RSAprivateFile,  // readonly
    r_AC_Update_Delete_RSApublicFile,   // readonly
    r_AC_Create_Delete_RSADir,          // readonly
    r_AC_Crypto_RSAprivateFile_RSApublicFile,  // readonly
}


/* keyAsym_RSAmodulusLenBits : from 512 to 4096, step 256, except for FIPS: 2048 and 3072 only (not yet enforced !)
Modifying keyAsym_RSAmodulusLenBits depends on radioKeyAsym, comprising:
 */
Pub!_keyAsym_RSAmodulusLenBits  keyAsym_RSAmodulusLenBits;
Pub!_keyAsym_crtModeGenerate    keyAsym_crtModeGenerate;
Pub!_keyAsym_usageGenerate      keyAsym_usageGenerate;  // interrelates with keyAsym_usagePrKDF
Pub!_keyAsym_usagePrKDF         keyAsym_usagePrKDF;   // interrelates with keyAsym_usageGenerate
Obs_usagePuKDF                  keyAsym_usagePuKDF;

Pub!_keyAsym_Id                 keyAsym_Id;
Pub!_keyAsym_Modifiable         keyAsym_Modifiable;
Pub!_keyAsym_fidAppDir          keyAsym_fidAppDir;
PubA2!_fidRSAprivate            fidRSAprivate;
PubA2!_fidRSApublic             fidRSApublic;


Obs_sizeNewRSAprivateFile       sizeNewRSAprivateFile;
Obs_sizeNewRSApublicFile        sizeNewRSApublicFile;

Obs_change_calcPrKDF            change_calcPrKDF;
Obs_change_calcPuKDF            change_calcPuKDF;

PubA16!_valuePublicExponent     valuePublicExponent;

Pub!(_keyAsym_Label,string)     keyAsym_Label;
Pub!_keyAsym_authId             keyAsym_authId;

Obs_statusInput                 statusInput;

Pub!(_AC_Update_PrKDF_PuKDF,          ubyte[2])  AC_Update_PrKDF_PuKDF;
//Pub!(_AC_Update_Delete_RSAprivateFile,ubyte[2])  AC_Update_Delete_RSAprivateFile;
//Pub!(_AC_Update_Delete_RSApublicFile, ubyte[2])  AC_Update_Delete_RSApublicFile;
Pub!(_AC_Create_Delete_RSADir,        ubyte[2])  AC_Create_Delete_RSADir;

void keyAsym_initialize_PubObs()
{
    /* initialze the publisher/observer system for GenerateKeyPair_RSA_tab */
    // some variables are declared as publisher though they don't need to be, currently just for consistency, but that's not the most efficient way
    keyAsym_Label             = new Pub!(_keyAsym_Label,string)   (r_keyAsym_Label,             AA["matrixKeyAsym"]);
    keyAsym_RSAmodulusLenBits = new Pub!_keyAsym_RSAmodulusLenBits(r_keyAsym_RSAmodulusLenBits, AA["matrixKeyAsym"]);
    keyAsym_crtModeGenerate   = new Pub!_keyAsym_crtModeGenerate  (r_keyAsym_crtModeGenerate,   AA["matrixKeyAsym"]);
    keyAsym_usageGenerate     = new Pub!_keyAsym_usageGenerate    (r_keyAsym_usageGenerate,     AA["matrixKeyAsym"]);
    keyAsym_usagePrKDF        = new Pub!_keyAsym_usagePrKDF       (r_keyAsym_usagePrKDF,        AA["matrixKeyAsym"]);
    keyAsym_Modifiable        = new Pub!_keyAsym_Modifiable       (r_keyAsym_Modifiable,        AA["matrixKeyAsym"]);
    keyAsym_authId            = new Pub!_keyAsym_authId           (r_keyAsym_authId,            AA["matrixKeyAsym"], true);
    keyAsym_Id                = new Pub!_keyAsym_Id               (r_keyAsym_Id,                AA["matrixKeyAsym"], true);
    keyAsym_fidAppDir         = new Pub!_keyAsym_fidAppDir        (r_keyAsym_fidAppDir,         AA["matrixKeyAsym"], true);
    fidRSAprivate             = new PubA2!_fidRSAprivate          (r_fidRSAprivate,             AA["matrixKeyAsym"]);
    fidRSApublic              = new PubA2!_fidRSApublic           (r_fidRSApublic,              AA["matrixKeyAsym"]);
    valuePublicExponent       = new PubA16!_valuePublicExponent   (r_valuePublicExponent,       AA["matrixKeyAsym"]);
    AC_Update_PrKDF_PuKDF           = new Pub!(_AC_Update_PrKDF_PuKDF,          ubyte[2]) (r_AC_Update_PrKDF_PuKDF,           AA["matrixKeyAsym"]);
//  AC_Update_Delete_RSAprivateFile = new Pub!(_AC_Update_Delete_RSAprivateFile,ubyte[2]) (r_AC_Update_Delete_RSAprivateFile, AA["matrixKeyAsym"]);
//  AC_Update_Delete_RSApublicFile  = new Pub!(_AC_Update_Delete_RSApublicFile, ubyte[2]) (r_AC_Update_Delete_RSApublicFile,  AA["matrixKeyAsym"]);
    AC_Create_Delete_RSADir         = new Pub!(_AC_Create_Delete_RSADir,        ubyte[2]) (r_AC_Create_Delete_RSADir,         AA["matrixKeyAsym"]);

    keyAsym_usagePuKDF      = new Obs_usagePuKDF  (0/*r_keyAsym_usagePuKDF,  AA["matrixKeyAsym"]*/); // visual representation removed
    sizeNewRSAprivateFile   = new Obs_sizeNewRSAprivateFile       (r_sizeNewRSAprivateFile,     AA["matrixKeyAsym"]);
    sizeNewRSApublicFile    = new Obs_sizeNewRSApublicFile        (r_sizeNewRSApublicFile,      AA["matrixKeyAsym"]);
    statusInput             = new Obs_statusInput                 (r_statusInput,               AA["matrixKeyAsym"]);
    change_calcPrKDF        = new Obs_change_calcPrKDF            (r_change_calcPrKDF,          AA["matrixKeyAsym"]);
    change_calcPuKDF        = new Obs_change_calcPuKDF            (r_change_calcPuKDF,          AA["matrixKeyAsym"]);
//// dependencies
    fidRSAprivate            .connect(&sizeNewRSAprivateFile.watch); // just for show (sizeCurrentRSAprivateFile) reason
    keyAsym_RSAmodulusLenBits.connect(&sizeNewRSAprivateFile.watch);
    keyAsym_crtModeGenerate  .connect(&sizeNewRSAprivateFile.watch);

    fidRSApublic             .connect(&sizeNewRSApublicFile.watch);  // just for show (sizeCurrentRSApublicFile) reason
    keyAsym_RSAmodulusLenBits.connect(&sizeNewRSApublicFile.watch);

    keyAsym_usagePrKDF.connect(&keyAsym_usagePuKDF.watch);
    // keyAsym_Id must be connected first to change_calcPrKDF, and only then to change_calcPuKDF
    keyAsym_Id               .connect(&change_calcPrKDF.watch); // THIS MUST BE the first entry for change_calcPrKDF ! If no keyAsym_Id is selected, this MUST be the only one accessible
    keyAsym_Label            .connect(&change_calcPrKDF.watch);
    keyAsym_authId           .connect(&change_calcPrKDF.watch);
    keyAsym_Modifiable       .connect(&change_calcPrKDF.watch);
    keyAsym_RSAmodulusLenBits.connect(&change_calcPrKDF.watch);
    keyAsym_usagePrKDF       .connect(&change_calcPrKDF.watch);
//  fidRSAprivate            .connect(&change_calcPrKDF.watch);

    keyAsym_Id               .connect(&change_calcPuKDF.watch); // THIS MUST BE the first entry for change_calcPuKDF ! If no keyAsym_Id is selected, this MUST be the only one accessible
    keyAsym_Label            .connect(&change_calcPuKDF.watch);
//  authIdRSApublicFile      .connect(&change_calcPuKDF.watch);
    keyAsym_Modifiable       .connect(&change_calcPuKDF.watch);
    keyAsym_RSAmodulusLenBits.connect(&change_calcPuKDF.watch);
    keyAsym_usagePuKDF       .connect(&change_calcPuKDF.watch);
//  fidRSApublic             .connect(&change_calcPuKDF.watch);

    keyAsym_fidAppDir    .connect(&statusInput.watch);
    fidRSAprivate        .connect(&statusInput.watch);
    fidRSApublic         .connect(&statusInput.watch);
    valuePublicExponent  .connect(&statusInput.watch);
    keyAsym_usagePrKDF   .connect(&statusInput.watch);
    keyAsym_usageGenerate.connect(&statusInput.watch);
    sizeNewRSAprivateFile.connect(&statusInput.watch);
    sizeNewRSApublicFile .connect(&statusInput.watch);

//// values to start with
    keyAsym_fidAppDir      .set(appdf is null? 0 : ub22integral(appdf.data[2..4]), true);
    keyAsym_crtModeGenerate.set(true, true);
    keyAsym_usageGenerate  .set(4,   true); // this is only for acos-generation; no variable depends on this
    AC_Update_PrKDF_PuKDF  .set([prkdf is null? 0xFF : prkdf.data[25], pukdf is null? 0xFF : pukdf.data[25]], true); // no variable depends on this
    AC_Create_Delete_RSADir.set([appdf is null? 0xFF : appdf.data[25], appdf is null? 0xFF : appdf.data[24]], true); // no variable depends on this

    toggle_radioKeyAsym_cb(AA["toggle_RSA_PrKDF_PuKDF_change"].GetHandle, 1); // was set to active already
//    AA["radioKeyAsym"].SetAttribute("VALUE_HANDLE", "toggle_RSA_PrKDF_PuKDF_change"); // doesn't work: "Changes the active toggle"
//    AA["toggle_RSA_PrKDF_PuKDF_change"].SetIntegerVALUE(1); // Doesn't invoke toggle_radioKeyAsym_cb
}


class PubA16(T, V=ubyte)
{
    mixin(commonConstructor);

    @property V[16] set(V[16] v, bool programmatically=false)  nothrow
    {
//    void set(V v, int pos /*position in V[8], 0-basiert*/, bool programmatically=false)  nothrow {
        import deimos.openssl.ossl_typ : BIGNUM, BN_CTX;
        import deimos.openssl.bn : BN_prime_checks, BN_CTX_new, BN_is_prime_ex, BN_bin2bn, BN_free, BN_CTX_free;
        try
        if (v != _value)
        {
            BN_CTX* ctx = BN_CTX_new();
            BIGNUM* p  = BN_bin2bn(v.ptr, v.length, null);
            scope(exit)
            {
                BN_free(p);
                BN_CTX_free(ctx);
            }
            _value = BN_is_prime_ex(p, BN_prime_checks, ctx, /*BN_GENCB* cb*/ null)? v : typeof(v).init;
            if (programmatically &&  _h !is null)
            {
                // trim leading zero bytes
                ptrdiff_t  pos = clamp(_value[].countUntil!"a>0", -1,15);
                _h.SetStringId2 ("", _lin, _col, format!"%(%02X%)"(pos==-1? [ubyte(0)] : _value[pos..$]));
            }
////assumeWontThrow(writefln(T.stringof~" object (was set to) values %(%02X %)", _value));
            emit(T.stringof, _value);
        }
        catch (Exception e) { printf("### Exception in PubA16.set()\n"); /* todo: handle exception */ }
        return _value;
    }

    mixin Pub_boilerplate!(T,V[16]);
}
/+
class PubA256(T, V=ubyte)
{
    this(int lin/*, int col*/, Handle control = null/*, bool hexRep = false*/) {
        _lin = lin;
        _col = 1;
        _h   = control;
        _hexRep = true;//hexRep;
//        if (_h !is null)
//            _h.SetAttributeStr(T.stringof, cast(char*)this);
    }

    mixin Pub_boilerplate!(T,V[256]);
    private :
    int      len; // used
}
+/

class Obs_usagePuKDF
{
    mixin(commonConstructor);

    void watch(string msg, int v)
    {
        switch(msg)
        {
            case "_keyAsym_usagePrKDF":
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        _value =  209;
        if ((v&4)==0) // if non-sign, then remove verify
            _value &= ~64;
        if ((v&8)==0) // if non-signRecover, then remove verifyRecover
            _value &= ~128;
        // if non-decrypt, then remove encrypt, if non-unwrap, then remove wrap
        if ((v&2)==0) // if non-decrypt, then remove encrypt
            _value &= ~1;
        if ((v&32)==0) // if non-unwrap, then remove wrap
            _value &= ~16;

////assumeWontThrow(writefln(typeof(this).stringof~" object was set to value %s", _value));
        emit("_keyAsym_usagePuKDF", _value);

        if (_h !is null)
        {
            _h.SetStringId2 ("", _lin, _col, keyUsageFlagsInt2string(_value));
            _h.Update;
        }
    }

    mixin Pub_boilerplate!(_keyAsym_usagePuKDF, int);
}

class Obs_sizeNewRSAprivateFile
{
    mixin(commonConstructor);

    void watch(string msg, int[2] v)
    {
        switch(msg)
        {
            case "_fidRSAprivate":
                _fidRSAprivate     = v[0];
                _fidSizeRSAprivate = v[1];
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        present();
    }

    void watch(string msg, int v)
    {
        switch(msg)
        {
            case "_keyAsym_RSAmodulusLenBits":
                _keyAsym_RSAmodulusLenBits = v;
                break;
            case "_keyAsym_crtModeGenerate":
                _keyAsym_crtModeGenerate = v;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        _value =  _keyAsym_RSAmodulusLenBits<=0? 0 : 5 + _keyAsym_RSAmodulusLenBits/16*(_keyAsym_crtModeGenerate ? 5 : 2);
        present();
    }

    void present()
    {
////assumeWontThrow(writefln(typeof(this).stringof~" object was set to _fidRSAprivate(%04X), _fidSizeRSAprivate(%s), _value(%s)", _fidRSAprivate, _fidSizeRSAprivate, _value));
        emit("_sizeNewRSAprivateFile", _value);

        if (_h !is null)
        {
            _h.SetStringId2 ("", _lin, _col, _value.to!string ~" / "~ _fidSizeRSAprivate.to!string);
            _h.Update;
        }
    }

    mixin Pub_boilerplate!(_sizeNewRSAprivateFile, int);

    private :
        int  _fidRSAprivate;
        int  _fidSizeRSAprivate;
        int  _keyAsym_RSAmodulusLenBits;
        int  _keyAsym_crtModeGenerate;
//      int  _value; // size of RSAprivate file required for the _keyAsym_RSAmodulusLenBits and _keyAsym_crtModeGenerate settings
} // class Obs_sizeNewRSAprivateFile

class Obs_sizeNewRSApublicFile
{
    mixin(commonConstructor);

    void watch(string msg, int[2] v)
    {
        switch(msg)
        {
            case "_fidRSApublic":
                _fidRSApublic     = v[0];
                _fidSizeRSApublic = v[1];
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        present();
    }

    void watch(string msg, int v)
    {
        switch(msg)
        {
            case "_keyAsym_RSAmodulusLenBits":
//                _keyAsym_RSAmodulusLenBits = v;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        _value =  v<=0? 0 : 21 + v/8;
        present();
    }

    void present()
    {
////assumeWontThrow(writefln(typeof(this).stringof~" object was set to _fidRSApublic(%04X), _fidSizeRSApublic(%s), _value(%s)", _fidRSApublic, _fidSizeRSApublic, _value));
        emit("_sizeNewRSApublicFile", _value);

        if (_h !is null)
        {
            _h.SetStringId2 ("", _lin, _col, _value.to!string ~" / "~ _fidSizeRSApublic.to!string);
            _h.Update;
        }
    }

    mixin Pub_boilerplate!(_sizeNewRSApublicFile, int);

    private :
        int  _fidRSApublic;
        int  _fidSizeRSApublic;
//      int   _value; // size of RSApublic file required for the _keyAsym_RSAmodulusLenBits setting
} // class Obs_sizeNewRSApublicFile


class Obs_change_calcPrKDF
{
    mixin(commonConstructor);

    @property ref PKCS15_ObjectTyp  pkcs15_ObjectTyp() @nogc nothrow /*pure*/ @safe { return _PrKDFentry; }
    @property     const(int)        get()        const @nogc nothrow /*pure*/ @safe { return _value; }

    void watch(string msg, int v)
    {
        import core.bitop : bitswap;
        int asn1_result;
        int outLen;
        switch (msg)
        {
            case "_keyAsym_Id":
                {
                    if (_PrKDFentry.structure_new !is null)
                        asn1_delete_structure(&_PrKDFentry.structure_new);
                    if (isNewKeyPairId)
                    {
                        _PrKDFentry = PKCS15_ObjectTyp.init;
                        nextUniquePairNo = nextUniqueRSAKeyPairNo();
                        assert(nextUniquePairNo>0);
                        /*
                        authId must be adapted
                        */

//30 2C 30 0A 0C 01 3F 03 02 06   C0 04 01 00 30 0C 04 01 FF 03   03 06 20 00 03 02 03 B8   A1 10 30 0E 30 08 04 06 3F 00 41 00 41 F7 02 02 10 00
                        _PrKDFentry.der = (cast(immutable(ubyte)[])hexString!"30 2C 30 0A 0C 01 3F 03 02 06   C0 04 01 00 30 0C 04 01 FF 03   03 06 20 00 03 02 03 B8   A1 10 30 0E 30 08 04 06 3F 00 41 00 41 F7 02 02 10 00").dup;
                        // all settings are preselected (except for keyAsym_authId) and must be set afterwards
                        _PrKDFentry.der[13] = cast(ubyte)keyAsym_authId.get; // FIXME
                        _PrKDFentry.der[18] = cast(ubyte)nextUniqueId;
//                        _PrKDFentry.der[30] = cast(ubyte)v;
                         /* CONVENTION, profile */
                        _PrKDFentry.der[41] = 0xF0 | cast(ubyte)nextUniquePairNo;
                        asn1_result = asn1_create_element(PKCS15, pkcs15_names[PKCS15_FILE_TYPE.PKCS15_PRKDF][1], &_PrKDFentry.structure); // "PKCS15.PrivateKeyType"
                        if (asn1_result != ASN1_SUCCESS)
                        {
                            assumeWontThrow(writeln("### Structure creation: ", asn1_strerror2(asn1_result)));
                            exit(1);
                        }
                        asn1_result = asn1_der_decoding(&_PrKDFentry.structure, _PrKDFentry.der, errorDescription);
                        if (asn1_result != ASN1_SUCCESS)
                        {
                            assumeWontThrow(writeln("### asn1Decoding: ", errorDescription));
                            exit(1);
                        }
                        ubyte[16]  str; // verify, that a value for "privateRSAKey.privateRSAKeyAttributes.value.indirect.path.path" does exist for this keyAsym_Id
                        if ((asn1_result= asn1_read_value(_PrKDFentry.structure, pkcs15_names[PKCS15_FILE_TYPE.PKCS15_RSAPrivateKey][2], str, outLen)) != ASN1_SUCCESS)
                        {
                            assumeWontThrow(writefln("### asn1_read_value: %(%02X %)", _PrKDFentry.der));
                            exit(1);
                        }
                        assert(v == getIdentifier(_PrKDFentry, "privateRSAKey.commonKeyAttributes.iD"));
                    }
                    else
                    {
                        auto haystackPriv= find!((a,b) => b == getIdentifier(a, "privateRSAKey.commonKeyAttributes.iD"))(PRKDF, v);
                        assert(!haystackPriv.empty);
                        _PrKDFentry = haystackPriv.front;
                        /* never touch/change structure or der (only structure_new and der_new), except when updating to file ! */
                    }
                    assert(_PrKDFentry.structure_new is null); // newer get's set in PRKDF
                    assert(_PrKDFentry.der_new is null);       // newer get's set in PRKDF
                    _PrKDFentry.structure_new = asn1_dup_node(_PrKDFentry.structure, "");

////                    assumeWontThrow(writefln("_old_encodedData of PrKDFentry: %(%02X %)", _PrKDFentry.der));
                }
                break;

            case "_keyAsym_authId":
                ubyte[1] authId = cast(ubyte)v; // optional
/*
                // remove, if authId==0, write if authId!=0
                if (authId==0)
                    asn1_write_value(_PrKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.authId".ptr, null, 0);
                else
*/
                asn1_write_value(_PrKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.authId", authId.ptr, 1);

                ubyte[1] flags; // optional
                asn1_result = asn1_read_value(_PrKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.flags", flags, outLen);
                if (asn1_result != ASN1_SUCCESS)
                {
                    assumeWontThrow(writeln("### asn1_read_value privateRSAKey.commonObjectAttributes.flags: ", asn1_strerror2(asn1_result)));
                    break;
                }
                assert(outLen==2); // bits
                flags[0] = util_general.bitswap(flags[0]);

                ubyte[1] tmp = util_general.bitswap( cast(ubyte) ((flags[0]&0xFE) | (v!=0)) );
                asn1_write_value(_PrKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.flags", tmp.ptr, 2); // 2 bits
                break;

            case "_keyAsym_Modifiable":
                ubyte[1] flags; // optional
                asn1_result = asn1_read_value(_PrKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.flags", flags, outLen);
                if (asn1_result != ASN1_SUCCESS)
                {
                    assumeWontThrow(writeln("### asn1_read_value privateRSAKey.commonObjectAttributes.flags: ", asn1_strerror2(asn1_result)));
                    break;
                }
//                assert(outLen==2); // bits
                flags[0] = util_general.bitswap(flags[0]);

                ubyte[1] tmp = util_general.bitswap( cast(ubyte) ((flags[0]&0xFD) | (v!=0)*2) );
                asn1_write_value(_PrKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.flags", tmp.ptr, 2); // 2 bits
                break;

            case "_keyAsym_RSAmodulusLenBits":
                ubyte[] tmp = integral2uba!2(v);
                asn1_write_value(_PrKDFentry.structure_new, "privateRSAKey.privateRSAKeyAttributes.modulusLength", tmp.ptr, cast(int)tmp.length);
                break;

            case "_keyAsym_usagePrKDF":
                ubyte[] tmp = integral2uba!4(bitswap(v));
                asn1_write_value(_PrKDFentry.structure_new, "privateRSAKey.commonKeyAttributes.usage", tmp.ptr, 10); // 10 bits
                break;

            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        present();
    }

    void watch(string msg, string v)
    {
        int asn1_result;
        switch (msg)
        {
            case "_keyAsym_Label":
                char[] label = v.dup ~ '\0';
//                GC.addRoot(cast(void*)label.ptr);
//                GC.setAttr(cast(void*)label.ptr, GC.BlkAttr.NO_MOVE);
                asn1_result = asn1_write_value(_PrKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.label", label.ptr, 0);
                if (asn1_result != ASN1_SUCCESS)
                    assumeWontThrow(writeln("### asn1_write_value privateRSAKey.commonObjectAttributes.label: ", asn1_strerror2(asn1_result)));
                break;

            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        GC.collect();
        present();
    }

    void present()
    {
//        assert(_PrKDFentry.posEnd); // it has been set
        _PrKDFentry.der_new = new ubyte[_PrKDFentry.der.length+32];
        int outDerLen;
        immutable asn1_result = asn1_der_coding(_PrKDFentry.structure_new, "", _PrKDFentry.der_new, outDerLen, errorDescription);
        if (asn1_result != ASN1_SUCCESS)
        {
            printf ("\n### _PrKDFentry.der_new encoding creation: ERROR  with Obs_change_calcPrKDF\n");
//                    assumeWontThrow(writeln("### asn1Coding: ", errorDescription));
            return;
        }
        if (outDerLen)
            _PrKDFentry.der_new.length = outDerLen;
        _value = cast(int)(_PrKDFentry.der_new.length - _PrKDFentry.der.length);
////assumeWontThrow(writefln(typeof(this).stringof~" object was set"));
////assumeWontThrow(writefln("_new_encodedData of PrKDFentry: %(%02X %)", _PrKDFentry.der_new));
//        emit("_change_calcPrKDF", _value);
        if (_h !is null)
        {
            _h.SetIntegerId2/*SetStringId2*/ ("", _lin, _col, _value/*.to!string*/); //  ~" / "~ _value.to!string
            _h.Update;
        }
    }

//    mixin Signal!(string, int);

    private :
        int               _value;
        PKCS15_ObjectTyp  _PrKDFentry;

        int    _lin;
        int    _col;
        Handle _h;
}

class Obs_change_calcPuKDF
{
    mixin(commonConstructor);

//    @property const(ubyte[]) old_encodedData() const @nogc nothrow /*pure*/ @safe { return _PuKDFentry.der; }
//    @property const(ubyte[]) new_encodedData() const @nogc nothrow /*pure*/ @safe { return _PuKDFentry.der_new; }
    @property ref PKCS15_ObjectTyp  pkcs15_ObjectTyp() @nogc nothrow /*pure*/ @safe { return _PuKDFentry; }
    @property     const(int)        get()        const @nogc nothrow /*pure*/ @safe { return _value; }

    void watch(string msg, int v)
    {
        import core.bitop : bitswap;
        int asn1_result;
        int outLen;
        switch (msg)
        {
            case "_keyAsym_Id":
                {
                    if (_PuKDFentry.structure_new !is null)
                        asn1_delete_structure(&_PuKDFentry.structure_new);
                    if (isNewKeyPairId)
                    {
                        _PuKDFentry = PKCS15_ObjectTyp.init;
//30 29 30 07 0C 01 3F 03 02 06 40   30 0C 04 01 FF 03   03 06 02 00 03 02 03 48   A1 10 30 0E 30 08 04 06 3F 00 41 00 41 FF 02 02 10 00
                        _PuKDFentry.der = (cast(immutable(ubyte)[])hexString!"30 29 30 07 0C 01 3F 03 02 06 40   30 0C 04 01 FF 03   03 06 02 00 03 02 03 48   A1 10 30 0E 30 08 04 06 3F 00 41 00 41 FF 02 02 10 00").dup;
                        _PuKDFentry.der[15] = cast(ubyte)nextUniqueId;
//                        _PuKDFentry.der[27] = cast(ubyte)v;
                        _PuKDFentry.der[38] = 0x30 | cast(ubyte)nextUniquePairNo;
                        asn1_result = asn1_create_element(PKCS15, pkcs15_names[PKCS15_FILE_TYPE.PKCS15_PUKDF][1], &_PuKDFentry.structure); // "PKCS15.PublicKeyType"
                        if (asn1_result != ASN1_SUCCESS)
                        {
                            assumeWontThrow(writeln("### Structure creation: ", asn1_strerror2(asn1_result)));
                            exit(1);
                        }
                        asn1_result = asn1_der_decoding(&_PuKDFentry.structure, _PuKDFentry.der, errorDescription);
                        if (asn1_result != ASN1_SUCCESS)
                        {
                            assumeWontThrow(writeln("### asn1Decoding: ", errorDescription));
                            exit(1);
                        }
                        ubyte[16]  str; // verify, that a value for "publicRSAKey.publicRSAKeyAttributes.value.indirect.path.path" does exist for this keyAsym_Id
                        if ((asn1_result= asn1_read_value(_PuKDFentry.structure, pkcs15_names[PKCS15_FILE_TYPE.PKCS15_RSAPublicKey][2], str, outLen)) != ASN1_SUCCESS)
                        {
                            assumeWontThrow(writefln("### asn1_read_value: %(%02X %)", _PuKDFentry.der));
                            exit(1);
                        }
                        assert(v == getIdentifier(_PuKDFentry, "publicRSAKey.commonKeyAttributes.iD"));
                    }
                    else
                    {
                        auto haystackPubl= find!((a,b) => b == getIdentifier(a, "publicRSAKey.commonKeyAttributes.iD"))(PUKDF, v);
                        assert(!haystackPubl.empty);
                        _PuKDFentry = haystackPubl.front;
                    }
                    assert(_PuKDFentry.structure_new is null); // newer get's set in PUKDF
                    assert(_PuKDFentry.der_new is null);       // newer get's set in PUKDF
                    _PuKDFentry.structure_new = asn1_dup_node(_PuKDFentry.structure, "");

////                    assumeWontThrow(writefln("_old_encodedData of PuKDFentry: %(%02X %)", _PuKDFentry.der));
/+
                    // CONVENTION: public key is expected to be non-private
                    _PuKDFentry.commonObjectAttributes.flags = _PuKDFentry.commonObjectAttributes.flags&~1;
+/
                }
                break;

            case "_keyAsym_Modifiable":
                ubyte[1] flags; // optional
                asn1_result = asn1_read_value(_PuKDFentry.structure_new, "publicRSAKey.commonObjectAttributes.flags", flags, outLen);
                if (asn1_result != ASN1_SUCCESS)
                {
                    assumeWontThrow(writeln("### asn1_read_value publicRSAKey.commonObjectAttributes.flags: ", asn1_strerror2(asn1_result)));
                    break;
                }
                assert(outLen==2); // bits
                flags[0] = util_general.bitswap(flags[0]);

////                _PuKDFentry.commonObjectAttributes.flags = (_PuKDFentry.commonObjectAttributes.flags&~2) | (v!=0)*2;
                ubyte[1] tmp = util_general.bitswap( cast(ubyte) ((flags[0]&0xFD) | (v!=0)*2) );
                asn1_write_value(_PuKDFentry.structure_new, "publicRSAKey.commonObjectAttributes.flags", tmp.ptr, 2); // 2 bits
                break;

            case "_keyAsym_RSAmodulusLenBits":
                ubyte[] tmp = integral2uba!2(v);
                asn1_write_value(_PuKDFentry.structure_new, "publicRSAKey.publicRSAKeyAttributes.modulusLength", tmp.ptr, cast(int)tmp.length);
                break;

            case "_keyAsym_usagePuKDF":
                ubyte[] tmp = integral2uba!4(bitswap(v));
                asn1_write_value(_PuKDFentry.structure_new, "publicRSAKey.commonKeyAttributes.usage", tmp.ptr, 10); // 10 bits
                break;

            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        present();
    }

    void watch(string msg, string v)
    {
        int asn1_result;
        switch (msg)
        {
            case "_keyAsym_Label":
                char[] label = v.dup ~ '\0';
                GC.addRoot(cast(void*)label.ptr);
                GC.setAttr(cast(void*)label.ptr, GC.BlkAttr.NO_MOVE);
                asn1_result = asn1_write_value(_PuKDFentry.structure_new, "publicRSAKey.commonObjectAttributes.label", label.ptr, 0);
                if (asn1_result != ASN1_SUCCESS)
                    assumeWontThrow(writeln("### asn1_write_value publicRSAKey.commonObjectAttributes.label: ", asn1_strerror2(asn1_result)));
                break;

            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        present();
    }

    void present()
    {
//        assert(_PuKDFentry.posEnd); // it has been set
        _PuKDFentry.der_new = new ubyte[_PuKDFentry.der.length+32];
        int outDerLen;
        immutable asn1_result = asn1_der_coding(_PuKDFentry.structure_new, "", _PuKDFentry.der_new, outDerLen,
            errorDescription);
        if (asn1_result != ASN1_SUCCESS)
        {
            printf ("\n### _PuKDFentry.der_new encoding creation: ERROR  with Obs_change_calcPuKDF\n");
//                    assumeWontThrow(writeln("### asn1Coding: ", errorDescription));
            return;
        }
        if (outDerLen)
            _PuKDFentry.der_new.length = outDerLen;
        _value = cast(int)(_PuKDFentry.der_new.length - _PuKDFentry.der.length);
////assumeWontThrow(writefln(typeof(this).stringof~" object was set"));
////assumeWontThrow(writefln("_new_encodedData of PuKDFentry: %(%02X %)", _PuKDFentry.der_new));
//        emit("_change_calcPuKDF", _value);
        if (_h !is null)
        {
            _h.SetIntegerId2/*SetStringId2*/ ("", _lin, _col, _value/*.to!string*/); //  ~" / "~ _value.to!string
            _h.Update;
        }
    }

//    mixin Signal!(string, int);

    private :
        int     _value;
        PKCS15_ObjectTyp  _PuKDFentry;

        int    _lin;
        int    _col;
        Handle _h;
}


class Obs_statusInput
{
    mixin(commonConstructor);

  @property bool[9] get() const /*@nogc*/ nothrow /*pure*/ /*@safe*/ { return _value; }

//    @property bool[4] val() const @nogc nothrow /*pure*/ @safe { return _value; }

    void watch(string msg, int[2] v)
    {
        switch(msg)
        {
            case "_fidRSAprivate":
                _fidSizeRSAprivate = v[1];
                _value[2] = all(v[]);
                _value[7] =  _sizeNewRSAprivateFile <= _fidSizeRSAprivate;
                break;
            case "_fidRSApublic":
                _fidSizeRSApublic = v[1];
                _value[3] = all(v[]);
                _value[8] =  _sizeNewRSApublicFile <= _fidSizeRSApublic;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        calculate();
    }

    void watch(string msg, int v)
    {
        switch(msg)
        {
            case "_keyAsym_fidAppDir":
                _value[1] = v>0;
                break;
            case "_keyAsym_usagePrKDF":
                _keyAsym_usagePrKDF = v;
                _value[6] = (v&2 && !(_keyAsym_usageGenerate&2))  || (v&4 && !(_keyAsym_usageGenerate&4))?  false : true;
                break;
            case "_keyAsym_usageGenerate":
                _keyAsym_usageGenerate = v;
                _value[6] = (_keyAsym_usagePrKDF&2 && !(v&2)) || (_keyAsym_usagePrKDF&4 && !(v&4))? false : true;
                break;
            case "_sizeNewRSAprivateFile":
                _sizeNewRSAprivateFile = v;
                _value[7] =  _sizeNewRSAprivateFile <= _fidSizeRSAprivate;
                break;
            case "_sizeNewRSApublicFile":
                _sizeNewRSApublicFile = v;
                _value[8] =  _sizeNewRSApublicFile <= _fidSizeRSApublic;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        calculate();
    }

    void watch(string msg, ubyte[16] v)
    {
        switch(msg)
        {
            case "_valuePublicExponent":
                _value[5] = ub82integral(v[0..8])>0 || ub82integral(v[8..16])>0;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        calculate();
    }

    void calculate()
    {
        string activeToggle = AA["radioKeyAsym"].GetStringVALUE();
        _value[0] = all( indexed(_value[],
                        activeToggle.among("toggle_RSA_PrKDF_PuKDF_change", "toggle_RSA_key_pair_delete")?  [1,2,3,4]     :
                        activeToggle.among("toggle_RSA_key_pair_regenerate")?                               [1,2,3,4,5,6,7,8] :
                        activeToggle.among("toggle_RSA_key_pair_create_and_generate")?                      [1,    4,5,6] :
                                                                                                            [1,2,3,4,5] ));
////assumeWontThrow(writefln(typeof(this).stringof~" object was set to values %(%s %)", _value));
//        emit("_statusInput", _value);

        with (_h) if (_h !is null)
        {
            if (_value[0])
            {
                SetStringId2 ("", _lin, _col, "Okay, subject to authentication");
                SetRGBId2(IUP_BGCOLOR, _lin, _col, 0, 255, 0);
            }
            else
            {
                SetStringId2 ("", _lin, _col, "Something is missing");
                SetRGBId2(IUP_BGCOLOR, _lin, _col, 255, 0, 0);
            }
            _h.Update;
        }
    }

//    mixin Signal!(string, bool[6]);

    private :
        int  _fidSizeRSAprivate;
        int  _fidSizeRSApublic;
        int  _sizeNewRSAprivateFile;
        int  _sizeNewRSApublicFile;
        int  _keyAsym_usagePrKDF;
        int  _keyAsym_usageGenerate;

/*
bool[ ] mapping:
 0==true: overall okay;
 1==true: appdf !is null, i.e. appDir exists
 2==true: fidRSAprivate exists and is below appDir in same directory as fidRSApublic
 3==true: fidRSApublic  exists and is below appDir in same directory as fidRSAprivate
 4==true: fidRSAprivate and fidRSApublic are a key pair with common key id; may also read priv file from pub in order to verify
 5==true: valuePublicExponent is a prime
 6==true: keyAsym_usagePrKDF and keyAsym_usageGenerate don't conflict (only for "toggle_RSA_key_pair_regenerate"/"toggle_RSA_key_pair_create_and_generate")
 7==true: private key file size available and required don't conflict (only for "toggle_RSA_key_pair_regenerate")
 8==true: public  key file size available and required don't conflict (only for "toggle_RSA_key_pair_regenerate")

 9==true  PRKDF file is sufficiently sized to carry new values; if not, silently delete and create new, larger file
10==true  PUKDF file is sufficiently sized to carry new values; if not, silently delete and create new, larger file
*/
        bool[9]  _value = [false,  false, false, false,  true, false, false, false, false ];
        int       _lin;
        int       _col;
        Handle    _h;
}


/* ATTENTION: this must be synchronous how opensc generates new ones from profile acos5_64.profile
currently the template defines for
EF public-key:  starting from file-id = 4131
EF private-key: starting from file-id = 41F1
The last nibble is common for a keypair and taken as keyAsym_Id (1 byte)
Operating with a 1 byte is NOT CONFORMANT to the standard, that's just how it is currently

The topic RSA Keypair file id must be reviewed as well: There are some hardcoded restrictions/conventions/rules, in the driver as well

*/
int nextUniqueRSAKeyPairNo() nothrow
{
    int[] keyAsym_IdAllowedRange = iota(1,16).array;
    int PairNo; // privateRSAKey.privateRSAKeyAttributes.value.indirect.path.path
    ubyte[16]  str;
    int outLen;
    int asn1_result;
    foreach (ref elem; PRKDF)
    {
        if ((asn1_result= asn1_read_value(elem.structure, "privateRSAKey.privateRSAKeyAttributes.value.indirect.path.path", str, outLen)) != ASN1_SUCCESS)
        {
            assumeWontThrow(writefln("### asn1_read_value %s: %s", "privateRSAKey.privateRSAKeyAttributes.value.indirect.path.path", asn1_strerror2(asn1_result)));
            assert(0);
        }
        assert(outLen>=2);
        PairNo = str[outLen-1]&0x0F;
        keyAsym_IdAllowedRange = find!((a,b) => a == b)(keyAsym_IdAllowedRange, PairNo); // remove any id smaller than id found
        if (keyAsym_IdAllowedRange.length)
            keyAsym_IdAllowedRange = keyAsym_IdAllowedRange[1..$]; // remove id found
    }
//    int result = keyAsym_IdAllowedRange.empty? -1 : keyAsym_IdAllowedRange.front;
//assumeWontThrow(writeln("nextUniqueRSAKeyPairNo: ", result));
    return  keyAsym_IdAllowedRange.empty? -1 : keyAsym_IdAllowedRange.front;//result;
}

void populate_info_from_getResponse(ref ub32 info, /*const*/ ubyte[MAX_FCI_GET_RESPONSE_LEN] rbuf)  nothrow
{
//    assumeWontThrow(writefln("%(%02X %)     %(%02X %)", info, rbuf));
    immutable len = rbuf[1];
    foreach (d,T,L,V; tlv_Range_mod(rbuf[2..2+len]))
    {
        if      (T == /*ISO7816_TAG_FCP_.*/ISO7816_TAG_FCP_SIZE)
            info[4..6]/*fileSize*/ = V[0..2];
        else if (T == /*ISO7816_TAG_FCP_.*/ISO7816_TAG_FCP_TYPE)
        {
            info[0]/*FDB*/ = V[0];
            if (iEF_FDB_to_structure(cast(EFDB)V[0])&6  &&  L.among(5,6))  // then it's a record-based fdb
            {
                info[4]/*MRL*/ = V[3];
                info[5]/*NOR*/ = V[L-1];
            }
        }
        else if (T == /*ISO7816_TAG_FCP_.*/ISO7816_TAG_FCP_FID)
            info[2..4]/*fid*/ = V[0..2];
        else if (T == /*ISO7816_TAG_FCP_.*/ISO7816_TAG_FCP_LCS)
            info[7]/*lcsi*/ = V[0];
/*
        else if (T == ISO7816_RFU_TAG_FCP_.ISO7816_RFU_TAG_FCP_SFI)
            info[6]/ *sfi* / = V[0];
        else if (T == ISO7816_RFU_TAG_FCP_.ISO7816_RFU_TAG_FCP_SAC) {
            ed.ambSAC[0..L] = V[0..L];
            ed.Readable = ! ( L>1  &&  (V[0]&1)  &&  V[L-1]==0xFF);
        }
*/
    } // foreach (d,T,L,V; tlv_Range_mod(rbuf[2..2+len]))
//    assumeWontThrow(writefln("%(%02X %)", info));
/+ from removed in acos5_64_init
    else {
        fsData data;
        data.path[0..2] = [0x3F, 0];
        data.fi[1] = 2;
        data.fi[6] = 255;
        foreach (T,L,V; tlv_Range(rbuf[2..2+rbuf[1]])) {
//            try {
                if      (T == ISO7816_TAG_FCP_.ISO7816_TAG_FCP_SIZE)
                    data.fi[4..6] = V[0..2];
                else if (T == ISO7816_TAG_FCP_.ISO7816_TAG_FCP_TYPE) {
                    data.fi[0] = V[0];
                    if (iEF_FDB_to_structure(cast(EFDB)V[0])&6  &&  L.among(5,6)) { // then it's a record-based fdb
                        data.fi[5] = V[L-1];
                        data.fi[4] = V[3];
                    }
                }
                else if (T == ISO7816_TAG_FCP_.ISO7816_TAG_FCP_FID)
                    data.fi[2..4] = V[0..2];
                else if (T == ISO7816_TAG_FCP_.ISO7816_TAG_FCP_LCS)
                    data.fi[7] = V[0];
//            }
//            catch (Exception e) { printf("### Exception in \n"); /* todo: handle exception */ }
        } // foreach (d,T,L,V; tlv_Range_mod(rbuf[2..2+len]))
        fsy = TreeTypeFSy(data);
        {
            import std.stdio;
            import std.exception;
            assumeWontThrow(writefln("%(%02X %)  %(%02X %)", data.fi, data.path));
        }
    }
+/
}


/+
ushort bitString2ushort_reversed(const bool[] bs) @nogc nothrow pure @safe {
    import std.math : ldexp; //pow;//    import core.bitop;
    assert(bs.length<=16);
    if (bs.length==0)
        return 0;

    real result = 0, significand1 = 1;
    foreach (int i, v; bs)
        if (v)
          result += ldexp(significand1,i);
    return cast(ushort)(result + 0.5);
}
+/

int set_more_for_keyAsym_Id(int keyAsym_Id) nothrow
{
    assert(keyAsym_Id > 0);

    import core.bitop : bitswap;

    string activeToggle = AA["radioKeyAsym"].GetStringVALUE();
//assumeWontThrow(writefln("activeToggle: %s", activeToggle));
////    printf("set_more_for_keyAsym_Id (%d)\n", keyAsym_Id);

    int  asn1_result;
    int  outLen;

    PKCS15_ObjectTyp  PrKDFentry = change_calcPrKDF.pkcs15_ObjectTyp;
    PKCS15_ObjectTyp  PuKDFentry = change_calcPuKDF.pkcs15_ObjectTyp;

    ubyte[1] flags; // optional
    asn1_result = asn1_read_value(PrKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.flags", flags, outLen);
    if (asn1_result != ASN1_SUCCESS)
        assumeWontThrow(writeln("### asn1_read_value privateRSAKey.commonObjectAttributes.flags: ", asn1_strerror2(asn1_result)));
    else
    {
//        assert(outLen==2); // bits
        flags[0] = util_general.bitswap(flags[0]);

        keyAsym_Modifiable.set((flags[0]&2)/2, true);

        if (!keyAsym_Modifiable.get &&  activeToggle.among("toggle_RSA_key_pair_delete", "toggle_RSA_key_pair_regenerate") )
        {
            IupMessage("Feedback upon setting keyAsym_Id",
"The PrKDF entry for the selected keyAsym_Id disallows modifying the RSA private key !\nThe toggle will be changed to toggle_RSA_PrKDF_PuKDF_change toggled");
            AA["toggle_RSA_PrKDF_PuKDF_change"].SetIntegerVALUE(1);
            toggle_radioKeyAsym_cb(AA["toggle_RSA_PrKDF_PuKDF_change"].GetHandle, 1);
        }
    }
    ubyte[1] authId; // optional
    asn1_result = asn1_read_value(PrKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.authId", authId, outLen);
    if (asn1_result != ASN1_SUCCESS)
    {
        assumeWontThrow(writeln("### asn1_read_value privateRSAKey.commonObjectAttributes.authId: ", asn1_strerror2(asn1_result)));
    }
    else
    {
        assert(outLen==1);
        if (authId[0])
        {    assert(flags[0]&1); } // may run into a problem if asn1_read_value for flags failed
        keyAsym_authId.set(authId[0], true);
    }

    { // make label inaccessible when leaving the scope
        char[] label = new char[65]; // optional
        label[0..65] = '\0';
        asn1_result = asn1_read_value(PrKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.label", label, outLen);
        if (asn1_result != ASN1_SUCCESS)
        {
            assumeWontThrow(writeln("### asn1_read_value privateRSAKey.commonObjectAttributes.label: ", asn1_strerror2(asn1_result)));
        }
        else
            keyAsym_Label.set(assumeUnique(label[0..outLen]), true);
    }
    GC.collect();

    ubyte[2] keyUsageFlags; // non-optional
    asn1_result = asn1_read_value(PrKDFentry.structure_new, "privateRSAKey.commonKeyAttributes.usage", keyUsageFlags, outLen);
    if (asn1_result != ASN1_SUCCESS)
        assumeWontThrow(writeln("### asn1_read_value privateRSAKey.commonKeyAttributes.usage: ", asn1_strerror2(asn1_result)));
    else
    {
//        assert(outLen==10); // bits
//assumeWontThrow(writefln("keyUsageFlags: %(%02X %)", keyUsageFlags));
        keyAsym_usagePrKDF.set( bitswap(ub22integral(keyUsageFlags)<<16), true);
    }

//        with (PrKDFentry.privateRSAKeyAttributes) {

    ubyte[2] modulusLength; // non-optional
    asn1_result = asn1_read_value(PrKDFentry.structure_new, "privateRSAKey.privateRSAKeyAttributes.modulusLength", modulusLength, outLen);
    if (asn1_result == ASN1_ELEMENT_NOT_FOUND)
        assumeWontThrow(writeln("### asn1_read_value privateRSAKey.privateRSAKeyAttributes.modulusLength: ", asn1_strerror2(asn1_result)));
    assert(outLen==2);
//assumeWontThrow(writefln("modulusLength set by set_more_for_keyAsym_Id: %(%02X %)", modulusLength));
    immutable modulusBitLen = ub22integral(modulusLength);
    assert(modulusBitLen%256==0 && modulusBitLen>=512  && modulusBitLen<=4096);
    keyAsym_RSAmodulusLenBits.set(modulusBitLen, true);

    ubyte[16]  str;
    asn1_result = asn1_read_value(PrKDFentry.structure_new, "privateRSAKey.privateRSAKeyAttributes.value.indirect.path.path", str, outLen);
    if (asn1_result == ASN1_ELEMENT_NOT_FOUND)
    {
        assumeWontThrow(writeln("### asn1_read_value privateRSAKey.privateRSAKeyAttributes.value.indirect.path.path: ", asn1_strerror2(asn1_result)));
        exit(1);
    }
    assert(outLen>=2);
    fidRSAprivate.set( [ub22integral(str[outLen-2..outLen]), 0], true );

/+
        with (PuKDFentry.commonObjectAttributes) {
            assert(PrKDFentry.commonObjectAttributes.label          == label);
            assert((PrKDFentry.commonObjectAttributes.flags&2)      == (flags&2));
            assert(authId==0);
            assert((flags&1)==0);
        }
        assert(PrKDFentry.privateRSAKeyAttributes.modulusLength == PuKDFentry.publicRSAKeyAttributes.modulusLength);
        with (PuKDFentry.commonKeyAttributes) {
//            keyAsym_usagePuKDF.set(usage, true);
            assert(PrKDFentry.commonKeyAttributes.keyReference  == keyReference);
        }
+/

    asn1_result = asn1_read_value(PuKDFentry.structure_new, "publicRSAKey.publicRSAKeyAttributes.value.indirect.path.path", str, outLen);
    if (asn1_result == ASN1_ELEMENT_NOT_FOUND)
    {
        assumeWontThrow(writeln("### asn1_read_value publicRSAKey.publicRSAKeyAttributes.value.indirect.path.path: ", asn1_strerror2(asn1_result)));
        exit(1);
    }
    assert(outLen>=2);
    fidRSApublic.set( [ub22integral(str[outLen-2..outLen]), 0], true );

    tnTypePtr rsaPriv, rsaPub;
    rsaPriv = fs.rangePreOrder().locate!"equal(a.data[2..4], b[])"(fidRSAprivate.getub2);
    rsaPub  = fs.rangePreOrder().locate!"equal(a.data[2..4], b[])"(fidRSApublic.getub2);
    assert(rsaPriv);
    assert(rsaPub);
    AA["matrixKeyAsym"].SetStringId2("", r_AC_Update_Delete_RSAprivateFile,        1, assumeWontThrow(format!"%02X"(rsaPriv.data[25])) ~" / "~ assumeWontThrow(format!"%02X"(rsaPriv.data[30])));
    AA["matrixKeyAsym"].SetStringId2("", r_AC_Update_Delete_RSApublicFile,         1, assumeWontThrow(format!"%02X"(rsaPub.data[25]))  ~" / "~ assumeWontThrow(format!"%02X"(rsaPub.data[30])));
    AA["matrixKeyAsym"].SetStringId2("", r_AC_Crypto_RSAprivateFile_RSApublicFile, 1, assumeWontThrow(format!"%02X"(rsaPriv.data[26])) ~" / "~ assumeWontThrow(format!"%02X"(rsaPub.data[26])));

////
    if (isNewKeyPairId)
    {
        ub16 buf = [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,1,0,1];
        valuePublicExponent.set(buf, true);
        isNewKeyPairId = false;
    }
    else
    {
        enum string commands = `
        int rv;
        sc_path path;
        sc_path_set(&path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &rsaPub.data[8], rsaPub.data[1], 0, -1);
        rv= sc_select_file(card, &path, null);
        assert(rv==0);
        ub16 buf;
        rv= sc_get_data(card, 5, buf.ptr, buf.length);
        assert(rv==buf.length);
        valuePublicExponent.set(buf, true);
`;
        mixin (connect_card!commands);
    }
    return 0;
}


extern(C) nothrow :


int matrixKeyAsym_dropcheck_cb(Ihandle* /*self*/, int lin, int col)
{
    if (col!=1 || lin>r_keyAsym_crtModeGenerate)
        return IUP_IGNORE; // draw nothing
//    printf("matrixKeyAsym_dropcheck_cb(%d, %d)\n", lin, col);
//    printf("matrixKeyAsym_dropcheck_cb  %s\n", AA["radioKeyAsym"].GetAttributeVALUE());
    immutable activeToggle = AA["radioKeyAsym"].GetStringVALUE();
    immutable isSelectedKeyPairId = AA["matrixKeyAsym"].GetIntegerId2("", r_keyAsym_Id, 1) != 0;
    switch (lin)
    {
    /* dropdown */
        case r_keyAsym_Id:
            if (activeToggle != "toggle_RSA_key_pair_create_and_generate")
                return IUP_DEFAULT; // show the dropdown symbol
            break;

        case r_keyAsym_RSAmodulusLenBits:
            if ( !activeToggle.among("toggle_RSA_PrKDF_PuKDF_change", "toggle_RSA_key_pair_delete", "toggle_RSA_key_pair_try_sign")  &&  isSelectedKeyPairId)
                return IUP_DEFAULT; // show the dropdown symbol
            break;

    /* toggle */
        case r_keyAsym_crtModeGenerate:
            if ( !activeToggle.among("toggle_RSA_PrKDF_PuKDF_change", "toggle_RSA_key_pair_delete", "toggle_RSA_key_pair_try_sign"))
                return IUP_CONTINUE; // show and enable the toggle button ; this short version works with TOGGLECENTERED only !
            break;

        case r_keyAsym_Modifiable:
            if ( !activeToggle.among("toggle_RSA_key_pair_delete", "toggle_RSA_key_pair_try_sign")  &&  isSelectedKeyPairId)
                return IUP_CONTINUE; // show and enable the toggle button ; this short version works with TOGGLECENTERED only !
            break;

        default:  break;
    }
    return  IUP_IGNORE; // draw nothing
} // matrixKeyAsym_dropcheck_cb


int matrixKeyAsym_drop_cb(Ihandle* /*self*/, Ihandle* drop, int lin, int col)
{
    if (col!=1 || lin>r_keyAsym_crtModeGenerate)
        return IUP_IGNORE; // draw nothing
//    printf("matrixKeyAsym_drop_cb(%d, %d)\n", lin, col);
    immutable activeToggle = AA["radioKeyAsym"].GetStringVALUE();
    immutable isSelectedKeyPairId = AA["matrixKeyAsym"].GetIntegerId2("", r_keyAsym_Id, 1) != 0;

    with (createHandle(drop))
    switch (lin)
    {
        case r_keyAsym_Id:
            if (activeToggle != "toggle_RSA_key_pair_create_and_generate")
            {
                int iD, i = 1;
                foreach (const ref elem; PRKDF)
                {
                    if ((iD= getIdentifier(elem, "privateRSAKey.commonKeyAttributes.iD")) < 0)
                        continue;
                    SetIntegerId("", i++, iD);
                }
                SetAttributeId("", i, null);
                SetAttributeStr(IUP_VALUE, null);
                return IUP_DEFAULT; // show the dropdown values
            }
            break;

/*
        case r_keyAsym_authId:
            if (activeToggle != "toggle_RSA_key_pair_delete") {
                ubyte[2]  str;
                int outLen;
                int i = 1;
//                SetIntegerId("", i++, 0);
                foreach (const ref elem; AODF) {
                    asn1_result = asn1_read_value(elem.structure, "pinAuthObj.commonAuthenticationObjectAttributes.authId", str, outLen);
                    if (asn1_result == ASN1_ELEMENT_NOT_FOUND) {
assumeWontThrow(writeln("### asn1_read_value pinAuthObj.commonAuthenticationObjectAttributes.authId: ", asn1_strerror2(asn1_result)));
                        if (asn1_read_value(elem.structure, "biometricAuthObj.commonAuthenticationObjectAttributes.authId", str, outLen) != ASN1_SUCCESS)
                            continue;
                    }
                    else if (asn1_result != ASN1_SUCCESS)
                        continue;
                    assert(outLen==1);
                    SetIntegerId("", i++, str[0]);
                }
                SetAttributeId("", i, null);
                SetAttributeStr(IUP_VALUE, null);
                return IUP_DEFAULT;
            }
            return     IUP_IGNORE;
*/

        case r_keyAsym_RSAmodulusLenBits:
            if ( !activeToggle.among("toggle_RSA_PrKDF_PuKDF_change", "toggle_RSA_key_pair_delete", "toggle_RSA_key_pair_try_sign")  &&  isSelectedKeyPairId)
            {
                foreach (i; 1..16)
                    SetIntegerId("", i, 4096-(i-1)*256);
                SetAttributeId("", 16, null);
                SetAttributeStr(IUP_VALUE, null);
                return IUP_DEFAULT; // show the dropdown values
            }
            break;

        default:  break;
    }
    return  IUP_IGNORE;  // don't show the dropdown values
}


int matrixKeyAsym_dropselect_cb(Ihandle* self, int lin, int col, Ihandle* /*drop*/, const(char)* t, int i, int v)
{
/*
DROPSELECT_CB: Action generated when an element in the dropdown list or the popup menu is selected. For the dropdown, if returns IUP_CONTINUE the value is accepted as a new
value and the matrix leaves edition mode, else the item is selected and editing remains. For the popup menu the returned value is ignored.

int function(Ihandle *ih, int lin , int col, Ihandle *drop, char *t, int i, int v ); [in C]

ih: identifier of the element that activated the event.
lin, col: Coordinates of the current cell.
drop: Identifier of the dropdown list or the popup menu shown to the user.
t: Text of the item whose state was changed.
i: Number of the item whose state was changed.
v: Indicates if item was selected or unselected (1 or 0). Always 1 for the popup menu.
*/
    assert(t);
    int val;
    try
        val = fromStringz(t).to!int;
    catch(Exception e) { printf("### Exception in matrixKeyAsym_dropselect_cb\n"); return IUP_CONTINUE; }
////    printf("matrixKeyAsym_dropselect_cb(lin: %d, col: %d, text (t) of the item whose state was changed: %s, mumber (i) of the item whose state was changed: %d, selected (v): %d)\n", lin, col, t, i, v);
    if (v/*selected*/ && col==1)
    {
//        Handle h = createHandle(self);

        switch (lin)
        {
            case r_keyAsym_Id:
                keyAsym_Id.set = val; //h.GetIntegerVALUE;
                break;

            case r_keyAsym_RSAmodulusLenBits:
                assert(i>=1  && i<=15);
                keyAsym_RSAmodulusLenBits.set =  (17-i)*256;
                break;

            default:
                assert(0);//break;
        }
    }
    return IUP_CONTINUE; // return IUP_DEFAULT;
}

int matrixKeyAsym_edition_cb(Ihandle* ih, int lin, int col, int mode, int /*update*/)
{
//mode: 1 if the cell has entered the edition mode, or 0 if the cell has left the edition mode
//update: used when mode=0 to identify if the value will be updated when the callback returns with IUP_DEFAULT. (since 3.0)
//matrixKeyAsym_edition_cb(1, 1) mode: 1, update: 0
//matrixKeyAsym_edition_cb(1, 1) mode: 0, update: 1
////    printf("matrixKeyAsym_edition_cb(%d, %d) mode: %d, update: %d\n", lin, col, mode, update);
    immutable activeToggle = AA["radioKeyAsym"].GetStringVALUE();
    immutable isSelectedKeyPairId = AA["matrixKeyAsym"].GetIntegerId2("", r_keyAsym_Id, 1) != 0;
    if (mode==1)
    {
        AA["statusbar"].SetString(IUP_TITLE, "statusbar");
        // toggle rows always readonly, if they are NOT enabled as toggles; otherwise: enabled as toggles, they don't go through edition_cb
        if (col!=1 || lin.among(r_keyAsym_Modifiable, r_keyAsym_crtModeGenerate))
            return IUP_IGNORE;
        // readonly, unconditionally
        if (lin.among( // r_keyAsym_usagePuKDF,  hidden
                      r_keyAsym_authId,
                      r_acos_internal,

                      r_fidRSAprivate,
                      r_fidRSApublic,
                      r_keyAsym_fidAppDir,
                      r_change_calcPrKDF,
                      r_change_calcPuKDF,
                      r_sizeNewRSAprivateFile,
                      r_sizeNewRSApublicFile,
                      r_statusInput,
                      r_AC_Update_PrKDF_PuKDF,
                      r_AC_Update_Delete_RSAprivateFile,
                      r_AC_Update_Delete_RSApublicFile,
                      r_AC_Create_Delete_RSADir))
            return IUP_IGNORE;

        // readonly, condition  isSelectedKeyPairId
        if (!isSelectedKeyPairId)
        {
            if (lin.among(r_keyAsym_Label,
                          r_keyAsym_usagePrKDF,
                          r_keyAsym_RSAmodulusLenBits))
                return IUP_IGNORE;
        }
        // readonly, condition  activeToggle
        switch (activeToggle)
        {
            case "toggle_RSA_PrKDF_PuKDF_change":
                if (lin.among(
//                            r_keyAsym_Id,
//                            r_keyAsym_Label,
//                            r_keyAsym_usagePrKDF,
                              r_keyAsym_RSAmodulusLenBits,
                              r_valuePublicExponent,
                              r_keyAsym_usageGenerate
                )) // read_only
                    return IUP_IGNORE;
                break;
//                else
//                    return IUP_DEFAULT;
            case "toggle_RSA_key_pair_delete",
                 "toggle_RSA_key_pair_try_sign":
                if (lin.among(
//                            r_keyAsym_Id,
                              r_keyAsym_Label,
                              r_keyAsym_usagePrKDF,
                              r_keyAsym_RSAmodulusLenBits,
                              r_valuePublicExponent,
                              r_keyAsym_usageGenerate
                )) // read_only
                    return IUP_IGNORE;
                break;
//                else
//                    return IUP_DEFAULT;

            case "toggle_RSA_key_pair_regenerate":
                break; //return IUP_DEFAULT;

            case "toggle_RSA_key_pair_create_and_generate":
                if (lin==r_keyAsym_Id)
                    return IUP_IGNORE;
                break; //return IUP_DEFAULT;

            default:  assert(0);
        }
        return IUP_DEFAULT;
    } // if (mode==1)

    //mode==0
    assert(lin!=r_keyAsym_authId);

    Handle h = createHandle(ih);

    switch (lin)
    {
        case r_keyAsym_usagePrKDF:
            if (activeToggle != "toggle_RSA_key_pair_create_and_generate")
                IupMessage("Feedback upon setting keyAsym_usagePrKDF",
"Be carefull changing this: It was basically set to 'sign and/or decrypt' + possibly more when the key pair was generated.\nThis is the sole hint available about the actual key usage capability, which is not retrievable any more, hidden by non-readability of private key file.\nIf something gets set here that is outside generated key's usage capability, then don't be surprised if RSA operation(s) won't (all) work as You might expect !");
            int tmp = clamp(h.GetIntegerVALUE & 558, 0, 1023);
            // if no "sign",   then also no "signRecover" and no "nonRepudiation"
            if (!(tmp&4))
                tmp &= 34;
            // if no "decrypt", then also no "unwrap"
            if (!(tmp&2))
                tmp &= 524;
            // if nothing remains, then set "sign"
            if (!tmp)
                tmp = 4;
            // checking against keyAsym_usageGenerate done in status
            keyAsym_usagePrKDF.set(tmp, true); // strange, doesn't update with new string
            h.SetStringVALUE(keyUsageFlagsInt2string(tmp));
            break;

        case r_keyAsym_usageGenerate:
            immutable tmp = clamp(h.GetIntegerVALUE & 6, 2, 6);
            keyAsym_usageGenerate.set(tmp, true); // strange, doesn't update with new string
            h.SetStringVALUE(keyUsageFlagsInt2string(tmp));
            break;

        case r_valuePublicExponent:
            string tmp_str = h.GetStringVALUE();
            assert(tmp_str.length<=32 );
            while (tmp_str.length<32)
                tmp_str = "0" ~ tmp_str;
            uba  tmp_arr = string2ubaIntegral(tmp_str);
            valuePublicExponent.set(tmp_arr[0..16], true); // strange, doesn't update with new string
            if (!any(valuePublicExponent.get[]))
                h.SetStringVALUE("");
            break;

        case r_keyAsym_Label:
            keyAsym_Label.set = h.GetStringVALUE();
            break;

        default:
            break;
    }
    return IUP_DEFAULT;
} // matrixKeyAsym_edition_cb



int matrixKeyAsym_togglevalue_cb(Ihandle* /*self*/, int lin, int /*col*/, int status)
{
//    assert(col==1 && lin.among(r_keyAsym_Modifiable, r_keyAsym_crtModeGenerate));
////    printf("matrixKeyAsym_togglevalue_cb(%d, %d) status: %d\n", lin, col, status);
    switch (lin)
    {
        case r_keyAsym_Modifiable:
//            immutable isSelectedKeyPairId = AA["matrixKeyAsym"].GetIntegerId2("", r_keyAsym_Id, 1) != 0;
//            if (isSelectedKeyPairId)
                keyAsym_Modifiable.set = status;
//            else
//            {    assert(0); }
            break;

        case r_keyAsym_crtModeGenerate:
            keyAsym_crtModeGenerate.set = status;
            break;

        default: break;
    }
    return IUP_DEFAULT;
}


int toggle_radioKeyAsym_cb(Ihandle* ih, int state)
{
//    printf("toggle_radioKeyAsym_cb (%d) %s\n", state, IupGetName(ih));
    if (state==0)  // for the toggle, that lost activated state
    {
        /* if the keyAsym_Id is not valid (e.g. prior selected was "toggle_RSA_key_pair_create_and_generate" but no creation was invoked)
           then select a valid one */
        int Id;
        Handle h = AA["matrixKeyAsym"];
        immutable inactivatedToggle = IupGetName(ih).fromStringz.idup;
        if (inactivatedToggle == "toggle_RSA_key_pair_create_and_generate" &&
            empty(find!((a,b) => b == getIdentifier(a, "privateRSAKey.commonKeyAttributes.iD"))(PRKDF, keyAsym_Id.get)))
            foreach (i, const ref elem; PRKDF)
            {
                if ((Id= getIdentifier(elem, "privateRSAKey.commonKeyAttributes.iD")) < 0)
                    continue;
                h.SetIntegerId2("", r_keyAsym_Id, 1, Id);
                matrixKeyAsym_dropselect_cb(h.GetHandle, r_keyAsym_Id, 1, null, Id.to!string.toStringz, cast(int)i+1, 1);
                break;
            }
        AA["statusbar"].SetString(IUP_TITLE, "statusbar");
        return IUP_DEFAULT;
    }
    string activeToggle = AA["radioKeyAsym"].GetStringVALUE();

    if (!keyAsym_Modifiable.get && activeToggle.among("toggle_RSA_key_pair_delete", "toggle_RSA_key_pair_regenerate") )
    {
        IupMessage("Feedback upon setting keyAsym_Id",
"The PrKDF entry for the selected keyAsym_Id disallows modifying the RSA private key !\nThe toggle will be changed to toggle_RSA_PrKDF_PuKDF_change toggled");
        AA["toggle_RSA_PrKDF_PuKDF_change"].SetIntegerVALUE(1);
        toggle_radioKeyAsym_cb(AA["toggle_RSA_PrKDF_PuKDF_change"].GetHandle, 1);
        return IUP_DEFAULT;
    }

    Handle hButton = AA["button_radioKeyAsym"];
////    printf("toggle_radioKeyAsym_cb (%d) %s\n", state, activeToggle.toStringz);

/*
"toggle_RSA_PrKDF_PuKDF_change"
"toggle_RSA_key_pair_delete"
"toggle_RSA_key_pair_regenerate"
"toggle_RSA_key_pair_create_and_generate"
"toggle_RSA_key_pair_try_sign"
*/
    with (AA["matrixKeyAsym"])
    switch (activeToggle)
    {
        case "toggle_RSA_PrKDF_PuKDF_change":
            hButton.SetString(IUP_TITLE, "PrKDF/PuKDF only: Change some administrative (PKCS#15) data");
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_Id,                1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_Label,             1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_Modifiable,        1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_usagePrKDF,        1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_keyAsym_RSAmodulusLenBits, 1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_valuePublicExponent,       1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_crtModeGenerate,   1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_usageGenerate,     1,  255,255,255);
            break;
        case "toggle_RSA_key_pair_delete":
            hButton.SetString(IUP_TITLE, "RSA key pair: Delete key pair files (Currently not capable to delete the last existing key pair, i.e. one must remain to be selectable)");
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_Id,                1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_Label,             1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_Modifiable,        1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_usagePrKDF,        1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keyAsym_RSAmodulusLenBits, 1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_valuePublicExponent,       1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_crtModeGenerate,   1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_usageGenerate,     1,  255,255,255);
            break;
        case "toggle_RSA_key_pair_regenerate":
            hButton.SetString(IUP_TITLE, "RSA key pair: Regenerate RSA key pair content in existing files (Takes some time: Up to 3-5 minutes for 4096 bit)");
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_Id,                1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_Label,             1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_Modifiable,        1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_usagePrKDF,        1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_keyAsym_RSAmodulusLenBits, 1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_valuePublicExponent,       1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_crtModeGenerate,   1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_usageGenerate,     1,  152,251,152);
            break;
        case "toggle_RSA_key_pair_create_and_generate":
            hButton.SetString(IUP_TITLE, "RSA key pair: Create new RSA key pair files and generate RSA key pair content");
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_Id,                1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_Label,             1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_Modifiable,        1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_usagePrKDF,        1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_keyAsym_RSAmodulusLenBits, 1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_valuePublicExponent,       1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_crtModeGenerate,   1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_usageGenerate,     1,  152,251,152);

            isNewKeyPairId = true;
            nextUniqueId = nextUniqueKeyId();
            assert(nextUniqueId>0);
            keyAsym_Id.set(nextUniqueId, true);
            break;
        case "toggle_RSA_key_pair_try_sign":
            hButton.SetString(IUP_TITLE, "RSA key pair: Sign SHA1/SHA256 hash");
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_Id,                1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_Label,             1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_Modifiable,        1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_usagePrKDF,        1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keyAsym_RSAmodulusLenBits, 1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_valuePublicExponent,       1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_crtModeGenerate,   1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keyAsym_usageGenerate,     1,  255,255,255);
            break;
        default:  assert(0);
    } // switch (activeToggle)
//    printf("invoke recalculation of statusInput\n");
    valuePublicExponent.emit_self(); // invokes updating statusInput for am activated toggle; (valuePublicExponent is arbitrary here, just one, that statusInput depends on)
    // a 'clean' alternative would be, to introduce a Publisher toggle, that statusInput depends on
    return IUP_DEFAULT;
} // toggle_radioKeyAsym_cb


const char[] button_radioKeyAsym_cb_common1 =`
            int diff;
            diff = doDelete? change_calcPrKDF.pkcs15_ObjectTyp.posStart - change_calcPrKDF.pkcs15_ObjectTyp.posEnd : change_calcPrKDF.get;

            ubyte[] zeroAdd = new ubyte[ diff>=0? 0 : abs(diff) ];
            auto haystackPriv = find!((a,b) => b == getIdentifier(a, "privateRSAKey.commonKeyAttributes.iD"))(PRKDF, keyAsym_Id.get);
            assert(!haystackPriv.empty);
            // change_calcPrKDF.pkcs15_ObjectTyp shall be identical to resulting haystackPriv.front (except the _new components)!) !

            with (change_calcPrKDF.pkcs15_ObjectTyp)
            if (!doDelete && der_new !is null)
            {
                haystackPriv.front.der = der = der_new.dup;

                asn1_node  structurePriv, tmp = haystackPriv.front.structure;
                int asn1_result = asn1_create_element(PKCS15, pkcs15_names[PKCS15_FILE_TYPE.PKCS15_PRKDF][3], &structurePriv);
                if (asn1_result != ASN1_SUCCESS)
                {
                    assumeWontThrow(writeln("### Structure creation: ", asn1_strerror2(asn1_result)));
                    return IUP_DEFAULT;
                }
                if (asn1_der_decoding(&structurePriv, haystackPriv.front.der, errorDescription) != ASN1_SUCCESS)
                {
                    assumeWontThrow(writeln("### asn1Decoding: ", errorDescription));
                    return IUP_DEFAULT;
                }
                haystackPriv.front.structure = structurePriv;
                structure                    = structurePriv;
                asn1_delete_structure(&tmp);
            }

            ubyte[] bufPriv;
            change_calcPrKDF.pkcs15_ObjectTyp.posEnd +=  diff;
            foreach (i, ref elem; haystackPriv)
            {
                if (i>0 || !doDelete)
                    bufPriv ~= elem.der;
                if (i>0)
                    elem.posStart += diff;
                elem.posEnd       += diff;
            }
            bufPriv ~=  zeroAdd;
            assert(prkdf);
//assumeWontThrow(writeln("  ### check change_calcPrKDF.pkcs15_ObjectTyp: ", change_calcPrKDF.pkcs15_ObjectTyp));
//assumeWontThrow(writeln("  ### check haystackPriv:                      ", haystackPriv));


            diff = doDelete? change_calcPuKDF.pkcs15_ObjectTyp.posStart - change_calcPuKDF.pkcs15_ObjectTyp.posEnd : change_calcPuKDF.get;
            zeroAdd = new ubyte[ diff>=0? 0 : abs(diff) ];
            auto haystackPubl = find!((a,b) => b == getIdentifier(a, "publicRSAKey.commonKeyAttributes.iD"))(PUKDF, keyAsym_Id.get);
            assert(!haystackPubl.empty);
            // change_calcPuKDF.pkcs15_ObjectTyp shall be identical to resulting haystackPubl.front (except the _new components)!) !

            with (change_calcPuKDF.pkcs15_ObjectTyp)
            if (!doDelete && der_new !is null)
            {
                haystackPubl.front.der = der = der_new.dup;

                asn1_node  structurePubl, tmp = haystackPubl.front.structure;
                int asn1_result = asn1_create_element(PKCS15, pkcs15_names[PKCS15_FILE_TYPE.PKCS15_PUKDF][3], &structurePubl);
                if (asn1_result != ASN1_SUCCESS)
                {
                    assumeWontThrow(writeln("### Structure creation: ", asn1_strerror2(asn1_result)));
                    return IUP_DEFAULT;
                }
                if (asn1_der_decoding(&structurePubl, haystackPubl.front.der, errorDescription) != ASN1_SUCCESS)
                {
                    assumeWontThrow(writeln("### asn1Decoding: ", errorDescription));
                    return IUP_DEFAULT;
                }
                haystackPubl.front.structure = structurePubl;
                structure                    = structurePubl;
                asn1_delete_structure(&tmp);
            }

            ubyte[] bufPubl;
            change_calcPuKDF.pkcs15_ObjectTyp.posEnd +=  diff;
            foreach (i, ref elem; haystackPubl)
            {
                if (i>0 || !doDelete)
                    bufPubl ~= elem.der;
                if (i>0)
                    elem.posStart += diff;
                elem.posEnd       += diff;
            }
            bufPubl ~=  zeroAdd;
            assert(pukdf);
//assumeWontThrow(writeln("  ### check change_calcPuKDF.pkcs15_ObjectTyp: ", change_calcPuKDF.pkcs15_ObjectTyp));
//assumeWontThrow(writeln("  ### check haystackPubl:                      ", haystackPubl));
`;
//mixin(button_radioKeyAsym_cb_common1);

/* TODO IMPORTANT make sure when generating new RSA key pair content, that one of the highest 7 bits of Modulus is set (requirement Modulus > EM), i.e. */
int button_radioKeyAsym_cb(Ihandle* ih)
{
    import std.math : abs;

    if (!statusInput.get[0])
    {
        assumeWontThrow(writeln("  ### statusInput doesn't allow the action requested"));
        return -1;
    }

    ubyte code(int crtModeGenerate, int usageGenerate) nothrow
    {
        int pre_result;
        switch (usageGenerate)
        {
            case 4: pre_result = 1; break;
            case 2: pre_result = 2; break;
            case 6: pre_result = 3; break;
            default: assert(0);
        }
        return cast(ubyte) (pre_result+ (crtModeGenerate != 0 ? 3 : 0));
    }

    Handle hstat = AA["statusbar"];
    hstat.SetString(IUP_TITLE, "");
    immutable activeToggle = AA["radioKeyAsym"].GetStringVALUE();

    switch (activeToggle)
    {
/*
        case "toggle_RSA_PrKDF_PuKDF_change",
             "toggle_RSA_key_pair_delete",
             "toggle_RSA_key_pair_regenerate",
             "toggle_RSA_key_pair_create_and_generate",
             "toggle_RSA_key_pair_try_sign": break;
*/
        case "toggle_RSA_PrKDF_PuKDF_change":
            if (equal(change_calcPrKDF.pkcs15_ObjectTyp.der, change_calcPrKDF.pkcs15_ObjectTyp.der_new) &&
                equal(change_calcPuKDF.pkcs15_ObjectTyp.der, change_calcPuKDF.pkcs15_ObjectTyp.der_new) )
            {
                IupMessage("Feedback", "Nothing changed! Won't write anything to files");
                return IUP_DEFAULT;
            }

            //Does statusInput check, that the bytes to be written to PrKDF and PuKDF are there in "free space"
            immutable bool doDelete;// = false;
            mixin(button_radioKeyAsym_cb_common1);

            enum string commands = `
            int rv;
            // from tools/pkcs15-init.c  main
            sc_pkcs15_card*  p15card;
            sc_profile*      profile;
            const(char)*     opt_profile      = "acos5_64"; //"pkcs15";
            const(char)*     opt_card_profile = "acos5_64";
            sc_file*         file;

            sc_pkcs15init_set_callbacks(&my_pkcs15init_callbacks);

            /* Bind the card-specific operations and load the profile */
            rv= sc_pkcs15init_bind(card, opt_profile, opt_card_profile, null, &profile);
            if (rv < 0)
            {
                printf("Couldn't bind to the card: %s\n", sc_strerror(rv));
                return IUP_DEFAULT; //return 1;
            }
            rv = sc_pkcs15_bind(card, &aid, &p15card);

            file = sc_file_new();
            scope(exit)

            {
                if (file)
                    sc_file_free(file);
                if (profile)
                    sc_pkcs15init_unbind(profile);
                if (p15card)
                    sc_pkcs15_unbind(p15card);
            }

            // update PRKDF and PUKDF; essential: don't allow to be called if the files aren't sufficiently sized
            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &prkdf.data[8], prkdf.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);
            if (rv >= 0 && bufPriv.length)
                rv = sc_update_binary(card, haystackPriv.front.posStart, bufPriv.ptr, bufPriv.length, 0);
            assert(rv==bufPriv.length);

            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &pukdf.data[8], pukdf.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);
            if (rv >= 0 && bufPubl.length)
                rv = sc_update_binary(card, haystackPubl.front.posStart, bufPubl.ptr, bufPubl.length, 0);
            assert(rv==bufPubl.length);
`;
            mixin(connect_card!commands);
            hstat.SetString(IUP_TITLE, "SUCCESS: Change some administrative (PKCS#15) data");
            return IUP_DEFAULT; // case "toggle_RSA_PrKDF_PuKDF_change"

        case "toggle_RSA_key_pair_regenerate":
            immutable bool doDelete; // = false;
            mixin(button_radioKeyAsym_cb_common1);

//            auto       pos_parent = new sitTypeFS(appdf);
            tnTypePtr  prFile, puFile;
            try
            {
                prFile = fs.rangeSiblings(appdf).locate!"equal(a.data[2..4], b[])"(fidRSAprivate.getub2);
//                pos_parent = new sitTypeFS(appdf);
                puFile = fs.rangeSiblings(appdf).locate!"equal(a.data[2..4], b[])"(fidRSApublic.getub2);
            }
            catch (Exception e) { printf("### Exception in button_radioKeyAsym_cb() for toggle_RSA_key_pair_regenerate\n"); return IUP_DEFAULT; /* todo: handle exception */ }
            assert(prFile);
            assert(puFile);

            CardCtl_generate_crypt_asym  cga = {
                file_id_priv: fidRSAprivate.getushort(), file_id_pub: fidRSApublic.getushort(),
                exponent_std: true, key_len_code: cast(ubyte)(keyAsym_RSAmodulusLenBits.get/128),
                key_priv_type_code: code(keyAsym_crtModeGenerate.get, keyAsym_usageGenerate.get), perform_mse: true
            };
            if (any(valuePublicExponent.get[0..8]) || ub82integral(valuePublicExponent.get[8..16]) != 0x10001) {
                cga.exponent_std = false;
                cga.exponent = valuePublicExponent.get;
            }
//assumeWontThrow(writeln("cga", cga));

            enum string commands = `
            int rv;
            // from tools/pkcs15-init.c  main
            sc_pkcs15_card*  p15card;
            sc_profile*      profile;
            const(char)*     opt_profile      = "acos5_64"; //"pkcs15";
            const(char)*     opt_card_profile = "acos5_64";
            sc_file*         file;

            sc_pkcs15init_set_callbacks(&my_pkcs15init_callbacks);

            /* Bind the card-specific operations and load the profile */
            rv= sc_pkcs15init_bind(card, opt_profile, opt_card_profile, null, &profile);
            if (rv < 0)
            {
                printf("Couldn't bind to the card: %s\n", sc_strerror(rv));
                return IUP_DEFAULT; //return 1;
            }
            rv = sc_pkcs15_bind(card, &aid, &p15card);

            file = sc_file_new();
            scope(exit)
            {
                if (file)
                    sc_file_free(file);
                if (profile)
                    sc_pkcs15init_unbind(profile);
                if (p15card)
                    sc_pkcs15_unbind(p15card);
            }

            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &prFile.data[8], prFile.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);
            if (rv < 0)
                return IUP_DEFAULT;
            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &puFile.data[8], puFile.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);
            if (rv < 0)
                return IUP_DEFAULT;

            rv= sc_card_ctl(card, SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES_EXIST, &cga);
            if (rv != SC_SUCCESS)
            {
                mixin (log!(__FUNCTION__,  "regenerate_keypair_RSA failed"));
                hstat.SetString(IUP_TITLE, "FAILURE: Generate new RSA key pair content");
                return IUP_DEFAULT;
            }

            // almost done, except updating PRKDF and PUKDF
            // update PRKDF and PUKDF; essential: don't allow to be called if the files aren't sufficiently sized
            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &prkdf.data[8], prkdf.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);
            if (rv >= 0 && bufPriv.length)
                rv = sc_update_binary(card, haystackPriv.front.posStart, bufPriv.ptr, bufPriv.length, 0);
            assert(rv==bufPriv.length);

            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &pukdf.data[8], pukdf.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);
            if (rv >= 0 && bufPubl.length)
                rv = sc_update_binary(card, haystackPubl.front.posStart, bufPubl.ptr, bufPubl.length, 0);
            assert(rv==bufPubl.length);
`;
            mixin (connect_card!commands);
            hstat.SetString(IUP_TITLE, "SUCCESS: Regenerate RSA key pair content in existing files");
/+ +/
            return IUP_DEFAULT; // case "toggle_RSA_key_pair_regenerate"

        case "toggle_RSA_key_pair_delete":
        /*
           A   key pair id must be selected, and be >0
           The key pair must be modifiable; flags bit modifiable
           Ask for permission, if the key pair id is associated with a certificate, because it will render the certificate useless
        */
            immutable doDelete = true;
            immutable keyAsym_Id_old = keyAsym_Id.get;
            mixin(button_radioKeyAsym_cb_common1);

//            auto       pos_parent = new sitTypeFS(appdf);
            tnTypePtr  prFile, puFile;
            try
            {
                prFile = fs.rangeSiblings(appdf).locate!"equal(a.data[2..4], b[])"(fidRSAprivate.getub2);
//                pos_parent = new sitTypeFS(appdf);
                puFile = fs.rangeSiblings(appdf).locate!"equal(a.data[2..4], b[])"(fidRSApublic.getub2);
            }
            catch (Exception e) { printf("### Exception in button_radioKeyAsym_cb() for toggle_RSA_key_pair_delete\n"); return IUP_DEFAULT; /* todo: handle exception */ }
            assert(prFile);
            assert(puFile);

            enum string commands = `
            int rv;
            // from tools/pkcs15-init.c  main
            sc_pkcs15_card*  p15card;
            sc_profile*      profile;
            const(char)*     opt_profile      = "acos5_64"; //"pkcs15";
            const(char)*     opt_card_profile = "acos5_64";
            sc_file*         file;

            sc_pkcs15init_set_callbacks(&my_pkcs15init_callbacks);

            /* Bind the card-specific operations and load the profile */
            rv= sc_pkcs15init_bind(card, opt_profile, opt_card_profile, null, &profile);
            if (rv < 0)
            {
                printf("Couldn't bind to the card: %s\n", sc_strerror(rv));
                return IUP_DEFAULT; //return 1;
            }
            rv = sc_pkcs15_bind(card, &aid, &p15card);

            file = sc_file_new();
            scope(exit)
            {
                if (file)
                    sc_file_free(file);
                if (profile)
                    sc_pkcs15init_unbind(profile);
                if (p15card)
                    sc_pkcs15_unbind(p15card);
            }

            // update PRKDF and PUKDF; essential: don't allow to be called if the files aren't sufficiently sized
            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &prkdf.data[8], prkdf.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);
            if (rv >= 0 && bufPriv.length)
                rv = sc_update_binary(card, haystackPriv.front.posStart, bufPriv.ptr, bufPriv.length, 0);
            assert(rv==bufPriv.length);

            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &pukdf.data[8], pukdf.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);
            if (rv >= 0 && bufPubl.length)
                rv = sc_update_binary(card, haystackPubl.front.posStart, bufPubl.ptr, bufPubl.length, 0);
            assert(rv==bufPubl.length);

            // delete RSA files
            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &prFile.data[8], prFile.data[1], 0, -1);
            rv= sc_pkcs15init_delete_by_path(profile, p15card, &file.path);
            assert(rv == SC_SUCCESS);

            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &puFile.data[8], puFile.data[1], 0, -1);
            rv= sc_pkcs15init_delete_by_path(profile, p15card, &file.path);
            assert(rv == SC_SUCCESS);
`;
            mixin (connect_card!commands);
            hstat.SetString(IUP_TITLE, "SUCCESS: Delete key pair files");

            // the files are deleted, but still part of fs and tree view; now remove those too
            ub2[] searched;
            searched ~= fidRSAprivate.getub2;
            searched ~= fidRSApublic. getub2;
//            sitTypeFS parent = new sitTypeFS(appdf);
            try
            foreach (nodeFS; fs.rangeSiblings(appdf))
            {
                assert(nodeFS);
                if (nodeFS.data[0] != EFDB.RSA_Key_EF && nodeFS.data[0] != EFDB.ECC_KEY_EF)
                    continue;
                immutable len = nodeFS.data[1];
                if (countUntil!((a,b) => equal(a[], b))(searched, nodeFS.data[8+len-2..8+len]) >= 0)
                {
                    auto  tr = cast(iup.iup_plusD.Tree) AA["tree_fs"];
                    int id = tr.GetId(nodeFS);
//assumeWontThrow(writeln("id: ", id));
//assumeWontThrow(writeln("TITLE: ", tr.GetStringId ("TITLE", id)));
                    if (id>0)
                    {
                        tr.SetStringVALUE(tr.GetStringId ("TITLE", id)); // this seems to select as required
                        tr.SetStringId("DELNODE", id, "SELECTED");
                        fs.erase(nodeFS);
                    }
                }
            }
            catch (Exception e) { printf("### Exception in button_radioKeyAsym_cb() for toggle_RSA_key_pair_delete\n"); return IUP_DEFAULT; /* todo: handle exception */}

            int rv;
            Handle h = AA["matrixKeyAsym"];
            // set to another keyAsym_Id, the first found
            foreach (i, const ref elem; PRKDF)
            {
                rv = 0;
                if ((rv= getIdentifier(elem, "privateRSAKey.commonKeyAttributes.iD")) < 0)
                {    assert(0); }// continue;
                if (rv==keyAsym_Id_old)
                    continue;
                assert(rv>0);
                h.SetIntegerId2("", r_keyAsym_Id, 1, rv);
                matrixKeyAsym_dropselect_cb(h.GetHandle, r_keyAsym_Id, 1, null, rv.to!string.toStringz, cast(int)i+1, 1);
                break;
            }
            // TODO remove will leak memory of structure
            PRKDF = PRKDF.remove!((a) => getIdentifier(a, "privateRSAKey.commonKeyAttributes.iD") == keyAsym_Id_old);
            PUKDF = PUKDF.remove!((a) => getIdentifier(a, "publicRSAKey.commonKeyAttributes.iD")  == keyAsym_Id_old);
//assumeWontThrow(writeln(PRKDF));

            GC.collect(); // just a check
            return IUP_DEFAULT; // case "toggle_RSA_key_pair_delete"

        case "toggle_RSA_key_pair_create_and_generate":
/+
            ubyte keyAsym_IdCurrent = cast(ubyte)keyAsym_Id.get;
            { // scope for the Cryptoki session; upon leaving, everything related get's closed/released
                import core.sys.posix.dlfcn : dlsym, dlerror;
                import util_pkcs11 : pkcs11_check_return_value, pkcs11_get_slot, pkcs11_start_session, pkcs11_login,
                    pkcs11_logout, pkcs11_end_session;

                CK_RV              rv;
                CK_BYTE[8]         userPin =  0;//[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
                int       pinLocal     = 1;//(info.attrs.pin.reference&0x80)==0x80;
                int       pinReference = 1;//info.attrs.pin.reference&0x7F; // strip the local flag

                immutable rc = IupGetParam(toStringz("Pin requested for authorization (SCB)"),
                    null/* &param_action*/, null/* void* user_data*/, /*format*/
                    "&Pin local (User)? If local==No, then it's the Security Officer Pin:%b[No,Yes]\n" ~
                    "&Pin reference (1-31; selects the record# in pin file):%i\n" ~
                    "Pin (minLen: 4, maxLen: 8):%s\n", &pinLocal, &pinReference, userPin.ptr, null);
                if (rc != 1)
                    return IUP_DEFAULT;//return SC_ERROR_INVALID_PIN_LENGTH;

                // TODO make the Cryptoki session related code more robust (possible errors returned) and platform-independant: currently it's Linux only
                assumeWontThrow(PKCS11.load("opensc-pkcs11.so"));
                scope(exit)  assumeWontThrow(PKCS11.unload());
                rv= C_Initialize(null);
                pkcs11_check_return_value(rv, "Failed to initialze Cryptoki");
                if (rv != CKR_OK)
                    return IUP_DEFAULT;
                scope(exit)
                    C_Finalize(NULL_PTR);

                CK_SLOT_ID  slot = pkcs11_get_slot();
                CK_SESSION_HANDLE  session = pkcs11_start_session(slot);

                /*
//                  The previous solution didn't work (loading driver.so twice): global vars aren't shared !
                  Required is to get the handle of driver.so/dll loaded already:
                  google: process show handle shared library loaded
                  programmatically: http://syprog.blogspot.com/2011/12/listing-loaded-shared-objects-in-linux.html
                  https://stackoverflow.com/questions/5103443/how-to-check-what-shared-libraries-are-loaded-at-run-time-for-a-given-process
                  https://unix.stackexchange.com/questions/120015/how-to-find-out-the-dynamic-libraries-executables-loads-when-run
                  other:
                  google: load shared object local global variable
                  https://softwareengineering.stackexchange.com/questions/244664/global-variable-in-a-linux-shared-library
                */
                // libacos5_64.so is loaded already, we need the library handle
                version(Posix) /*version(CRuntime_Glibc)*/
                {
                    import std.path : baseName, stripExtension;
                    import core.sys.posix.dlfcn : dlopen, RTLD_NOW;
                    import util_opensc : lh;

                    struct lmap // link_map
                    {
                        void*  base_address;   /* Base address of the shared object */
                        char*  path;           /* Absolute file name (path) of the shared object */
                        void*  not_needed1;    /* Pointer to the dynamic section of the shared object */
                        lmap*  next; /* chain of loaded objects */
                        lmap*  prev; /* chain of loaded objects */
                    }

                    struct something
                    {
                        void*[3]    pointers;
                        something*  ptr;
                    }

                    lh = null;
                    lmap* pl;
                    void* ph = dlopen(null, RTLD_NOW);
                    something* p = cast(something*) ph;
                    p = p.ptr;
                    pl = cast(lmap*) p.ptr;

                    //     List Loaded Objects
                    //     Now we are ready to list all loaded objects. Assume p is a pointer to the first link_map (in our case lmap) structure:
//                    printf("\n");
                    while(null != pl)
                    {
//                        printf("%s\n", pl.path);
                        if (baseName(stripExtension(fromStringz(pl.path) ) ) == "libacos5_64")
                        {
                            lh = cast(void*)pl;
                            break;
                        }
                        pl = pl.next;
                    }
                    if (lh != null)
                    {
                        auto ctrl_generate_keypair_RSA =
                            cast(ft_ctrl_generate_keypair_RSA) dlsym(lh, "ctrl_generate_keypair_RSA");
                        char* error = dlerror();
                        if (error)
                        {
                            printf("dlsym error ctrl_generate_keypair_RSA: %s\n", error);
                            return IUP_DEFAULT;
                        }
                        /* This will switch off updating PrKDF and PuKDF by opensc, thus we'll have to do it here later !
                          Multiple reasons:
                          1. It's currently impossible to convince opensc to encode the publicRSAKeyAttributes.value CHOICE as indirect. i.e. it would store the publicRSAKey within PuKDF,
                             consuming a lot of memory for many/long keys unnecessarily: acos stores the pub key as file anyway, and it's accessible
                          2. opensc always adds signRecover/verifyRecover when sign/verify is selected
                          3. PuKDF contains wrong entry commonKeyAttributes.native=false
//                          4. opensc changes the id setting, see id-style in profile; currently I prefer 1-byte ids, same as the last nibble of fileid, i.e. keypair 41F5/4135 gets id 0x05
                          5. opensc erases CommonObjectAttributes.flags for pubkey occasionally
                          6. opensc stores less bits for  occasionally
                          7  opensc stores incorect modulusLength occasionally
                         */
                        // also this provides more control of keygen, than possible with opensc (tools etc.)
                        ctrl_generate_keypair_RSA(true, !!(keyAsym_usageGenerate.get&2), !!keyAsym_crtModeGenerate.get);
                    }
                } // version(Posix)

                pkcs11_login(session, userPin); // CKR_USER_PIN_NOT_INITIALIZED
                CK_OBJECT_HANDLE  publicKey, privateKey;
                CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
                CK_ULONG modulusBits = keyAsym_RSAmodulusLenBits.get;
                CK_BYTE[] publicExponent = valuePublicExponent.get[0..16].dup;  // check whether the key_gen command respects this ; check  publicExponent handling in general in opensc (e.g. _sc_card_add_rsa_alg)
                CK_BYTE[] subject = cast(ubyte[])representation(keyAsym_Label.get);
                CK_BYTE[] id      = [keyAsym_IdCurrent];
                CK_BBOOL yes = CK_TRUE;
                CK_BBOOL no  = CK_FALSE;
                CK_ATTRIBUTE[] publicKeyTemplate = [
                    {CKA_ID, id.ptr, id.length},
                    {CKA_LABEL, subject.ptr, subject.length},
                    {CKA_TOKEN, &yes, CK_BBOOL.sizeof}, // CKA_TOKEN=true to create a token object, opposed to session object
//                    {CKA_LOCAL, &yes, CK_BBOOL.sizeof}, // not becessary
                    {CKA_ENCRYPT, keyAsym_usagePrKDF.get&2? &yes : &no, CK_BBOOL.sizeof},
                    {CKA_VERIFY,  keyAsym_usagePrKDF.get&4? &yes : &no, CK_BBOOL.sizeof},

                    {CKA_MODULUS_BITS, &modulusBits, modulusBits.sizeof},
                    {CKA_PUBLIC_EXPONENT, publicExponent.ptr, 3}
                ];
                CK_ATTRIBUTE[] privateKeyTemplate = [
                    {CKA_ID, id.ptr, id.length},
                    {CKA_LABEL, subject.ptr, subject.length},
                    {CKA_TOKEN, &yes, CK_BBOOL.sizeof},
//                    {CKA_LOCAL, &yes, CK_BBOOL.sizeof}, // not becessary
                    {CKA_PRIVATE, &yes, CK_BBOOL.sizeof},
                    {CKA_SENSITIVE, &yes, CK_BBOOL.sizeof},
                    {CKA_DECRYPT, keyAsym_usagePrKDF.get&2? &yes : &no, CK_BBOOL.sizeof},
                    {CKA_SIGN,    keyAsym_usagePrKDF.get&4? &yes : &no, CK_BBOOL.sizeof},
                ];

                rv = C_GenerateKeyPair(session,
                    &mechanism,
                    publicKeyTemplate.ptr,  publicKeyTemplate.length,
                    privateKeyTemplate.ptr, privateKeyTemplate.length,
                    &publicKey,
                    &privateKey);
                pkcs11_check_return_value(rv, "generate key pair");
                if (rv != SC_SUCCESS)
                    hstat.SetString(IUP_TITLE, "FAILURE: Generate new RSA key pair. This isn't abnormal with acos."~
                        " Just try again");

                pkcs11_logout(session);
                pkcs11_end_session(session);
                if (rv != SC_SUCCESS)
                    return IUP_DEFAULT;
            }  // scope for the Cryptoki session; upon leaving, everything related get's closed/released

            ubyte[MAX_FCI_GET_RESPONSE_LEN] rbuf_priv;
            ubyte[MAX_FCI_GET_RESPONSE_LEN] rbuf_publ;
            ub32 info_priv;
            ub32 info_publ;
            int prPosEnd, puPosEnd;
            prPosEnd =  !PRKDF.empty? PRKDF[$ - 1].posEnd : 0;
            puPosEnd =  !PUKDF.empty? PUKDF[$ - 1].posEnd : 0;
            PKCS15_ObjectTyp PrKDFentry = change_calcPrKDF.pkcs15_ObjectTyp;
            PKCS15_ObjectTyp PuKDFentry = change_calcPuKDF.pkcs15_ObjectTyp;
            PRKDF ~= PKCS15_ObjectTyp(prPosEnd, cast(int)(prPosEnd+PrKDFentry.der_new.length), PrKDFentry.der_new.dup, null, asn1_dup_node(PrKDFentry.structure_new, ""), null);
            PUKDF ~= PKCS15_ObjectTyp(puPosEnd, cast(int)(puPosEnd+PuKDFentry.der_new.length), PuKDFentry.der_new.dup, null, asn1_dup_node(PuKDFentry.structure_new, ""), null);
            PrKDFentry.der       = PRKDF[$-1].der;
            asn1_delete_structure(&PrKDFentry.structure);
            PrKDFentry.structure = PRKDF[$-1].structure;

            PuKDFentry.der       = PUKDF[$-1].der;
            asn1_delete_structure(&PuKDFentry.structure);
            PuKDFentry.structure = PUKDF[$-1].structure;

            enum string commands = `
            int rv;
            // from tools/pkcs15-init.c  main
            sc_pkcs15_card*  p15card;
            sc_profile*      profile;
            const(char)*     opt_profile      = "acos5_64"; //"pkcs15";
            const(char)*     opt_card_profile = "acos5_64";
            sc_file*         file;

            sc_pkcs15init_set_callbacks(&my_pkcs15init_callbacks);

            /* Bind the card-specific operations and load the profile */
            rv= sc_pkcs15init_bind(card, opt_profile, opt_card_profile, null, &profile);
            if (rv < 0)
            {
                printf("Couldn't bind to the card: %s\n", sc_strerror(rv));
                return IUP_DEFAULT; //return 1;
            }
            rv = sc_pkcs15_bind(card, &aid, &p15card);

            file = sc_file_new();
            scope(exit)
            {
                if (file)
                    sc_file_free(file);
                if (profile)
                    sc_pkcs15init_unbind(profile);
                if (p15card)
                    sc_pkcs15_unbind(p15card);
            }

            // update PRKDF and PUKDF; essential: don't allow to be called if the files aren't sufficiently sized
            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &prkdf.data[8], prkdf.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);
            if (rv >= 0 && PrKDFentry.der_new.length)
                rv = sc_update_binary(card, prPosEnd, PrKDFentry.der_new.ptr, PrKDFentry.der_new.length, 0);
            assert(rv==PrKDFentry.der_new.length);

            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &pukdf.data[8], pukdf.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);
            if (rv >= 0 && PuKDFentry.der_new.length)
                rv = sc_update_binary(card, puPosEnd, PuKDFentry.der_new.ptr, PuKDFentry.der_new.length, 0);
            assert(rv==PuKDFentry.der_new.length);

            FCISEInfo  info2;
            rv= acos5_64_short_select(card, fidRSAprivate.getub2, &info2, rbuf_priv);
            assert(rv == SC_SUCCESS); // the file should exist now: it was created by the C_GenerateKeyPair call
            info_priv[24..32] = info2.sac[];
            info2 = FCISEInfo.init;
            rv= acos5_64_short_select(card, fidRSApublic.getub2,  &info2, rbuf_publ);
            assert(rv == SC_SUCCESS); // the file should exist now: it was created by the C_GenerateKeyPair call
            info_publ[24..32] = info2.sac[];
`;
            mixin(connect_card!commands);
            populate_info_from_getResponse(info_priv, rbuf_priv);
            populate_info_from_getResponse(info_publ, rbuf_publ);
            ubyte appdfPathLen = appdf.data[1];
            info_priv[1] = info_publ[1] = cast(ubyte)(appdfPathLen+2);
            info_priv[6] = PKCS15_FILE_TYPE.PKCS15_RSAPrivateKey;
            info_publ[6] = PKCS15_FILE_TYPE.PKCS15_RSAPublicKey;
            info_priv[8..8+appdfPathLen] = info_publ[8..8+appdfPathLen] = appdf.data[8..8+appdfPathLen];
            info_priv[8+appdfPathLen..10+appdfPathLen] = info_priv[2..4];
            info_publ[8+appdfPathLen..10+appdfPathLen] = info_publ[2..4];
//assumeWontThrow(writefln("%(%02X %)", info_priv));
//assumeWontThrow(writefln("%(%02X %)", info_publ));
//            auto iter = new itTypeFS(appdf);
            auto pos_priv = fs.insertAsChildLast(appdf, info_priv);
            auto pos_publ = fs.insertAsChildLast(appdf, info_publ);
            auto tr = cast(iup.iup_plusD.Tree) AA["tree_fs"];
            int id_appdf, rv;
            with (tr)
            {
                id_appdf = GetId(appdf);
                SetStringId(IUP_ADDLEAF, id_appdf, assumeWontThrow(format!" %04X  %s"(ub22integral(info_publ[2..4]),
                  file_type(2, cast(EFDB)info_publ[0], ub22integral(info_publ[2..4]), info_publ[4..6]))) ~"    "~pkcs15_names[info_publ[6]][0]);
                rv = SetUserId(id_appdf+1, pos_publ);
                assert(rv);
                SetAttributeId("TOGGLEVALUE", id_appdf+1, info_publ[7]==5? IUP_ON : IUP_OFF);
//                SetAttributeId(IUP_IMAGE,     id_appdf+1, "IUP_IMGBLANK");
                SetAttributeId(IUP_IMAGE,     id_appdf+1, IUP_IMGBLANK);

                SetStringId(IUP_ADDLEAF, id_appdf, assumeWontThrow(format!" %04X  %s"(ub22integral(info_priv[2..4]),
                  file_type(2, cast(EFDB)info_priv[0], ub22integral(info_priv[2..4]), info_priv[4..6]))) ~"    "~pkcs15_names[info_priv[6]][0]);
                rv = SetUserId(id_appdf+1, pos_priv);
                assert(rv);
                SetAttributeId("TOGGLEVALUE", id_appdf+1, info_priv[7]==5? IUP_ON : IUP_OFF);
//                SetAttributeId(IUP_IMAGE,     id_appdf+1, "IUP_IMGBLANK");
                SetAttributeId(IUP_IMAGE,     id_appdf+1, IUP_IMGBLANK);
            }
/+
            foreach (id; 0..tr.GetInteger("COUNT")) {
                auto nodeFS = cast(tnTypePtr) tr.GetUserId(id);
                assumeWontThrow(writefln("%d  %s   %(%02X %)", id, tr.GetAttributeId("TITLE", id).fromStringz, nodeFS? nodeFS.data : ub32.init));
            }
+/
            // change the choice leaving 'create'  TODO check if this is necessary
            AA["toggle_RSA_PrKDF_PuKDF_change"].SetIntegerVALUE(1);
            toggle_radioKeyAsym_cb(AA["toggle_RSA_PrKDF_PuKDF_change"].GetHandle, 1);
            keyAsym_Id.set(keyAsym_IdCurrent, true);
            hstat.SetString(IUP_TITLE, "SUCCESS: RSA_key_pair_create_and_generate");
            GC.collect(); // just a check
+/
            return IUP_DEFAULT; // case "toggle_RSA_key_pair_create_and_generate"

        case "toggle_RSA_key_pair_try_sign":
            version(none) { // THE scope for all referring to the connection via libp11 and openssl engine "pkcs11"; will show up in debug log as opensc-pkcs11
/*
	"dependencies": {
		"p11:deimos": "~>0.0.3"
		"p11:deimos": "~>0.0.3",
	}
*/
    /* prepare for routing an OpenSSL password request to IupGetParam and result back to OpenSSL */
    /* https://curl.haxx.se/mail/lib-2013-08/0196.html */
            import deimos.p11;
            import deimos.openssl.err : ERR_reason_error_string, ERR_get_error;
            import deimos.openssl.obj_mac : NID_sha256;
            import deimos.openssl.ui;
            import deimos.openssl.engine;
            import deimos.openssl.rsa;
//            assumeWontThrow(writeln("EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES: ", EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES));
//            rsa_oaep_params_st xy;
//            xy.maskHash = null;
            PKCS11_CTX* ctx_p11 = PKCS11_CTX_new();
            scope(exit)
                PKCS11_CTX_free(ctx_p11);

            int ret;
            /* load pkcs #11 module */
            /* actually the p11-kit configuration will point to opensc-pkcs11.so as PKCS#11 library: It's definded with highest priority */
            if ((ret= PKCS11_CTX_load(ctx_p11, "/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so")) != 0) {
                assumeWontThrow(stderr.writefln("loading pkcs11 engine failed: %s",
                    fromStringz(ERR_reason_error_string(ERR_get_error()))));
//                    ret = 1;
                return IUP_DEFAULT; //goto nolib;
            }
            scope(exit)
                PKCS11_CTX_unload(ctx_p11);

            /* get information on all slots */
            PKCS11_SLOT* slots;
            uint nslots;
            if ((ret= PKCS11_enumerate_slots(ctx_p11, &slots, &nslots)) < 0) {
                assumeWontThrow(stderr.writeln("no slots available"));
//                ret = 2;
                return IUP_DEFAULT; //goto noslots;
            }
            scope(exit)
                PKCS11_release_all_slots(ctx_p11, slots, nslots);

            /* get first slot with a token */
            PKCS11_SLOT* slot = PKCS11_find_token(ctx_p11, slots, nslots);
            if (slot == null || slot.token == null) {
                assumeWontThrow(stderr.writeln("no token available"));
//                ret = 3;
                return IUP_DEFAULT; //goto notoken;
            }

            /* we are going to sign with a private key from hardware token. The usage of private key for cryptograhic ops is supposed to be protected by a pin.
               one method of supplying a pin to the pkcs11 engine is by using the control command (what we'll do now
               another methof would be to use UI_create_method
            */

            // extern(C) int get_pin_callback(sc_profile* profile, int /*id*/, const(sc_pkcs15_auth_info)* info, const(char)* label, ubyte* pinbuf, size_t* pinsize) nothrow
            int  pinLocal = 1;//(info.attrs.pin.reference&0x80)==0x80;
            int  pinReference = 1;//info.attrs.pin.reference&0x7F; // strip the local flag
            char[33]  pinbuf;
            // pinbuf[0..9] = '\0';

            ret = IupGetParam(toStringz("Login Pin requested"),
                null/* &param_action*/, null/* void* user_data*/, /*format*/
                "&Pin local (User)? If local==No, then it's the Security Officer Pin:%b[No,Yes]\n" ~
                "&Pin reference (1-31; selects the record# in pin file):%i\n" ~
                "Pin (minLen: 4, maxLen: 8):%s\n", &pinLocal, &pinReference, pinbuf.ptr, null);
            if (ret != 1)
                return IUP_DEFAULT; //return SC_ERROR_INVALID_PIN_LENGTH;
            assumeWontThrow(stderr.writefln("Pin: %s", pinbuf));

            /* perform pkcs #11 login */
            if ((ret= PKCS11_login(slot, 0, pinbuf.ptr)) != 0) {
                assumeWontThrow(stderr.writeln("PKCS11_login failed"));
//                ret = 10;
                return IUP_DEFAULT; //goto failed;
            }

            int logged_in;
            /* check if user is logged in */
            if ((ret= PKCS11_is_logged_in(slot, 0, &logged_in)) != 0) {
                assumeWontThrow(stderr.writeln("PKCS11_is_logged_in failed"));
//                ret = 11;
                return IUP_DEFAULT; //goto failed;
            }
            if (!logged_in) {
                assumeWontThrow(stderr.writeln("PKCS11_is_logged_in says user is not logged in, expected to be logged in"));
//                ret = 12;
                return IUP_DEFAULT; //goto failed;
            }

            PKCS11_KEY* prkey;
            PKCS11_KEY* keys;
            uint nkeys;
            if ((ret= PKCS11_enumerate_keys(slot.token, &keys, &nkeys)) != 0) {
                assumeWontThrow(stderr.writeln("PKCS11_login failed"));
//                ret = 13;
                return IUP_DEFAULT; //goto failed;
            }
            foreach (i; 0..nkeys)
                with (keys+i)
                if (isPrivate && *id == keyAsym_Id.get && id_len==1) {
                    prkey = keys+i;
                    assumeWontThrow(writeln("prkey.label: ", fromStringz(prkey.label)));
                    break;
                }
            if (prkey is null) {
                assumeWontThrow(writeln("prkey is null"));
                return IUP_DEFAULT; //goto failed;
            }

            ubyte[32] hash = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
                              21,22,23,24,25,26,27,28,29,30,31,32];
            ubyte[512] sigret;
            uint  siglen;
            ret = PKCS11_sign(NID_sha256, hash.ptr, hash.length, sigret.ptr, &siglen, prkey);
            assert(ret == 1);
            }
//          hstat.SetString(IUP_TITLE, "SUCCESS: Signature generation and encryption of signature, printed to stdout. The key is capable to decrypt");
            hstat.SetString(IUP_TITLE, "SUCCESS: Signature generation");
/+ + /
            /* convert the 'textual' hex to an ubyte[] hex (first 64 chars = 32 byte) ; sadly std.conv.hexString works for literals only */
            string tmp_str = AA["hash_to_be_signed"].GetStringVALUE();
            tmp_str.length = 64;
            auto prefix_sha1   = (cast(immutable(ubyte)[])hexString!"30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14");
            auto prefix_sha256 = (cast(immutable(ubyte)[])hexString!"30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20");

            ubyte[] digestInfo = prefix_sha256 ~ string2ubaIntegral(tmp_str)[0..32];
////            assumeWontThrow(writefln("\n### digestInfo_to_be_signed: %(%02X %)", digestInfo));
//            auto       pos_parent = new sitTypeFS(appdf);
            tnTypePtr  prFile, puFile;
            try
            {
                prFile = fs.rangeSiblings(appdf).locate!"equal(a.data[2..4], b[])"(fidRSAprivate.getub2);
                puFile = fs.rangeSiblings(appdf).locate!"equal(a.data[2..4], b[])"(fidRSApublic.getub2);
            }
            catch (Exception e) { printf("### Exception in button_radioKeyAsym_cb() for toggle_RSA_key_pair_try_sign\n"); return IUP_DEFAULT; /* todo: handle exception */ }
            assert(prFile && puFile);

            CardCtl_generate_crypt_asym  cga = { file_id_pub: fidRSApublic.getushort(), perform_mse: true };
            enum string commands = `
            int rv;
            // from tools/pkcs15-init.c  main
            sc_pkcs15_card*  p15card;
            sc_profile*      profile;
            const(char)*     opt_profile      = "acos5_64"; //"pkcs15";
            const(char)*     opt_card_profile = "acos5_64";
            sc_file*         file;

            sc_pkcs15init_set_callbacks(&my_pkcs15init_callbacks);

            /* Bind the card-specific operations and load the profile */
            rv= sc_pkcs15init_bind(card, opt_profile, opt_card_profile, null, &profile);
            if (rv < 0)
            {
                printf("Couldn't bind to the card: %s\n", sc_strerror(rv));
                return IUP_DEFAULT; //return 1;
            }
            rv = sc_pkcs15_bind(card, &aid, &p15card);

            file = sc_file_new();
            scope(exit)
            {
                if (file)
                    sc_file_free(file);
                if (profile)
                    sc_pkcs15init_unbind(profile);
                if (p15card)
                    sc_pkcs15_unbind(p15card);
            }

            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &prFile.data[8], prFile.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_GENERATE);
            if (rv < 0)
                return IUP_DEFAULT;

            {
                sc_security_env  env; // = { /*SC_SEC_ENV_ALG_PRESENT |*/ SC_SEC_ENV_FILE_REF_PRESENT, SC_SEC_OPERATION_SIGN, SC_ALGORITHM_RSA };
                with (env)
                {
                    operation = SC_SEC_OPERATION_SIGN;
                    flags     = /*SC_SEC_ENV_ALG_PRESENT |*/ SC_SEC_ENV_FILE_REF_PRESENT;
                    algorithm = SC_ALGORITHM_RSA;
                    file_ref.len         = 2;
                    file_ref.value[0..2] = fidRSAprivate.getub2;
                }
                if ((rv= sc_set_security_env(card, &env, 0)) < 0)
                {
                    mixin (log!(__FUNCTION__,  "sc_set_security_env failed for SC_SEC_OPERATION_SIGN"));
                    hstat.SetString(IUP_TITLE, "sc_set_security_env failed for SC_SEC_OPERATION_SIGN");
                    return IUP_DEFAULT;
                }
            }

            auto sigLen = cast(ushort)keyAsym_RSAmodulusLenBits.get/8;
            // 512 bit key is to short for sha384 and sha512, thus require at least 768 bit if those will be allowed too; here it's okay: sha256 32 + digestheader 19 +11 < 64
            ubyte[] signature = new ubyte[sigLen];
//            ubyte[32] data = iota(ubyte(1), ubyte(33), ubyte(1)).array[]; // simulates a SHA256 hash
            if ((rv= sc_compute_signature(card, digestInfo.ptr, digestInfo.length, signature.ptr, signature.length)) != sigLen)
            {
                    mixin (log!(__FUNCTION__,  "sc_compute_signature failed"));
                    hstat.SetString(IUP_TITLE, "sc_compute_signature failed");
                    return IUP_DEFAULT;
            }
            hstat.SetString(IUP_TITLE, "SUCCESS: Signature generation, printed to stdout");
            assumeWontThrow(writefln("### signature: %(%02X %)", signature));

            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &puFile.data[8], puFile.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_GENERATE);
            if (rv < 0)
                return IUP_DEFAULT;

//            ubyte[]  encryptedSignature = new ubyte[sigLen];
            cga.data_len = sigLen;
            cga.data[0..sigLen] = signature[0..sigLen];

            rv= sc_card_ctl(card, SC_CARDCTL_ACOS5_ENCRYPT_ASYM, &cga);
            if (rv < 0)
                return IUP_DEFAULT;
            assert(equal(cga.data[sigLen-digestInfo.length..sigLen], digestInfo[]));
            hstat.SetString(IUP_TITLE, "SUCCESS: Signature generation and signature verification (same hash), printed to stdout");
            assumeWontThrow(writefln("### encrypted signature: %(%02X %)", cga.data[0..sigLen] /*encryptedSignature*/));
            // strip PKCS#1-v1.5 padding01 and digestInfo/oid from encryptedSignature
//            encryptedSignature = encryptedSignature[1..$];
//            encryptedSignature = find(encryptedSignature, 0);
//            encryptedSignature = encryptedSignature[1..$];
//            encryptedSignature = encryptedSignature[encryptedSignature[3]+6..$];
//            assert(equal(hash[], encryptedSignature));
            assumeWontThrow(writefln("### encrypted signature, padding and digestInfo/oid stripped: %(%02X %)", cga.data[sigLen-digestInfo.length+19..sigLen] /*encryptedSignature*/));
/+
            // try encryption and decryption
            ubyte[] ciphertext = new ubyte[sigLen];
            ubyte[] msg        = new ubyte[sigLen];
            msg[$-hash.length..$] = hash[0..$];
            msg[$-hash.length -1] = 0;
            msg[0]                = 0;
            msg[1]                = 2;
            import std.range : generate, takeExactly;
            import std.random;
            auto PSLen = cast(ushort)(sigLen -32 -3);
            // use self-made padding
            assumeWontThrow(msg[2..2+PSLen] = generate!(() => uniform!"[]"(ubyte(1), ubyte(255))).takeExactly(PSLen).array);

            {
                sc_security_env  env; // = { SC_SEC_ENV_ALG_PRESENT | SC_SEC_ENV_FILE_REF_PRESENT, SC_SEC_OPERATION_ENCIPHER_RSAPUBLIC, SC_ALGORITHM_RSA };
                with (env)
                {
                    operation = SC_SEC_OPERATION_ENCIPHER_RSAPUBLIC;
                    flags     = /*SC_SEC_ENV_ALG_PRESENT |*/ SC_SEC_ENV_FILE_REF_PRESENT;
//                    algorithm = SC_ALGORITHM_RSA;
                    file_ref.len         = 2;
                    file_ref.value[0..2] = fidRSApublic.getub2;
                }
                if ((rv= sc_set_security_env(card, &env, 0)) < 0)
                {
                    mixin (log!(__FUNCTION__,  "sc_set_security_env failed for SC_SEC_OPERATION_ENCIPHER_RSAPUBLIC"));
                    hstat.SetString(IUP_TITLE, "sc_set_security_env failed for SC_SEC_OPERATION_ENCIPHER_RSAPUBLIC");
                    return IUP_DEFAULT;
                }
            }
            /* the acos command for verifying a signature is very limited in that it works only for signatures created from a SHA1 hash.
               Thus the driver doesn't implement that and anyway, it's better done in opensc with openssl
               but cry_pso_7_4_3_8_2A_asym_encrypt_RSA can do similar for "verification", the last hashLen bytes are the ones to compare: */
            rv= cry_pso_7_4_3_8_2A_asym_encrypt_RSA(card, msg, ciphertext);
//            rv= sc_card_ctl(card, SC_CARDCTL_ACOS5_ENCRYPT_ASYM, &cga);
            if (rv < 0)
                return IUP_DEFAULT;
            assumeWontThrow(writefln("\n### encrypted hash (with 'self-made' padding): %(%02X %)", ciphertext));

            {
                sc_security_env  env; // = { SC_SEC_ENV_ALG_PRESENT | SC_SEC_ENV_FILE_REF_PRESENT, SC_SEC_OPERATION_DECIPHER, SC_ALGORITHM_RSA };
                with (env)
                {
                    operation = SC_SEC_OPERATION_DECIPHER;
                    flags     = SC_SEC_ENV_ALG_PRESENT | SC_SEC_ENV_FILE_REF_PRESENT;
                    algorithm = SC_ALGORITHM_RSA;
                    file_ref.len         = 2;
                    file_ref.value[0..2] = fidRSAprivate.getub2;
                }
                if ((rv= sc_set_security_env(card, &env, 0)) < 0)
                {
                    mixin (log!(__FUNCTION__,  "sc_set_security_env failed for SC_SEC_OPERATION_DECIPHER"));
                    hstat.SetString(IUP_TITLE, "sc_set_security_env failed for SC_SEC_OPERATION_DECIPHER");
                    return IUP_DEFAULT;
                }
            }
            ubyte[] msg2 = new ubyte[sigLen];
            if ((rv= sc_decipher(card, ciphertext.ptr, ciphertext.length, msg2.ptr, msg2.length)) <= 0)
            {
                mixin (log!(__FUNCTION__,  "sc_decipher failed; probably the key is not capable to decrypt"));
                hstat.SetString(IUP_TITLE, "sc_decipher failed; probably the key is not capable to decrypt; sign and verify was okay!");
                return IUP_DEFAULT;
            }
            assert(equal(msg, msg2));
            assumeWontThrow(writefln("### decrypted hash padded: %(%02X %)", msg2));
            // strip PKCS#1-v1.5 padding02 from msg2
            msg2 = msg2[1..$];
            msg2 = find(msg2, 0);
            msg2 = msg2[1..$];
            assumeWontThrow(writefln("### decrypted hash, padding stripped: %(%02X %)", msg2));
+/
            hstat.SetString(IUP_TITLE, "SUCCESS: Signature generation and encryption of signature, printed to stdout. The key is capable to decrypt");
`;
            mixin (connect_card!commands);
/ + +/
            GC.collect(); // just a check

            return IUP_DEFAULT; // case "toggle_RSA_key_pair_try_sign"

        default:  assert(0);
    } // switch (activeToggle)
} // button_radioKeyAsym_cb
