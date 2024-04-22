/*
 * key_sym.d: Program acos5_gui's 'AES/3DES/DES key handling' file
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

module key_sym;

import core.memory : GC;
import core.stdc.stdlib : exit;
import core.stdc.string : memcpy;
import std.stdio;
import std.exception : assumeWontThrow, assumeUnique;
import std.conv: to, hexString;
import std.format;
import std.range : iota, chunks;/*, indexed, chain*/
import std.range.primitives : empty, popFront, front;
import std.algorithm.comparison : among/*, clamp*/, equal, min, max, either;
import std.algorithm.searching : canFind, countUntil, all, any, find, startsWith;
import std.algorithm.iteration : each;
import std.algorithm.mutation : remove;
import std.typecons : Tuple, tuple;
import std.signals;
import std.traits : EnumMembers;

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

import util_opensc : connect_card, readFile, decompose, PKCS15Path_FileType, pkcs15_names,
    PKCS15_FILE_TYPE, fs, SKDF, AODF,
    PKCS15_ObjectTyp, errorDescription, PKCS15, appdf,
    tnTypePtr, aid, is_ACOSV3_opmodeV3_FIPS_140_2L3,
    my_pkcs15init_callbacks, tlv_Range_mod, file_type, getIdentifier, is_ACOSV3_opmodeV3_FIPS_140_2L3_active, getPath;

import acos5_shared_rust : CardCtl_crypt_sym, SC_CARDCTL_ACOS5_ENCRYPT_SYM, SC_CARDCTL_ACOS5_DECRYPT_SYM,
    BLOCKCIPHER_PAD_TYPE_PKCS5, BLOCKCIPHER_PAD_TYPE_ZEROES;

//import wrapper.libtasn1 : asn1_node;
//import pkcs11;

import deimos.openssl.des : DES_KEY_SZ, DES_cblock, DES_set_odd_parity, DES_is_weak_key;

// tag types, Obs
struct _keySym_algoStore{}
struct _keySym_keyRef{}

enum isEVO = false;

enum skLabel  = ".commonObjectAttributes.label";
enum skFlags  = ".commonObjectAttributes.flags";
enum skAuthId = ".commonObjectAttributes.authId";
enum skID     = ".commonKeyAttributes.iD";
enum skUsage  = ".commonKeyAttributes.usage";
enum skKeyRef = ".commonKeyAttributes.keyReference";
enum skKeyLen = ".commonSecretKeyAttributes.keyLen";
enum skPath   = ".genericSecretKeyAttributes.value.indirect.path.path";
enum skRecNo  = ".genericSecretKeyAttributes.value.indirect.path.index";

enum /* matrixKeySymRowName */
{
    r_keySym_Id = 1,                    // dropdown
    r_keySym_recordNo,                  // dropdown
//    r_keySym_keyRef,                  // hidden
    r_keySym_global_local,              // toggle
    r_keySym_fid,                       // readonly
    r_keySym_fidAppDir,                 // readonly

    r_keySym_Label,
    r_keySym_Modifiable,                // toggle
//    r_keySym_usageSKDF,               // hidden
    r_keySym_authId,                    // readonly

    r_keySym_algoFamily,                // dropdown,  AES or DES-based
    r_keySym_keyLenBits,                // dropdown
//    r_keySym_algoStore,               // hidden

    r_keySym_IntAuthYN,                 // toggle
    r_keySym_IntAuthUsageCounterYN,     // toggle
    r_keySym_IntAuthUsageCounterValue,

    r_keySym_ExtAuthYN,                 // toggle
    r_keySym_ExtAuthErrorCounterYN,     // toggle
    r_keySym_ExtAuthErrorCounterValue,

    r_keySym_bytesStockAES,
    r_keySym_bytesStockDES,
    r_keySym_ByteStringStore,           // readonly

    r_row_empty,                        // readonly
    r_fromfile,
    r_tofile,
    r_iv,                               // IV will be supported in OpenSC beginning from v0.20.0
    r_mode,
    r_enc_dec,
    r_change_calcSKDF,                  // readonly
    r_AC_Update_SKDF,                   // readonly
    r_AC_Update_Crypto_keySymFile,      // readonly
}

tnTypePtr   skdf;

Pub!_keySym_global_local          keySym_global_local;

Pub!_keySym_usageSKDF             keySym_usageSKDF;
Pub!_keySym_Id                    keySym_Id;
Pub!_keySym_Modifiable            keySym_Modifiable;
Pub!_keySym_authId                keySym_authId;

Pub!(_keySym_Label,string)        keySym_Label;
Pub!(_keySym_algoFamily,string)   keySym_algoFamily;
Pub!_keySym_keyLenBits            keySym_keyLenBits;

Pub!_keySym_fidAppDir             keySym_fidAppDir;
PubA2!_keySym_fid                 keySym_fid;

Pub!_keySym_ExtAuthYN             keySym_ExtAuthYN;
Pub!_keySym_ExtAuthErrorCounterYN keySym_ExtAuthErrorCounterYN;
Pub!_keySym_ExtAuthErrorCounterValue keySym_ExtAuthErrorCounterValue;
Pub!_keySym_IntAuthYN             keySym_IntAuthYN;
Pub!_keySym_IntAuthUsageCounterYN keySym_IntAuthUsageCounterYN;
Pub!_keySym_IntAuthUsageCounterValue keySym_IntAuthUsageCounterValue;

Pub!(_keySym_bytesStockAES,ubyte[32])  keySym_bytesStockAES;
Pub!(_keySym_bytesStockDES,ubyte[24])  keySym_bytesStockDES;

Pub!_keySym_recordNo              keySym_recordNo;
Obs_keySym_keyRef                 keySym_keyRef;

Obs_keySym_algoStore              keySym_algoStore;
Obs_keySym_ByteStringStore        keySym_ByteStringStore;

Obs_change_calcSKDF               change_calcSKDF;


void keySym_initialize_PubObs()
{
    /* initialze the publisher/observer system for this tab */
    // some variables are declared as publisher though they don't need to be, currently just for consistency, but that's not the most efficient way
    keySym_global_local          = new Pub!_keySym_global_local          (r_keySym_global_local,          AA["matrixKeySym"]);
    keySym_usageSKDF             = new Pub!_keySym_usageSKDF             (0/*r_keySym_usageSKDF,          AA["matrixKeySym"]*/); // visual representation removed
    keySym_Id                    = new Pub!_keySym_Id                    (r_keySym_Id,                    AA["matrixKeySym"]);
    keySym_Modifiable            = new Pub!_keySym_Modifiable            (r_keySym_Modifiable,            AA["matrixKeySym"]);
    keySym_authId                = new Pub!_keySym_authId                (r_keySym_authId,                AA["matrixKeySym"]);

    keySym_Label                 = new Pub!(_keySym_Label,string)        (r_keySym_Label,                 AA["matrixKeySym"]);
    keySym_algoFamily            = new Pub!(_keySym_algoFamily,string)   (r_keySym_algoFamily,            AA["matrixKeySym"]);
    keySym_keyLenBits            = new Pub!_keySym_keyLenBits            (r_keySym_keyLenBits,            AA["matrixKeySym"]);

    keySym_fid                   = new PubA2!_keySym_fid                 (r_keySym_fid,                   AA["matrixKeySym"]);
    keySym_fidAppDir             = new Pub!_keySym_fidAppDir             (r_keySym_fidAppDir,             AA["matrixKeySym"], true);

    keySym_ExtAuthYN             = new Pub!_keySym_ExtAuthYN             (r_keySym_ExtAuthYN,             AA["matrixKeySym"]);
    keySym_ExtAuthErrorCounterYN = new Pub!_keySym_ExtAuthErrorCounterYN (r_keySym_ExtAuthErrorCounterYN, AA["matrixKeySym"]);
    keySym_ExtAuthErrorCounterValue = new Pub!_keySym_ExtAuthErrorCounterValue (r_keySym_ExtAuthErrorCounterValue, AA["matrixKeySym"]);

    keySym_IntAuthYN             = new Pub!_keySym_IntAuthYN             (r_keySym_IntAuthYN,             AA["matrixKeySym"]);
    keySym_IntAuthUsageCounterYN = new Pub!_keySym_IntAuthUsageCounterYN (r_keySym_IntAuthUsageCounterYN, AA["matrixKeySym"]);
    keySym_IntAuthUsageCounterValue = new Pub!_keySym_IntAuthUsageCounterValue  (r_keySym_IntAuthUsageCounterValue, AA["matrixKeySym"]);

    keySym_algoStore             = new Obs_keySym_algoStore              (0/*r_keySym_algoStore,          AA["matrixKeySym"]*/); // visual representation removed
    keySym_bytesStockAES         = new Pub!(_keySym_bytesStockAES,ubyte[32])(r_keySym_bytesStockAES,      AA["matrixKeySym"]);
    keySym_bytesStockDES         = new Pub!(_keySym_bytesStockDES,ubyte[24])(r_keySym_bytesStockDES,      AA["matrixKeySym"]);
    keySym_ByteStringStore       = new Obs_keySym_ByteStringStore        (r_keySym_ByteStringStore,       AA["matrixKeySym"]);

    keySym_recordNo              = new Pub!_keySym_recordNo              (r_keySym_recordNo,              AA["matrixKeySym"]);
    keySym_keyRef                = new Obs_keySym_keyRef                 (0/*r_keySym_keyRef,             AA["matrixKeySym"]*/); // visual representation removed

    change_calcSKDF              = new Obs_change_calcSKDF               (r_change_calcSKDF,              AA["matrixKeySym"]);
//struct _AC_Update_SKDF{}       //SCB
//struct _AC_Update_keyFile{}    //SCB

//// dependencies
    keySym_Id                      .connect(&keySym_algoStore.watch); // reset keySym_algoStore
    keySym_algoFamily              .connect(&keySym_algoStore.watch);
    keySym_keyLenBits              .connect(&keySym_algoStore.watch);

    keySym_Id                      .connect(&keySym_keyRef.watch); // reset keySym_keyRef
    keySym_global_local            .connect(&keySym_keyRef.watch);
    keySym_recordNo                .connect(&keySym_keyRef.watch);

    keySym_Id                      .connect(&change_calcSKDF.watch);
    keySym_Label                   .connect(&change_calcSKDF.watch);
    keySym_Modifiable              .connect(&change_calcSKDF.watch);
    keySym_keyLenBits              .connect(&change_calcSKDF.watch);
      keySym_algoStore             .connect(&change_calcSKDF.watch);
    keySym_global_local            .connect(&change_calcSKDF.watch);
    keySym_recordNo                .connect(&change_calcSKDF.watch);
      keySym_keyRef                .connect(&change_calcSKDF.watch);

    keySym_recordNo                .connect(&keySym_ByteStringStore.watch);
      keySym_algoStore             .connect(&keySym_ByteStringStore.watch);
    keySym_bytesStockAES           .connect(&keySym_ByteStringStore.watch);
    keySym_bytesStockDES           .connect(&keySym_ByteStringStore.watch);
    keySym_ExtAuthYN               .connect(&keySym_ByteStringStore.watch);
    keySym_IntAuthYN               .connect(&keySym_ByteStringStore.watch);
    keySym_ExtAuthErrorCounterYN   .connect(&keySym_ByteStringStore.watch);
    keySym_IntAuthUsageCounterYN   .connect(&keySym_ByteStringStore.watch);
    keySym_ExtAuthErrorCounterValue.connect(&keySym_ByteStringStore.watch);
    keySym_IntAuthUsageCounterValue.connect(&keySym_ByteStringStore.watch);
    keySym_fid                     .connect(&keySym_ByteStringStore.watch);

//// values to start with
    keySym_IntAuthUsageCounterValue.set(0xFFFE, true);
    keySym_ExtAuthErrorCounterValue.set(0x0E, true);

    ubyte[32] tmp= [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
    keySym_bytesStockAES.set(tmp, true);
    foreach (i; 0..3/*keyLen/blocksize*/) // TODO replace see
    {
        auto p = cast(DES_cblock*)(tmp.ptr+i*DES_KEY_SZ);
        DES_set_odd_parity (p);
        if (DES_is_weak_key(p) == 1)
        {    assert(0); }
    }
    keySym_bytesStockDES.set(tmp[0..24], true);
    // set colours
    toggle_radioKeySym_cb(AA["toggle_sym_SKDF_change"].GetHandle, 1); // was set to active already
}


class Obs_keySym_keyRef
{
    mixin(commonConstructor);

    void watch(string msg, int v)
    {
        switch(msg)
        {
            case "_keySym_Id":
                _keySym_global_local = 2;
                _keySym_recordNo     = 0;
                break;
            case "_keySym_recordNo":
                  _keySym_recordNo = v;
                break;
            case "_keySym_global_local":
                  _keySym_global_local = v;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        _value = _keySym_recordNo | (_keySym_global_local? 0x80 : 0);
//writefln("  "~typeof(this).stringof~" object was set to value 0x%02X", _value);
        if (_keySym_global_local!=2 && _keySym_recordNo)
        {
////writefln("  "~typeof(this).stringof~" object was set to value 0x%02X", _value);
            emit("_keySym_keyRef", _value);
        }

        if (_h !is null)
        {
            _h.SetStringId2 ("", _lin, _col, format!"%02X"(_value));
            _h.Update;
        }
    }

    mixin Pub_boilerplate!(_keySym_keyRef, int);

    private :
    int    _keySym_global_local = 2;
    int    _keySym_recordNo;
} // class Obs_keySym_keyRef


class Obs_keySym_algoStore
{
    mixin(commonConstructor);

    void watch(string msg, string v)
    {
        switch(msg)
        {
            case "_keySym_algoFamily":
                  _keySym_algoFamily = v;
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
            case "_keySym_Id":
                  _keySym_algoFamily   = "";
                  _keySym_keyLenBits = 0;
                break;
            case "_keySym_keyLenBits":
                  _keySym_keyLenBits = v;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        calculate();
    }

    void calculate()
    {
//desKey,  0x05
//des2Key, 0x04  assuming this denotes  128-bit 3DES
//des3Key, 0x14  assuming this denotes  192-bit 3DES
// thus for the des types, the naming includes the keyLen, whereas aes has 1 name, but 3 different possible keyLen
//aesKey,  0x02, 0x12, 0x22
        switch (_keySym_keyLenBits)
        {
            case  64:  _value = _keySym_algoFamily=="DES"? (isEVO? 0x11 : 0x05) : (isEVO? 0x22 : 0x02); break;
            case 128:  _value = _keySym_algoFamily=="DES"? (isEVO? 0x12 : 0x04) : (isEVO? 0x22 : 0x02); break;
            case 192:  _value = _keySym_algoFamily=="DES"? (isEVO? 0x14 : 0x14) : (isEVO? 0x24 : 0x12); break;
            case 256:  _value = _keySym_algoFamily=="DES"? (isEVO? 0x14 : 0x14) : (isEVO? 0x28 : 0x22); break;
            default:  goto case 192; // as long as _keySym_keyLenBits wasn't set
        }
////writefln("  "~typeof(this).stringof~" object was set to value 0x%02X", _value);
        if (_keySym_keyLenBits && !_keySym_algoFamily.empty)
        {
////writefln("  "~typeof(this).stringof~" object was set to value 0x%02X", _value);
            emit("_keySym_algoStore", _value);
        }

        if (_h !is null)
        {
            _h.SetStringId2 ("", _lin, _col, format!"0x%02X"(_value));
            _h.Update;
        }
    }

    mixin Pub_boilerplate!(_keySym_algoStore, int);
//  alias _value this;

    private :
        string  _keySym_algoFamily;
        int     _keySym_keyLenBits;
} // class Obs_keySym_algoStore


class Obs_keySym_ByteStringStore
{
    mixin(commonConstructor);

    @property ubyte[38] get()    const @nogc nothrow /*pure*/ @safe { return _value; }
    @property int       getLen() const @nogc nothrow /*pure*/ @safe { return _len; }

    void watch(string msg, int v)
    {
        switch(msg)
        {
            case "_keySym_recordNo":
                  _keySym_recordNo = v;
                break;
            case "_keySym_algoStore":
                  _keySym_algoStore = v;
                break;
            case "_keySym_ExtAuthYN":
                  _keySym_ExtAuthYN = v;
                break;
            case "_keySym_IntAuthYN":
                  _keySym_IntAuthYN = v;
                break;
            case "_keySym_ExtAuthErrorCounterYN":
                  _keySym_ExtAuthErrorCounterYN = v;
                break;
            case "_keySym_IntAuthUsageCounterYN":
                  _keySym_IntAuthUsageCounterYN = v;
                break;
            case "_keySym_ExtAuthErrorCounterValue":
                _keySym_ExtAuthErrorCounterValueMod = v | v<<4;
                break;
            case "_keySym_IntAuthUsageCounterValue":
                  _keySym_IntAuthUsageCounterValue = v;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        calculate();
    }

    void watch(string msg, ubyte[32] v)
    {
        switch(msg)
        {
            case "_keySym_bytesStockAES":
                  _keySym_bytesStockAES = v;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        calculate();
    }

    void watch(string msg, ubyte[24] v)
    {
        switch(msg)
        {
            case "_keySym_bytesStockDES":
                  _keySym_bytesStockDES = v;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        calculate();
    }

    void watch(string msg, int[2] v)
    {
        switch(msg)
        {
            case "_keySym_fid":
                _keySym_fid_MRL = v[1];
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        calculate();
    }

    void calculate()
    {
        immutable _keySym_keyLenBytes =  keyLenBytesfromAlgoKeySym(_keySym_algoStore);
        _value = _value.init;
        _value[0] = 0x80 | cast(ubyte) _keySym_recordNo; // valid and key id (1-31) // Key ID 1 byte

        if (ctxTagNofromAlgoKeySym(_keySym_algoStore) != CtxTagNo.genericSecretKey /*.aesKey*/) // with AES, IntAuth and ExtAuth is unusable  TODO prevent that it can be set then
            _value[1] = cast(ubyte) (2*_keySym_IntAuthYN + _keySym_ExtAuthYN); // IntAuth and/or ExtAuth // Key Type 1 byte
        // Key Info  0-3 byte
        if (_keySym_IntAuthYN && _value[1]) // first UsageCounter, then ErrorCounterValueMod
            _value[2..4] = integral2uba!2(_keySym_IntAuthUsageCounterYN? _keySym_IntAuthUsageCounterValue : 0xFFFF)[0..2];
        if (_keySym_ExtAuthYN && _value[1])
            _value[2+2*_keySym_IntAuthYN] = cast(ubyte) (_keySym_ExtAuthErrorCounterYN? _keySym_ExtAuthErrorCounterValueMod : 0xFF);

        ubyte algoPos = cast(ubyte) (2+_value[1]); // 81 01 FF 14   010203...
        _value[algoPos] = cast(ubyte) _keySym_algoStore; // Algorithm Reference 1 byte
        _len = algoPos+1;
        if (blocksizefromAlgoKeySym(_keySym_algoStore)==16)
            _value[_len.._len+_keySym_keyLenBytes] = _keySym_bytesStockAES[0.._keySym_keyLenBytes];
        else
            _value[_len.._len+_keySym_keyLenBytes] = _keySym_bytesStockDES[0.._keySym_keyLenBytes];
        _len += _keySym_keyLenBytes;
        if (_len < _keySym_fid_MRL) {
            _value[_len.._keySym_fid_MRL] = 0;
            _len = _keySym_fid_MRL;
        }
////writefln("  "~typeof(this).stringof~" object was set to value 0x %(%02X %)", _value[0.._len]);

        if (_h !is null)
        {
            _h.SetStringId2 ("", _lin, _col, ubaIntegral2string(_value[0.._len]));
            _h.Update;
        }
    }

    private :
    int        _keySym_recordNo;
    int        _keySym_algoStore =5;
    ubyte[32]  _keySym_bytesStockAES;
    ubyte[24]  _keySym_bytesStockDES;
    int        _keySym_ExtAuthYN;
    int        _keySym_IntAuthYN;
    int        _keySym_ExtAuthErrorCounterYN;
    int        _keySym_IntAuthUsageCounterYN;
    int        _keySym_ExtAuthErrorCounterValueMod;
    int        _keySym_IntAuthUsageCounterValue;
    int        _keySym_fid_MRL;

    int        _len;
    ubyte[38]  _value; // why 38 and not 37 ?
    int    _lin;
    int    _col;
    Handle _h;
} // class Obs_keySym_ByteStringStore

class Obs_change_calcSKDF
{
    mixin(commonConstructor);

    static string asn1Read(string what, string where)
    {
    //return `writeln("` ~ message ~ `");`;
        return `asn1_result = asn1_read_value(_SKDFentry.structure_new, skChoiceName(ctn)~"` ~ what ~ `", ` ~ where ~ `, outLen);`;
    }

    static string asn1ReadRep(string what)
    {
        return `writeln("### asn1_read_value "~skChoiceName(ctn)~"` ~ what ~ `"~": ", asn1_strerror2(asn1_result));`;
    }

    static string asn1Write(string what, string where, string Len)
    {
        return `asn1_result = asn1_write_value(_SKDFentry.structure_new, (skChoiceName(ctn)~"` ~ what ~ `").toStringz, ` ~ where ~ `.ptr, cast(int)`~Len~`);`;
    }//                       asn1_write_value(_SKDFentry.structure_new, (skChoiceName(ctn)~skKeyLen).toStringz, tmp.ptr, cast(int)tmp.length);

    static string asn1WriteRep(string what)
    {
        return `writeln("### asn1_write_value "~skChoiceName(ctn)~"` ~ what ~ `"~": ", asn1_strerror2(asn1_result));`;
    }


    @property      CtxTagNo          getctn()           @nogc nothrow /*pure*/ @safe { return  ctn; }
    @property  ref PKCS15_ObjectTyp  pkcs15_ObjectTyp() @nogc nothrow /*pure*/ @safe { return  _SKDFentry; }
    @property      const(int)        get()        const @nogc nothrow /*pure*/ @safe { return  _value; }
    @property      void              setIsNewKeyId()    @nogc nothrow /*pure*/ @safe { isNewKeyId = true; }
//
    void watch(string msg, int v)
    {
        import std.string : toStringz;
        import wrapper.libtasn1 : ASN1_SUCCESS, asn1_strerror2, asn1_write_value;
        int asn1_result;
        int outLen;
        switch (msg)
        {
            case "_keySym_Id":
                import wrapper.libtasn1 : asn1_create_element, asn1_dup_node, asn1_delete_structure, asn1_der_decoding, asn1_der_coding, asn1_read_value;
                if (_SKDFentry.structure_new !is null)
                    asn1_delete_structure(&_SKDFentry.structure_new);

                if (isNewKeyId)
                {
                    assert(v>0);
                    _SKDFentry = PKCS15_ObjectTyp.init;
                    _SKDFentry.der.reserve(0x36+16); // for the path correction
                        /*
                        authId must be adapted
                        */
//A4 34 30 0A 0C 01 3F 03 02 06 C0 04 01 01 30 10 04 01 00 03 03 06 C0 00 03 02 03 B0 02 02 00 00 A0 04 02 02 00 C0 A1 0E 30 0C 30 0A 04 02 3F 00 02 01 00 80 01 00
                    _SKDFentry.der = (cast(immutable(ubyte)[])hexString!"A4 34 30 0A 0C 01 3F 03 02 06 C0 04 01 01 30 10 04 01 00 03 03 06 C0 00 03 02 03 B0 02 02 00 00 A0 04 02 02 00 C0 A1 0E 30 0C 30 0A 04 02 3F 00 02 01 00 80 01 00").dup;
                    ctn = cast(CtxTagNo) (_SKDFentry.der[0]-0xA0);
////                    _SKDFentry.der[13] = cast(ubyte)keySym_authId.get; // FIXME
                    _SKDFentry.der[18] = cast(ubyte) v;
                    _SKDFentry.der[31] = cast(ubyte) (keySym_recordNo.get | (keySym_global_local.get? 0x80 : 0));
                    _SKDFentry.der[50] = cast(ubyte)  keySym_recordNo.get;

                    /* CONVENTION, profile */
                    /* ATTENTION: _SKDFentry.structure will leak memory if no write operation occurs */
                    asn1_result = asn1_create_element(PKCS15, pkcs15_names[PKCS15_FILE_TYPE.PKCS15_SKDF][1], &_SKDFentry.structure); // "PKCS15.SecretKeyType"
                    if (asn1_result != ASN1_SUCCESS)
                    {
                        writeln("### Structure creation: ", asn1_strerror2(asn1_result));
                        exit(1);
                    }

                    asn1_result = asn1_der_decoding(&_SKDFentry.structure, _SKDFentry.der, errorDescription);
                    if (asn1_result != ASN1_SUCCESS)
                    {
                        writeln("### asn1Decoding: ", errorDescription);
                        exit(1);
                    }
                    // correct der's path to local sym key file, skFile
                    tnTypePtr  skFile;
                    getNOR(skFile);
                    assert(skFile);
                    ubyte[16] path;
                    path[0..skFile.data[1]] = skFile.data[8..8+skFile.data[1]];
                    asn1_result= asn1_write_value(_SKDFentry.structure, (skChoiceName(ctn)~skPath).toStringz, path.ptr, skFile.data[1]);
                    if (asn1_result != ASN1_SUCCESS)
                    {
                        writefln("### asn1_write_value: %(%02X %)", _SKDFentry.der);
                        exit(1);
                    }
                    _SKDFentry.der.length += 16;
                    int outDerLen;
                    asn1_result = asn1_der_coding(_SKDFentry.structure, "", _SKDFentry.der, outDerLen, errorDescription);
                    if (asn1_result != ASN1_SUCCESS)
                    {
                        printf ("\n### _SKDFentry.der encoding path correction: ERROR  with Obs_change_calcSKDF\n");
                        exit(1);
                    }
                    if (outDerLen)
                        _SKDFentry.der.length = outDerLen;
                    assert(v == getIdentifier(_SKDFentry, skChoiceName(ctn)~skID));

                    _SKDFentry.posStart =  !SKDF.empty? SKDF[$ - 1].posEnd : 0;
                    _SKDFentry.posEnd   = cast(int) (_SKDFentry.posStart + _SKDFentry.der.length);
                } // if (isNewKeyId)
                else
                {
                    /* never touch/change structure or der (only structure_new and der_new), except when updating to file ! */
                    auto res = rangeExtractedSym(SKDF).find!(a => a.iD == v);
                    int iD = res.empty? 0 : res.front.iD;
                    assert(iD>0);
                    ctn = res.front.ctn;
                    _SKDFentry = res.front.elem;
                }
/* *** */
                assert(_SKDFentry.structure_new is null); // newer get's set in SKDF
                assert(_SKDFentry.der_new is null);       // newer get's set in SKDF
                _SKDFentry.structure_new = asn1_dup_node(_SKDFentry.structure, "");

////                writefln("  _old_encodedData of SKDFentry: %(%02X %)", _SKDFentry.der);
                //set_more_for_keySym_Id
//                printf("set_more_for_keySym_Id (%d)\n", v);

                updating_PubObs = true;

                ubyte[1] flags; // optional
                mixin (asn1Read(skFlags, "flags"));
                if (asn1_result != ASN1_SUCCESS)  mixin (asn1ReadRep(skFlags));
                else
                {
                    assert(outLen.among(0,1,2)); // max 2 bits
                    keySym_Modifiable.set((flags[0] & 0x40)/0x40, true);

                    immutable activeToggle = AA["radioKeySym"].GetStringVALUE();
                    if (!keySym_Modifiable.get &&  activeToggle.among("toggle_sym_delete", "toggle_sym_update", "toggle_sym_updateSMkeyHost",
                        "toggle_sym_updateSMkeyCard", "toggle_sym_enc_dec") )
                    {
                        IupMessage("Feedback upon setting keyId",
"The SKDF entry for the selected keyId disallows modifying the key !\nThe toggle will be changed to toggle_sym_SKDF_change toggled");
                        AA["toggle_sym_SKDF_change"].SetIntegerVALUE(1);
                        toggle_radioKeySym_cb(AA["toggle_sym_SKDF_change"].GetHandle, 1);
                    }
                }

                ubyte[1] authId; // optional  Identifier ::= OCTET STRING (SIZE (0..255))
                mixin (asn1Read(skAuthId, "authId"));
                if (asn1_result != ASN1_SUCCESS)  mixin (asn1ReadRep(skAuthId));
                else
                {
                    assert(outLen<=255);
                    if (authId[0])
                    {    assert(flags[0]&0x80); } // may run into a problem if asn1_read_value for flags failed
                    keySym_authId.set(authId[0], true);
                }

                { // make label inaccessible when leaving the scope
                    char[] label = new char[256]; // optional  Label ::= UTF8String (SIZE(0..255))
                    label[0..256] = '\0';
                    mixin (asn1Read(skLabel, "label"));
                    if (asn1_result != ASN1_SUCCESS)  mixin (asn1ReadRep(skLabel));
                    else
                        keySym_Label.set(assumeUnique(label[0..outLen]), true);
                }

                ubyte[2] keyUsageFlags; // non-optional
                mixin (asn1Read(skUsage, "keyUsageFlags"));
                if (asn1_result != ASN1_SUCCESS)  mixin (asn1ReadRep(skUsage));
                else
                {
//        assert(outLen==10); // bits
////writefln("keyUsageFlags: %(%02X %)", keyUsageFlags);
                    import core.bitop : bitswap;
                    keySym_usageSKDF.set( bitswap(ub22integral(keyUsageFlags)<<16), true);
                }

                ubyte[2] keyLength; // non-optional
                mixin (asn1Read(skKeyLen, "keyLength"));
                if (asn1_result != ASN1_SUCCESS)  mixin (asn1ReadRep(skKeyLen));
                else
                {
                  assert(outLen.among(1,2));
                  immutable keyLenBits = ub22integral(keyLength);
                  assert(keyLenBits%64==0 && keyLenBits>=64  && keyLenBits<=256);
                  keySym_keyLenBits.set(keyLenBits, true);
                }
                keySym_algoFamily.set(ctn==CtxTagNo.genericSecretKey /*.aesKey*/? "AES" : "DES", true);

                ubyte[3] index; // optional, but do require that here !  INTEGER (0..65535)
                mixin (asn1Read(skRecNo, "index"));
                if (asn1_result != ASN1_SUCCESS)  mixin (asn1ReadRep(skRecNo));
                if (asn1_result != ASN1_SUCCESS)  assert(0);
                assert(outLen.among(1,2,3));
                keySym_recordNo.set(cast(int) ub82integral(index[0..outLen]), true);

                ubyte[] path = getPath(_SKDFentry, skChoiceName(ctn)~skPath, true, false);
                assert(path.length);
                keySym_global_local.set(path.length>4, true);

                ubyte[2] keyReference; // optional  Reference ::= INTEGER (0..255)
                mixin (asn1Read(skKeyRef, "keyReference"));
                if (asn1_result != ASN1_SUCCESS)  mixin (asn1ReadRep(skKeyRef));
                else
                {
                    assert(outLen.among(1,2));
                    assert(keySym_keyRef.get == ub22integral(keyReference));
                }

                isNewKeyId = false;

                updating_PubObs = false;
                break;

            case "_keySym_Modifiable":
                if (updating_PubObs)
                    return;
                import wrapper.libtasn1 : asn1_read_value;
                ubyte[1] flags; // optional
                mixin (asn1Read(skFlags, "flags"));
                if (asn1_result != ASN1_SUCCESS)  mixin (asn1ReadRep(skFlags));
                if (asn1_result != ASN1_SUCCESS)  break;
                assert(outLen.among(0,1,2)); // max 2 bits
                ubyte[1] tmp = cast(ubyte) ((flags[0]&~0x40) | (v!=0)*0x40);
                mixin (asn1Write(skFlags, "tmp", "2")); // 2 bits
                break;

            case "_keySym_algoStore":
                if (updating_PubObs)
                    return;
                ctn = ctxTagNofromAlgoKeySym(v);
////writefln("##### ctn: %s", ctn);
                break;

            case "_keySym_keyLenBits":
                if (updating_PubObs)
                    return;
                ubyte[2] tmp = integral2uba!2(v);
                mixin (asn1Write(skKeyLen, "tmp", "tmp.length"));
                break;

            case "_keySym_global_local":
                if (updating_PubObs)
                   return;
                tnTypePtr  skFile;
                getNOR(skFile);
                assert(skFile);

                ubyte[16] tmp;
                tmp[0..skFile.data[1]] = skFile.data[8..8+skFile.data[1]];
                mixin (asn1Write(skPath, "tmp", "skFile.data[1]"));
                break;

            case "_keySym_recordNo":
                if (updating_PubObs)
                    return;
                ubyte[1] tmp = [cast(ubyte)v];
                mixin (asn1Write(skRecNo, "tmp", "tmp.length"));
               break;

            case "_keySym_keyRef":
                if (updating_PubObs)
                    return;
                ubyte[2] tmp = integral2uba!2(v);
                mixin (asn1Write(skKeyRef, "tmp", "tmp.length"));
                break;

            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        present();
    }

    void watch(string msg, string v)
    {
        import std.string : toStringz;
        import wrapper.libtasn1 : ASN1_SUCCESS, asn1_strerror2, asn1_write_value;
        int asn1_result;
        switch (msg)
        {
            case "_keySym_Label":
                if (updating_PubObs)
                    return;
                char[] label = v.dup ~ '\0';
                mixin (asn1Write(skLabel, "label", "0"));
                if (asn1_result != ASN1_SUCCESS)  mixin (asn1WriteRep(skLabel));
                break;

            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        present();
    }

    void present()
    {
        import wrapper.libtasn1 : asn1_node, ASN1_SUCCESS, asn1_der_coding, asn1_der_decoding, asn1_create_element, asn1_delete_structure, asn1_strerror2;
        _SKDFentry.der_new = new ubyte[_SKDFentry.der.length+32];
        int outDerLen;
        auto asn1_result = asn1_der_coding(_SKDFentry.structure_new, "", _SKDFentry.der_new, outDerLen, errorDescription);
        if (asn1_result != ASN1_SUCCESS)
        {
            printf ("\n### _SKDFentry.der_new encoding creation: ERROR  with Obs_change_calcSKDF\n");
//                    writeln("### asn1Coding: ", errorDescription);
            return;
        }
        if (outDerLen)
            _SKDFentry.der_new.length = outDerLen;
        _value = cast(int)(_SKDFentry.der_new.length - _SKDFentry.der.length);

        assert(ctn != CtxTagNo.unknown);
        switch (ctn) {
            case 2,3,4, 15:  _SKDFentry.der_new[0] = 0xA0|ctn; break;
            case 254:        _SKDFentry.der_new[0] = 0x30; break;
            default:         break;
        }
        if (ctn != CtxTagNo.unknown && _SKDFentry.der_new[0] != (0xA0|ctn) &&
                                       _SKDFentry.der_new[0] != 0x30)
        {
writefln("#### mismatch [0] and ctn ! ctn: %s", ctn);
            _SKDFentry.der_new[0] = 0xA0|ctn;
            asn1_node  structure_new;
            asn1_result = asn1_create_element(PKCS15, pkcs15_names[PKCS15_FILE_TYPE.PKCS15_SKDF][1], &structure_new);

            if (asn1_result != ASN1_SUCCESS)
            {
                writeln("### Structure creation: ", asn1_strerror2(asn1_result));
                return;
            }
            asn1_result = asn1_der_decoding(&structure_new, _SKDFentry.der_new, errorDescription);
            if (asn1_result != ASN1_SUCCESS)
            {
                writeln("### asn1Decoding: ", errorDescription);
                return;
            }
            asn1_delete_structure(&_SKDFentry.structure_new);
            _SKDFentry.structure_new = structure_new;
        }
//writefln("  "~typeof(this).stringof~" object was set");
//writefln("  _new_encodedData of SKDFentry: %(%02X %)", _SKDFentry.der_new);
        if (_h !is null)
        {
            _h.SetIntegerId2("", _lin, _col, _value);
            _h.Update;
        }
    }

    private :
        bool isNewKeyId;
        bool updating_PubObs;
        CtxTagNo  ctn = CtxTagNo.unknown;
        int               _value;
        PKCS15_ObjectTyp  _SKDFentry;

        int    _lin;
        int    _col;
        Handle _h;
}


struct ExtractedSym
{
    CtxTagNo ctn;
    int iD;
    int recNo;
    ubyte[] path;
    PKCS15_ObjectTyp elem;

    bool sameRecNo(int recordNo) nothrow { return recNo == recordNo; }
    bool sameGlobalLocal(int globalLocal) nothrow { return path.length == 4+2*globalLocal; }
    bool sameGlobalLocalAndRecNo(int globalLocal, int recordNo) nothrow { return sameGlobalLocal(globalLocal) && sameRecNo(recordNo); }
}

auto rangeExtractedSym(PKCS15_ObjectTyp[] skdf) nothrow
{
    struct RangeExtractedSym
    {
        void popFront() nothrow { skdf.popFront(); }
        @property bool empty() nothrow { return skdf.empty; }

        @property ExtractedSym front() nothrow
        {
            ExtractedSym es;
            try {
//    assumeWontThrow(writeln("watch point 1"));
                es.ctn = EnumMembers!CtxTagNo.either!(a => getIdentifier(skdf[0], skChoiceName(a)~skID, false, false) > 0);
//    assumeWontThrow(writeln("watch point 11"));
            }
            catch (Exception e) { printf("### Exception in rangeExtractedSym.front either\n");/* todo: handle exception */ }
            assert(es.ctn != CtxTagNo.unknown);
            es.iD = getIdentifier(skdf[0], skChoiceName(es.ctn)~skID);

            if ((es.recNo= getIdentifier(skdf[0], skChoiceName(es.ctn)~skRecNo)) < 0)
            { assert(0); }

            if ((es.path=        getPath(skdf[0], skChoiceName(es.ctn)~skPath) ) is null)
            { assert(0); }

            es.elem = skdf[0];
//    assumeWontThrow(writeln("watch point 12"));
//    assumeWontThrow(writeln("ExtractedSym es: ", es));
            return es;
        }

version(none)
        int opApply(int delegate(ExtractedSym)  dg) nothrow
        {
            int result; /* continue as long as result==0 */
            ExtractedSym es;
            foreach (elem; skdf)
            {
                try
                    es.ctn = EnumMembers!CtxTagNo.either!(a => getIdentifier(elem, skChoiceName(a)~skID, false, false) > 0);
                catch (Exception e) { printf("### Exception in rangeExtractedSym.opApply either\n"); /* todo: handle exception */ }
                assert(es.ctn != CtxTagNo.unknown);
                es.iD = getIdentifier(elem, skChoiceName(es.ctn)~skID);

                if ((es.recNo= getIdentifier(elem, skChoiceName(es.ctn)~skRecNo)) < 0)
                { assert(0); }

                if ((es.path=        getPath(elem, skChoiceName(es.ctn)~skPath) ) is null)
                { assert(0); }

                es.elem = elem;
//                assumeWontThrow(writefln("es: %s", es));

                try // allow throwing foreach bodies
                    if ((result= dg(es)) != 0)
                        break;
                catch (Exception e) { printf("### Exception in rangeExtractedSym.opApply dg(es)\n"); /* todo: handle exception */ }
            }
            return result;
        }
    }
    return RangeExtractedSym();
}
//RangeExtractedSym rangeExtractedSym(PKCS15_ObjectTyp[] skdf) nothrow { return RangeExtractedSym(skdf); }

enum CtxTagNo : ubyte
{
    des3Key = 4,
    des2Key = 3,
    desKey  = 2,
    aesKey  = 15,            // OpenSC doesn't support this context tag; use genericSecretKey instead for AES

    genericSecretKey = 254,  // this is no context tag !!!
    unknown = 255            // this is no context tag !!!
}


string skChoiceName(CtxTagNo ctxTag) nothrow
{
    try
      return ctxTag.to!string;
    catch (Exception e) { printf("### Exception in skChoiceName\n"); }
    return "";
}

unittest
{
    assert(skChoiceName(CtxTagNo.genericSecretKey)  == "genericSecretKey");
    assert(skChoiceName(CtxTagNo.aesKey)  == "aesKey");
    assert(skChoiceName(CtxTagNo.des3Key) == "des3Key");
    assert(skChoiceName(CtxTagNo.des2Key) == "des2Key");
    assumeWontThrow(writeln("PASSED: skChoiceName"));
}


int nextUniqueKeyId() nothrow
{
    import std.array : array;
    int[] keyIdAllowed = iota(1,31).array;

    rangeExtractedSym(SKDF).each!(n => keyIdAllowed = keyIdAllowed.remove!(a => a == n.iD));

    import util_opensc : PRKDF;
    PRKDF.each!(n => keyIdAllowed = keyIdAllowed.remove!(a => a == getIdentifier(n, "privateRSAKey"~skID)));
//assumeWontThrow(writeln("keyIdAllowed ", keyIdAllowed));
    return keyIdAllowed.empty? -1 : keyIdAllowed.front;
}


int getNOR(out tnTypePtr  keySym_file) nothrow
{
    ubyte NOR;
    try
    {
        keySym_file = fs.rangeSiblings(keySym_global_local.get? appdf : fs.root()).locate!"a.data[0]==b"(EFDB.Sym_Key_EF);
        if (keySym_file)
            NOR = keySym_file.data[5];
    }
    catch (Exception e) { printf("### Exception in matrixKeySym_drop_cb() for r_keySym_recordNo\n"); /* todo: handle exception */ }
    return NOR;
}


void set_more_for_global_local() nothrow
{
////    printf("set_more_for_global_local (%d)\n", keySym_global_local.get);
    keySym_fidAppDir.set(keySym_global_local.get? (appdf is null? 0 : ub22integral(appdf.data[2..4])) : 0x3F00, true);

    tnTypePtr  keySym_file;
    int NOR = getNOR(keySym_file);
    assert(keySym_file);
    keySym_fid.set(keySym_file is null? [0,0] : [ub22integral(keySym_file.data[2..4]), 0], true);
    assert(skdf);
////assumeWontThrow(writeln("keySym_fid MRL: ", keySym_fid.size));
    AA["matrixKeySym"].SetStringId2("", r_AC_Update_SKDF,              1, assumeWontThrow(format!"%02X"(       skdf.data[25])));
    AA["matrixKeySym"].SetStringId2("", r_AC_Update_Crypto_keySymFile, 1, assumeWontThrow(format!"%02X"(keySym_file.data[25])) ~" / "~ assumeWontThrow(format!"%02X"(keySym_file.data[26])));

    if (AA["radioKeySym"].GetStringVALUE() != "toggle_sym_create_write")
    {
        if ((keySym_file && keySym_recordNo.get>NOR) || keySym_recordNo.get==0)
        { assert(0); }
    }
    else
    {
//      searchAndSetRecordNoUnused();
        if (keySym_recordNo.get>0 && keySym_recordNo.get<=NOR && !rangeExtractedSym(SKDF).any!(a => a.sameGlobalLocalAndRecNo(keySym_global_local.get, keySym_recordNo.get)))
            return;

        foreach (j; 1..1+NOR)
        {
            if (rangeExtractedSym(SKDF).any!(a => a.sameGlobalLocalAndRecNo(keySym_global_local.get, j)))
                continue;
            keySym_recordNo.set(j, true);
            return;
        }
        // there is no free slot in that file; what to do now
    }
}


extern(C) nothrow :


int matrixKeySym_dropcheck_cb(Ihandle* /*self*/, int lin, int col)
{
    if (col!=1 /*|| lin>r_keySym_global_local*/)
        return IUP_IGNORE; // draw nothing
//    printf("matrixKeySym_dropcheck_cb(%d, %d)\n", lin, col);
//    printf("matrixKeySym_dropcheck_cb  %s\n", AA["radioKeySym"].GetAttributeVALUE());
    immutable activeToggle = AA["radioKeySym"].GetStringVALUE();
    immutable isSelectedKeyId = AA["matrixKeySym"].GetIntegerId2("", r_keySym_Id, 1) != 0;
    switch (lin)
    {
    /* dropdown */
        case r_keySym_Id:
            if (activeToggle.among("toggle_sym_SKDF_change",
                                   "toggle_sym_delete",
                                   "toggle_sym_update",
                                   "toggle_sym_enc_dec"))
                return IUP_DEFAULT; // show the dropdown symbol
            break;

        case r_keySym_recordNo:
            if (activeToggle=="toggle_sym_create_write")
                return IUP_DEFAULT; // show the dropdown symbol
            break;

        case r_keySym_algoFamily,
             r_keySym_keyLenBits:
            if (activeToggle.among("toggle_sym_update", "toggle_sym_create_write") && isSelectedKeyId)
                return IUP_DEFAULT; // show the dropdown symbol
            break;

    /* toggle */
        case r_keySym_global_local:
            if (activeToggle=="toggle_sym_create_write")
                return IUP_CONTINUE; // show and enable the toggle button
            break;

         case r_keySym_IntAuthYN, r_keySym_ExtAuthYN:
            if (activeToggle.among("toggle_sym_update", "toggle_sym_create_write") && isSelectedKeyId)
                return IUP_CONTINUE; // show and enable the toggle button
            break;

       case r_keySym_Modifiable:
            if (activeToggle.among("toggle_sym_SKDF_change",
                                   "toggle_sym_update",
                                   "toggle_sym_updateSMkeyHost",
                                   "toggle_sym_updateSMkeyCard",
                                   "toggle_sym_create_write") && isSelectedKeyId)
                return IUP_CONTINUE; // show and enable the toggle button
            break;

        case r_keySym_IntAuthUsageCounterYN:
            if (activeToggle.among("toggle_sym_update", "toggle_sym_updateSMkeyCard", "toggle_sym_create_write") && isSelectedKeyId)
                return IUP_CONTINUE; // show and enable the toggle button
            break;

        case r_keySym_ExtAuthErrorCounterYN:
            if (activeToggle.among("toggle_sym_update", "toggle_sym_updateSMkeyHost", "toggle_sym_create_write") && isSelectedKeyId)
                return IUP_CONTINUE; // show and enable the toggle button
            break;

        default:  break;
    }
    return  IUP_IGNORE; // draw nothing
} // matrixKeySym_dropcheck_cb


int matrixKeySym_drop_cb(Ihandle* /*self*/, Ihandle* drop, int lin, int col)
{
    if (col!=1 /*|| lin.among(r_keySym_global_local)*/)
        return IUP_IGNORE; // draw nothing
//    printf("matrixKeySym_drop_cb(%d, %d)\n", lin, col);
    immutable activeToggle = AA["radioKeySym"].GetStringVALUE();

    with (createHandle(drop))
    switch (lin)
    {
        case r_keySym_Id:
            if (activeToggle.among("toggle_sym_SKDF_change",
                                   "toggle_sym_delete",
                                   "toggle_sym_update",
                                   "toggle_sym_enc_dec"))
            {
                int i;
                rangeExtractedSym(SKDF).each!(n => SetIntegerId("", ++i, n.iD));
                SetAttributeId("", ++i, null);
                SetAttributeStr(IUP_VALUE, null);
                return IUP_DEFAULT; // show the dropdown values
            }
            break;

        case r_keySym_recordNo:
            if (activeToggle=="toggle_sym_create_write")
            {
                tnTypePtr  dummy;
                int i;
                foreach (recNo; 1..1+getNOR(dummy))
                {
                    if (rangeExtractedSym(SKDF).any!(a => a.sameGlobalLocalAndRecNo(keySym_global_local.get, recNo)))
                        continue;
                    SetIntegerId("", ++i, recNo);
                }
                SetAttributeId("", ++i, null);
                SetAttributeStr(IUP_VALUE, null);
                return IUP_DEFAULT; // show the dropdown values
            }
            break;

        case r_keySym_algoFamily:
            if (activeToggle.among("toggle_sym_update", "toggle_sym_create_write"))
            {
                SetAttributeId("", 1, "AES");
                SetAttributeId("", 2, "DES");
                SetAttributeId("", 3, null);
                SetAttributeStr(IUP_VALUE, null);
                return IUP_DEFAULT; // show the dropdown values
            }
            break;

        case r_keySym_keyLenBits:
            if (activeToggle.among("toggle_sym_update", "toggle_sym_create_write"))
            {
                if (keySym_algoFamily.get=="AES")
                {
                    SetAttributeId("", 1, "128");
                    SetAttributeId("", 2, "192");
                    SetAttributeId("", 3, "256");
                }
                else  // if (keySym_algoFamily.get=="DES")
                {
                    SetAttributeId("", 1, "64");
                    SetAttributeId("", 2, "128");
                    SetAttributeId("", 3, "192");
                }
                SetAttributeId("", 4, null);
                SetAttributeStr(IUP_VALUE, null);
                return IUP_DEFAULT; // show the dropdown values
            }
            break;

        default:  break;
    }
    return IUP_IGNORE;
}


int matrixKeySym_dropselect_cb(Ihandle* self, int lin, int col, Ihandle* /*drop*/, const(char)* t, int i, int v)
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
//    int val;
//    try
//        val = fromStringz(t).to!int;
//    catch(Exception e) { printf("### Exception in matrixKeyAsym_dropselect_cb\n"); return IUP_CONTINUE; }
////    printf("matrixKeyAsym_dropselect_cb(lin: %d, col: %d, text (t) of the item whose state was changed: %s, mumber (i) of the item whose state was changed: %d, selected (v): %d)\n", lin, col, t, i, v);
    if (v/*selected*/ && col==1)
    {
        Handle h = createHandle(self);

        switch (lin)
        {
            case r_keySym_Id:
                keySym_Id.set = h.GetIntegerVALUE;
                break;

            case r_keySym_algoFamily:
                keySym_algoFamily.set = h.GetStringVALUE();
                if (keySym_algoFamily.get=="AES")
                {
                    keySym_ExtAuthYN.set(0, true);
                    keySym_IntAuthYN.set(0, true);
                }
                break;

            case r_keySym_keyLenBits:
                keySym_keyLenBits.set = h.GetIntegerVALUE();
                break;

            case r_keySym_recordNo:
                keySym_recordNo.set = h.GetIntegerVALUE();
                break;

            default: break;
        }
    }
    return IUP_CONTINUE; // return IUP_DEFAULT;
}


int matrixKeySym_edition_cb(Ihandle* ih, int lin, int col, int mode, int /*update*/)
{
//mode: 1 if the cell has entered the edition mode, or 0 if the cell has left the edition mode
//update: used when mode=0 to identify if the value will be updated when the callback returns with IUP_DEFAULT. (since 3.0)
//matrixRsaAttributes_edition_cb(1, 1) mode: 1, update: 0
//matrixRsaAttributes_edition_cb(1, 1) mode: 0, update: 1

////    printf("matrixKeySym_edition_cb(%d, %d) mode: %d, update: %d\n", lin, col, mode, update);
    immutable activeToggle = AA["radioKeySym"].GetStringVALUE();
    immutable isSelectedKeyId = AA["matrixKeySym"].GetIntegerId2("", r_keySym_Id, 1) != 0;
    if (mode==1)
    {
        // toggle rows always readonly, if they are NOT enabled as toggles; otherwise: enabled as toggles, they don't go through edition_cb
        if (col!=1 || lin.among(r_keySym_global_local,
                                r_keySym_Modifiable,
                                r_keySym_IntAuthYN,
                                r_keySym_IntAuthUsageCounterYN,
                                r_keySym_ExtAuthYN,
                                r_keySym_ExtAuthErrorCounterYN))
            return IUP_IGNORE;

        // readonly, unconditionally
        if (lin.among(//r_keySym_keyRef,    hidden
                      r_keySym_fid,
                      r_keySym_fidAppDir,
                      //r_keySym_usageSKDF, hidden
                      r_keySym_authId,
                      //r_keySym_algoStore, hidden
                      r_keySym_ByteStringStore,
                      r_row_empty,
                      r_change_calcSKDF))
            return IUP_IGNORE;

        // readonly, condition  isSelectedKeyPairId
        if (!isSelectedKeyId)
        {
            if (lin.among(r_keySym_Label))
                return IUP_IGNORE;
        }
        // readonly, condition  activeToggle
        switch (activeToggle)
        {
            case "toggle_sym_SKDF_change":
                if (lin.among(r_keySym_recordNo,

                              r_keySym_algoFamily,
                              r_keySym_keyLenBits,
                              r_keySym_IntAuthUsageCounterValue,
                              r_keySym_ExtAuthErrorCounterValue,

                              r_keySym_bytesStockAES,
                              r_keySym_bytesStockDES,

                              r_fromfile,
                              r_tofile,
                              r_iv,
                              r_mode,
                              r_enc_dec
                ))
                    return IUP_IGNORE;
                break;

            case "toggle_sym_delete":
                if (lin.among(r_keySym_recordNo,

                              r_keySym_Label,

                              r_keySym_algoFamily,
                              r_keySym_keyLenBits,
                              r_keySym_IntAuthUsageCounterValue,
                              r_keySym_ExtAuthErrorCounterValue,

                              r_keySym_bytesStockAES,
                              r_keySym_bytesStockDES,

                              r_fromfile,
                              r_tofile,
                              r_iv,
                              r_mode,
                              r_enc_dec
                ))
                    return IUP_IGNORE;
                break;

            case "toggle_sym_update":
                if (lin.among(r_keySym_recordNo,

                              r_fromfile,
                              r_tofile,
                              r_iv,
                              r_mode,
                              r_enc_dec
                ))
                    return IUP_IGNORE;
                break;

            case "toggle_sym_updateSMkeyHost":
                if (lin.among(r_keySym_Id,
                              r_keySym_recordNo,

                              r_keySym_algoFamily,
                              r_keySym_keyLenBits,
                              r_keySym_IntAuthUsageCounterValue,

                              r_fromfile,
                              r_tofile,
                              r_iv,
                              r_mode,
                              r_enc_dec
                ))
                    return IUP_IGNORE;
                break;

            case "toggle_sym_updateSMkeyCard":
                if (lin.among(r_keySym_Id,
                              r_keySym_recordNo,

                              r_keySym_algoFamily,
                              r_keySym_keyLenBits,
                              r_keySym_ExtAuthErrorCounterValue,

                              r_fromfile,
                              r_tofile,
                              r_iv,
                              r_mode,
                              r_enc_dec
                ))
                    return IUP_IGNORE;
                break;

            case "toggle_sym_create_write":
                if (lin.among(r_keySym_Id,

                              r_fromfile,
                              r_tofile,
                              r_iv,
                              r_mode,
                              r_enc_dec
                ))
                    return IUP_IGNORE;
                break;

            case "toggle_sym_enc_dec":
                if (lin.among(r_keySym_recordNo,

                              r_keySym_Label,

                              r_keySym_algoFamily,
                              r_keySym_keyLenBits,
                              r_keySym_IntAuthUsageCounterValue,
                              r_keySym_ExtAuthErrorCounterValue,

                              r_keySym_bytesStockAES,
                              r_keySym_bytesStockDES,
                ))
                    return IUP_IGNORE;
                break;

            default:  break;
        }
        return IUP_DEFAULT;
    } // if (mode==1)

    //mode==0

    Handle h = createHandle(ih);
    switch (lin)
    {
        case r_keySym_algoFamily:
            // postprocess for keySym_algoFamily, set in matrixKeySym_dropselect_cb
            if      (keySym_algoFamily.get=="AES" && keySym_keyLenBits.get==64)
              keySym_keyLenBits.set(128, true);
            else if (keySym_algoFamily.get=="DES" && keySym_keyLenBits.get==256)
                keySym_keyLenBits.set(192, true);
            break;

        case r_keySym_ExtAuthErrorCounterValue:
            immutable v  = h.GetIntegerVALUE();
            if (v<1 || v>14) // clamp(v, 1, 0x0E)
                return IUP_IGNORE;
            keySym_ExtAuthErrorCounterValue.set = v;
            break;

        case r_keySym_IntAuthUsageCounterValue:
            immutable v  = h.GetIntegerVALUE();
            if (v<1 || v>0xFFFE) // clamp(v, 1, 0xFFFE)
                return IUP_IGNORE;
            keySym_IntAuthUsageCounterValue.set = v;
            break;

        case r_keySym_Label:
            keySym_Label.set = h.GetStringVALUE();
            break;

        case r_keySym_bytesStockAES:
            auto tmp = string2ubaIntegral(h.GetStringVALUE());
            tmp.length = 32;
            keySym_bytesStockAES.set(tmp[0..32], true);
            h.SetStringVALUE(ubaIntegral2string(tmp[0..32]));
            break;

        case r_keySym_bytesStockDES:
            auto tmp = string2ubaIntegral(h.GetStringVALUE());
            tmp.length = 24;

            foreach (i; 0..3/*keyLen/blocksize*/)
            {
                auto p = cast(DES_cblock*)(tmp.ptr+i*DES_KEY_SZ);
                DES_set_odd_parity (p);
                if (DES_is_weak_key(p) == 1)
                    return IUP_IGNORE;
            }

            keySym_bytesStockDES.set(tmp[0..24], true);
//            keyAsym_usagePrKDF.set(tmp, true); // strange, doesn't update with new string
            h.SetStringVALUE(ubaIntegral2string(tmp[0..24]));
            break;

        default:
            break;
    }

    return IUP_DEFAULT;
} // matrixKeySym_edition_cb


int matrixKeySym_togglevalue_cb(Ihandle* /*self*/, int lin, int /*col*/, int status)
{
//    assert(col==1 && lin.among(r_keyPairModifiable, r_storeAsCRTRSAprivate));
//    printf("matrixKeySym_togglevalue_cb(%d, %d) status: %d\n", lin, col, status);
//            bool isSelectedKeyId = AA["matrixKeySym"].GetIntegerId2("", r_keySym_Id, 1) != 0;
    switch (lin)
    {
        case r_keySym_Modifiable:
            keySym_Modifiable.set = status;
            break;

        case r_keySym_global_local:
            keySym_global_local.set = status;
            break;

        case r_keySym_ExtAuthYN:
               keySym_ExtAuthYN.set = status;
            break;

        case r_keySym_IntAuthYN:
               keySym_IntAuthYN.set = status;
            break;

        case r_keySym_ExtAuthErrorCounterYN:
               keySym_ExtAuthErrorCounterYN.set = status;
            break;

        case r_keySym_IntAuthUsageCounterYN:
               keySym_IntAuthUsageCounterYN.set = status;

            break;

        default: break;
    }
    return IUP_DEFAULT;
}


int toggle_radioKeySym_cb(Ihandle* ih, int state)
{
////    printf("toggle_radioKeySym_cb (%d) %s\n", state, IupGetName(ih));
    if (state==0)  // for the toggle, that lost activated state
    {
        /* if the keyAsym_Id is not valid (e.g. prior selected was "toggle_RSA_key_pair_create_and_generate" but no creation was invoked)
           then select a valid one */
        Handle h = AA["matrixKeySym"];
        immutable inactivatedToggle = createHandle(ih).GetName();
        //check whether keySym_recordNo is suitable because used in SKDF
        if (inactivatedToggle=="toggle_sym_create_write")
        {
            if (rangeExtractedSym(SKDF).any!(a => a.sameGlobalLocalAndRecNo(keySym_global_local.get, keySym_recordNo.get)))
                return IUP_DEFAULT;
            if (!SKDF.empty)
                keySym_Id.set(rangeExtractedSym(SKDF).front.iD, true);

/+
bool doSelectNew = true;
            int recNo;
            foreach (es; rangeExtractedSym(SKDF)) {
                if (!es.sameGlobalLocal(keySym_global_local.get))
                    continue;
//                if (es.recNo==keySym_recordNo.get) {
//                    doSelectNew = false; // i.e. we are leaving "toggle_sym_create_write" with a keySym_Id present in SKDF
//                    break;
//                }
                recNo = es.recNo;
            }
            if (doSelectNew) {
                if (recNo>0)
                    keySym_recordNo.set(recNo, true);
                else {
                    keySym_global_local.set(!keySym_global_local.get, true);
                    foreach (es; rangeExtractedSym(SKDF)) {
                        if (!es.sameGlobalLocal(keySym_global_local.get))
                            continue;
                        keySym_recordNo.set(es.recNo, true);
                        break;
                    }
                }
//              setKeySym_IdFromSKDFrecNo();
                if (keySym_recordNo.get==0)
                    return IUP_DEFAULT;

                AA["matrixKeySym"].SetStringId2 ("", r_keySym_Id, 1, "");
                auto res = rangeExtractedSym(SKDF).find!(a => a.sameGlobalLocalAndRecNo(keySym_global_local.get, keySym_recordNo.get));
                int iD = res.empty? 0 : res.front.iD;
                assert(iD>0);
                keySym_Id.set(iD, true);
//                foreach (es; rangeExtractedSym(SKDF)) {
//                    if (es.sameGlobalLocalAndRecNo(keySym_global_local.get, keySym_recordNo.get)) {
//                        keySym_Id.set(es.iD, true);
//                        break;
//                    }
//                    AA["matrixKeySym"].SetStringId2 ("", r_keySym_Id, 1, "");
//                }
            }
+/
        }
        AA["statusbar"].SetString(IUP_TITLE, "statusbar");
        return IUP_DEFAULT;
    } // if (state==0)

    void setColorForbidden(int[] rows)
    {
        with (AA["matrixKeySym"])
            foreach (row; rows)
                SetRGBId2(IUP_BGCOLOR, row, 1,  255,255,255);
    }
    void setColorAllowed(int[] rows)
    {
        with (AA["matrixKeySym"])
            foreach (row; rows)
                SetRGBId2(IUP_BGCOLOR, row, 1,  152,251,152);
    }

    Handle hButton = AA["button_radioKeySym"];
    string activeToggle = AA["radioKeySym"].GetStringVALUE();
    with (AA["matrixKeySym"])
    switch (activeToggle)
    {
        case "toggle_sym_SKDF_change":
            hButton.SetString(IUP_TITLE, "SKDF only: Change some administrative (PKCS#15) data");
            setColorAllowed  ([r_keySym_Id,
                               r_keySym_Label,
                               r_keySym_Modifiable ]);
            setColorForbidden([r_keySym_recordNo,   r_keySym_global_local,
                               r_keySym_algoFamily, r_keySym_keyLenBits,
                               r_keySym_IntAuthYN,  r_keySym_IntAuthUsageCounterYN,  r_keySym_IntAuthUsageCounterValue,
                               r_keySym_ExtAuthYN,  r_keySym_ExtAuthErrorCounterYN,  r_keySym_ExtAuthErrorCounterValue,
                               r_keySym_bytesStockAES, r_keySym_bytesStockDES,
                               r_fromfile, r_tofile, r_iv, r_mode, r_enc_dec ]);
            break;

        case "toggle_sym_delete":
            hButton.SetString(IUP_TITLE, "Delete key record's content (select by key id)");
            setColorAllowed  ([r_keySym_Id ]);
            setColorForbidden([r_keySym_recordNo,   r_keySym_global_local,
                               r_keySym_Label,      r_keySym_Modifiable,
                               r_keySym_algoFamily, r_keySym_keyLenBits,
                               r_keySym_IntAuthYN,  r_keySym_IntAuthUsageCounterYN,  r_keySym_IntAuthUsageCounterValue,
                               r_keySym_ExtAuthYN,  r_keySym_ExtAuthErrorCounterYN,  r_keySym_ExtAuthErrorCounterValue,
                               r_keySym_bytesStockAES, r_keySym_bytesStockDES,
                               r_fromfile, r_tofile, r_iv, r_mode, r_enc_dec ]);
            break;
        case "toggle_sym_update":
            hButton.SetString(IUP_TITLE, "Update/Write a key file record");
            setColorAllowed  ([r_keySym_Id,
                               r_keySym_Label,      r_keySym_Modifiable,
                               r_keySym_algoFamily, r_keySym_keyLenBits,
                               r_keySym_IntAuthYN,  r_keySym_IntAuthUsageCounterYN,  r_keySym_IntAuthUsageCounterValue,
                               r_keySym_ExtAuthYN,  r_keySym_ExtAuthErrorCounterYN,  r_keySym_ExtAuthErrorCounterValue,
                               r_keySym_bytesStockAES, r_keySym_bytesStockDES ]);
            setColorForbidden([r_keySym_recordNo,   r_keySym_global_local,
                               r_fromfile, r_tofile, r_iv, r_mode, r_enc_dec ]);
            break;

        case "toggle_sym_updateSMkeyHost":
            hButton.SetString(IUP_TITLE, "Update/Write a key file record");
            setColorAllowed  ([r_keySym_Label,      r_keySym_Modifiable,
                                                    r_keySym_ExtAuthErrorCounterYN,  r_keySym_ExtAuthErrorCounterValue,
                               r_keySym_bytesStockAES, r_keySym_bytesStockDES ]);
            setColorForbidden([r_keySym_Id,
                               r_keySym_recordNo,   r_keySym_global_local,
                               r_keySym_algoFamily, r_keySym_keyLenBits,
                               r_keySym_IntAuthYN,  r_keySym_IntAuthUsageCounterYN,  r_keySym_IntAuthUsageCounterValue,
                               r_keySym_ExtAuthYN,
                               r_fromfile, r_tofile, r_iv, r_mode, r_enc_dec ]);
// if key SMkeyHost doesn't exist already, then this is not suitable: change to "toggle_sym_create_write" with some pre-settings
// otherwise select the iD and set it
            auto res = rangeExtractedSym(SKDF).find!(a => a.sameGlobalLocalAndRecNo(1, 1));
            int iD = res.empty? 0 : res.front.iD;
            if (iD>0 && iD != keySym_Id.get)
                keySym_Id.set(iD, true);
            keySym_ExtAuthYN.set(true,  true);
            keySym_IntAuthYN.set(false, true);
            break;

        case "toggle_sym_updateSMkeyCard":
            hButton.SetString(IUP_TITLE, "Update/Write a key file record");
            setColorAllowed  ([r_keySym_Label,      r_keySym_Modifiable,
                                                    r_keySym_IntAuthUsageCounterYN,  r_keySym_IntAuthUsageCounterValue,

                               r_keySym_bytesStockAES, r_keySym_bytesStockDES ]);
            setColorForbidden([r_keySym_Id,
                               r_keySym_recordNo,   r_keySym_global_local,
                               r_keySym_algoFamily, r_keySym_keyLenBits,
                               r_keySym_IntAuthYN,
                               r_keySym_ExtAuthYN,  r_keySym_ExtAuthErrorCounterYN,  r_keySym_ExtAuthErrorCounterValue,
                               r_fromfile, r_tofile, r_iv, r_mode, r_enc_dec ]);
// if key SMkeyCard doesn't exist already, then this is not suitable: change to "toggle_sym_create_write" with some pre-settings
// otherwise select the iD and set it
            auto res = rangeExtractedSym(SKDF).find!(a => a.sameGlobalLocalAndRecNo(1, 2));
            int iD = res.empty? 0 : res.front.iD;
            if (iD>0 && iD != keySym_Id.get)
                keySym_Id.set(iD, true);
            keySym_ExtAuthYN.set(false, true);
            keySym_IntAuthYN.set(true,  true);
            break;

        case "toggle_sym_create_write":
            hButton.SetString(IUP_TITLE, "Write new key file record and add to SKDF");
            setColorAllowed  ([r_keySym_recordNo,   r_keySym_global_local,
                               r_keySym_Label,      r_keySym_Modifiable,
                               r_keySym_algoFamily, r_keySym_keyLenBits,
                               r_keySym_IntAuthYN,  r_keySym_IntAuthUsageCounterYN,  r_keySym_IntAuthUsageCounterValue,
                               r_keySym_ExtAuthYN,  r_keySym_ExtAuthErrorCounterYN,  r_keySym_ExtAuthErrorCounterValue,
                               r_keySym_bytesStockAES, r_keySym_bytesStockDES ]);
            setColorForbidden([r_keySym_Id,
                               r_fromfile, r_tofile, r_iv, r_mode, r_enc_dec ]);
            // must select a record in file global/local, that isn't present in SKDF
            keySym_global_local.set(true, true);
            change_calcSKDF.setIsNewKeyId;
            keySym_Id.set(nextUniqueKeyId(), true);
            break;

        case "toggle_sym_enc_dec":
            hButton.SetString(IUP_TITLE, "Encrypt or Decrypt fromfile -> tofile  (with key selected by id)");
            setColorAllowed  ([r_keySym_Id,
                               r_fromfile, r_tofile, r_iv, r_mode, r_enc_dec ]);
            setColorForbidden([r_keySym_recordNo,   r_keySym_global_local,
                               r_keySym_Label,      r_keySym_Modifiable,
                               r_keySym_algoFamily, r_keySym_keyLenBits,
                               r_keySym_IntAuthYN,  r_keySym_IntAuthUsageCounterYN,  r_keySym_IntAuthUsageCounterValue,
                               r_keySym_ExtAuthYN,  r_keySym_ExtAuthErrorCounterYN,  r_keySym_ExtAuthErrorCounterValue,
                               r_keySym_bytesStockAES, r_keySym_bytesStockDES ]);
            break;

        default:
            assert(0);
    }
    return IUP_DEFAULT;
}

/+
ubyte algoECB_MSEfromAlgoKeySym(int algoKeySym)
{
    switch (algoKeySym)
    {
        case 0x02, 0x03, 0x12, 0x13, 0x22, 0x23: /*  AES */ return 4;
        case 0x04, 0x14:                         /* 3DES */ return 0;
        case 0x05:                               /*  DES */ return 1;
        case 0x00, 0x01: // mixed (3)DES / AES : don't use that
                assert(0);
       default: assert(0);
    }
}
+/

ubyte blocksizefromAlgoKeySym(int algoKeySym)
//out (result; result==8 || result==16, "return value must be either 8 or 16")
{
    switch (algoKeySym)
    {
        case 0x02, 0x03, 0x12, 0x13, 0x22, 0x23: /*  AES */ return 16;
        case 0x04, 0x14,                         /* 3DES */
             0x05:                               /*  DES */ return 8;
        case 0x00, 0x01: // mixed (3)DES / AES : don't use that
                assert(0);
       default: assert(0);
    }
}


ubyte keyLenBytesfromAlgoKeySym(int algoKeySym)
{
    switch (algoKeySym)
    {
        case 0x02, 0x03: /*  AES */ return 16;
        case 0x12, 0x13: /*  AES */ return 24;
        case 0x22, 0x23: /*  AES */ return 32;
        case 0x04:       /* 3DES */ return 16;
        case 0x14:       /* 3DES */ return 24;
        case 0x05:       /*  DES */ return 8;
        case 0x00:                  return 16;  // mixed 3DES / AES : don't use that
        case 0x01: assert(0);                   // mixed  DES / AES : don't use that
       default:    assert(0);
    }
}


CtxTagNo ctxTagNofromAlgoKeySym(int algoKeySym)
{
    switch (algoKeySym)
    {
        case 0x02, 0x03: /*  AES */ return CtxTagNo.genericSecretKey; // CtxTagNo.aesKey;
        case 0x12, 0x13: /*  AES */ return CtxTagNo.genericSecretKey; // CtxTagNo.aesKey;
        case 0x22, 0x23: /*  AES */ return CtxTagNo.genericSecretKey; // CtxTagNo.aesKey;
        case 0x04:       /* 3DES */ return CtxTagNo.des2Key;
        case 0x14:       /* 3DES */ return CtxTagNo.des3Key;
        case 0x05:       /*  DES */ return CtxTagNo.desKey;
        case 0x00:                  return CtxTagNo.unknown;  // mixed 3DES / AES : don't use that
        case 0x01: assert(0);                                 // mixed  DES / AES : don't use that
       default:    assert(0);
    }
}


int btn_random_key_cb(Ihandle* ih)
{
    import deimos.openssl.rand : RAND_bytes;
    int rv;
    ubyte[16] tmp_iv;
    ubyte[32] tmp_key;
    if ((rv= RAND_bytes(tmp_key.ptr, cast(int)tmp_key.length)) == 0)
        return IUP_DEFAULT;
    if ((rv= RAND_bytes(tmp_iv.ptr,  cast(int)tmp_iv.length)) == 0)
        return IUP_DEFAULT;

    version(Posix) {
        /* display entropy_avail */
        import std.process : executeShell; // executeShell is not @nogc and not nothrow
        import std.string : chop;
        try {
            auto cat = executeShell("cat /proc/sys/kernel/random/entropy_avail");
            auto text = cast(Text)AA["entropy_avail_text"];
            text.SetStringVALUE("entropy_avail: " ~ (cat.status == 0 ? chop(cat.output) : "0"));
        }
        catch (Exception e) { printf("### Exception in btn_random_key_cb() \n"); /* todo: handle exception */ }
    }

    keySym_bytesStockAES.set(tmp_key, true);

    DES_cblock[3] key3 = void;
    memcpy(key3.ptr, tmp_key.ptr, 3*DES_KEY_SZ);
    foreach (ref key; key3)
    {
//        auto p = cast(DES_cblock*)(tmp.ptr+i*DES_KEY_SZ);
        DES_set_odd_parity(&key);
        while (DES_is_weak_key(&key) == 1) // should be unlikely to match one of the rare weak keys, though possible
            RAND_bytes(key.ptr, DES_KEY_SZ);
    }
    keySym_bytesStockDES.set((key3[0]~key3[1]~key3[2])[0..24], true);
    assumeWontThrow(AA["matrixKeySym"].SetStringId2("", r_iv, 1, format!"%(%02X%)"(tmp_iv)));

    return IUP_DEFAULT;
}


const char[] button_radioKeySym_cb_common1 =`
            import wrapper.libtasn1 : asn1_node, asn1_dup_node, asn1_delete_structure;

            int diff;
            diff = doDelete? change_calcSKDF.pkcs15_ObjectTyp.posStart - change_calcSKDF.pkcs15_ObjectTyp.posEnd : change_calcSKDF.get;

            ubyte[] zeroAdd = new ubyte[ diff>=0? 0 : abs(diff) ];
            auto haystack = find!((a,b) => b == getIdentifier(a, skChoiceName(change_calcSKDF.getctn)~skID, false, false))(SKDF, keySym_Id.get);
            assert(!haystack.empty);
            // change_calcSKDF.pkcs15_ObjectTyp shall be identical to resulting haystack.front (except the _new components)!) !

            asn1_node  front_structure = haystack.front.structure;
            with (change_calcSKDF.pkcs15_ObjectTyp)
            if (!doDelete)
            {
                haystack.front.der       = der       = der_new.dup;
                haystack.front.structure = structure = asn1_dup_node(structure_new, "");
                asn1_delete_structure(&front_structure);
            }
/*
  ATTENTION with asn1_delete_structure(&front_structure):
  change_calcSKDF.pkcs15_ObjectTyp.structure points to deleted content ! It MUST not be referenced any more
*/
            ubyte[] buf;
            change_calcSKDF.pkcs15_ObjectTyp.posEnd +=  diff;
            foreach (i, ref elem; haystack)
            {
                elem.posEnd       += diff;
                if (i>0 || !doDelete)
                    buf ~= elem.der;
                if (i>0)
                    elem.posStart += diff;
            }
            buf ~=  zeroAdd;
            assert(skdf);
//assumeWontThrow(writeln("  ### check change_calcSKDF.pkcs15_ObjectTyp: ", change_calcSKDF.pkcs15_ObjectTyp));
//assumeWontThrow(writeln("  ### check haystack:                         ", haystack));
`;
//mixin(button_radioKeySym_cb_common1);


const char[] button_radioKeySym_cb_common2 =`
            // from tools/pkcs15-init.c  main
            sc_pkcs15_card*  p15card;
            sc_profile*      profile;
            const(char)*     opt_profile      = "acos5_external"; //"pkcs15";
            const(char)*     opt_card_profile = "acos5_external";
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
`;
//mixin(button_radioKeySym_cb_common2);


int button_radioKeySym_cb(Ihandle* ih)
{
    import std.math : abs;
    Handle hstat = AA["statusbar"];
    hstat.SetString(IUP_TITLE, "");
    immutable activeToggle = AA["radioKeySym"].GetStringVALUE();
    assert(skdf);
    tnTypePtr  skFile;
    getNOR(skFile);
    assert(skFile);

    switch (activeToggle)
    {
/*
        case "toggle_sym_SKDF_change",
             "toggle_sym_delete",
             "toggle_sym_update",
             "toggle_sym_updateSMkeyHost",
             "toggle_sym_updateSMkeyCard",
             "toggle_sym_create_write",
             "toggle_sym_enc_dec":  break;
*/
        case "toggle_sym_SKDF_change":
            immutable bool doDelete;// = false;
            mixin(button_radioKeySym_cb_common1);

            enum string commands = `
            int rv;
            mixin(button_radioKeySym_cb_common2);

            // update SKDF; essential: don't allow to be called if the files aren't sufficiently sized
            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &skdf.data[8], skdf.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);
            if (rv >= 0 && buf.length)
                rv = sc_update_binary(card, haystack.front.posStart, buf.ptr, buf.length, 0);
            assert(rv==buf.length);
`;
            mixin(connect_card!commands);
            hstat.SetString(IUP_TITLE, "SUCCESS: Change some administrative (PKCS#15) data");
            break; // case "toggle_sym_SKDF_change"

        case "toggle_sym_delete":
            immutable bool doDelete = true;
            mixin(button_radioKeySym_cb_common1);

            enum string commands = `
            int rv;
            mixin(button_radioKeySym_cb_common2);

            // update SKDF; essential: don't allow to be called if the file isn't sufficiently sized
            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &skdf.data[8], skdf.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);

            if (rv >= 0 && buf.length)
                rv = sc_update_binary(card, haystack.front.posStart, buf.ptr, buf.length, 0);
//assumeWontThrow(writefln("toggle_sym_delete: rv: %s, buf.length: %s, %s", rv, buf.length, __LINE__));
            assert(rv==buf.length);

            // update record
            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &skFile.data[8], skFile.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);
            if (rv < 0)
                return IUP_DEFAULT;
//rv = sc_delete_record(card, keySym_recordNo.get);
//assumeWontThrow(writefln("toggle_sym_delete: rv: %s, skFile.data[4]: %s, %s", rv, skFile.data[4], __LINE__));
//            assert(rv == skFile.data[4]);
`;
            mixin (connect_card!commands);
            hstat.SetString(IUP_TITLE, "SUCCESS: Delete key");
            immutable keySym_Id_old = keySym_Id.get;
            Handle h = AA["matrixKeySym"];
            // set to another keySym_Id, the first found
            auto res = rangeExtractedSym(SKDF).find!(a => a.iD != keySym_Id_old);
            int iD = res.empty? 0 : res.front.iD;
            if (iD>0)
                keySym_Id.set(iD, true);

            res = rangeExtractedSym(SKDF).find!(a => a.iD == keySym_Id_old);
            iD = res.empty? 0 : res.front.iD;
            assert(iD>0);
            SKDF = SKDF.remove!(a => a == res.front.elem);

            asn1_delete_structure(&front_structure);
            GC.collect(); // just a check
////assumeWontThrow(writeln(SKDF));
            break; // case "toggle_sym_delete"

        case "toggle_sym_update", "toggle_sym_updateSMkeyHost", "toggle_sym_updateSMkeyCard", "toggle_sym_create_write":
            if (activeToggle == "toggle_sym_create_write")
            {
                import wrapper.libtasn1 : asn1_node, asn1_dup_node, asn1_delete_structure;
                SKDF ~= change_calcSKDF.pkcs15_ObjectTyp;
                SKDF[$-1].der_new       = null;
                SKDF[$-1].structure_new = null;
                asn1_node  front_structure2 = SKDF[$-1].structure;
                SKDF[$-1].structure = asn1_dup_node(change_calcSKDF.pkcs15_ObjectTyp.structure_new, "");
                asn1_delete_structure(&front_structure2);
            }
            immutable bool doDelete;// = false;
            mixin(button_radioKeySym_cb_common1);

            enum string commands = `
            int rv;
            mixin(button_radioKeySym_cb_common2);

            // update SKDF; essential: don't allow to be called if the file isn't sufficiently sized
            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &skdf.data[8], skdf.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);

            if (rv == SC_SUCCESS)
            {
                if (buf.length)
                {
                    rv = sc_update_binary(card, haystack.front.posStart, buf.ptr, buf.length, 0);
                    assert(rv==buf.length);
                }
                else
                { assert(0); }

                // update record
                sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &skFile.data[8], skFile.data[1], 0, -1);
                rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);
                if (rv < 0)
                    return IUP_DEFAULT;
                rv= sc_update_record(card, keySym_recordNo.get, 0, keySym_ByteStringStore.get.ptr, keySym_ByteStringStore.getLen, SC_RECORD_BY_REC_NR);
                assert(rv == keySym_ByteStringStore.getLen);
            }
`;
            mixin (connect_card!commands);
            if (activeToggle == "toggle_sym_create_write")
            {
assumeWontThrow(writeln(SKDF));
                // change the choice leaving 'create'  This is necessary, otherwise the same iD could be used multiple times for creation
                AA["toggle_sym_SKDF_change"].SetIntegerVALUE(1);
                toggle_radioKeySym_cb(AA["toggle_sym_SKDF_change"].GetHandle, 1);
                keySym_Id.set(keySym_Id.get, true);
                hstat.SetString(IUP_TITLE, "SUCCESS: key create");
                GC.collect(); // just a check
            }
            break; // case "toggle_sym_update", "toggle_sym_updateSMkeyHost", "toggle_sym_updateSMkeyCard", "toggle_sym_create_write":

        case "toggle_sym_enc_dec":
            import std.string : toStringz;
//            import std.file;
            Handle mtx = AA["matrixKeySym"];
            immutable fromfile     = mtx.GetStringId2("", r_fromfile, 1);
            immutable tofile       = mtx.GetStringId2("", r_tofile, 1);
            immutable what_enc_dec = mtx.GetStringId2("", r_enc_dec, 1);
            immutable what_mode    = mtx.GetStringId2("", r_mode, 1);
            immutable what_iv      = string2ubaIntegral(mtx.GetStringId2("", r_iv, 1)).idup;
//            assert(what_iv.length==16);
            immutable cbc = what_mode=="cbc";
            immutable ub2 fid      = integral2uba!2(keySym_fidAppDir.get); /* */
//          immutable ubyte algoECB_MSE = algoECB_MSEfromAlgoKeySym(keySym_algoStore.get); /* */
            ubyte blocksize             =   blocksizefromAlgoKeySym(keySym_algoStore.get); /* */
/*
            if (cbc && what_iv.length < blocksize)
            {
                IupMessage("Feedback upon IV", assumeWontThrow(format!"There are %d, less than blockSize (%d) bytes for the IV: Fill up and retry"(what_iv.length, blocksize).toStringz));
                return IUP_DEFAULT;
            }
*/
/+
            ubyte algoMSE = algoECB_MSE;
            ubyte[] tlv_crt_sym_encdec = (cast(immutable(ubyte)[])hexString!"B8 FF  95 01 40  80 01 FF  83 01 FF").dup;
            if (cbc)
            {
                algoMSE += 2;
                tlv_crt_sym_encdec ~= [ubyte(0x87), blocksize] /*~ what_iv[0..blocksize]*/;
            }
            assert(tlv_crt_sym_encdec.length>=2);
            tlv_crt_sym_encdec[1]  = cast(ubyte) (tlv_crt_sym_encdec.length-2);
            tlv_crt_sym_encdec[7]  = algoMSE;
            tlv_crt_sym_encdec[10] = cast(ubyte) keySym_keyRef.get;
+/
            string outStr = assumeWontThrow(tofile~format!"_keyRef%02X"(keySym_keyRef.get())~ what_mode!="cbc" ?
                    "" : format!"_IV%(%02X%)"(AA["matrixKeySym"].GetStringId2("", r_iv, 1) ) );
            CardCtl_crypt_sym  crypt_sym_data = {
                infile: fromfile.toStringz,
                outfile: tofile.toStringz,
                iv_len: cbc? blocksize : 0,
                key_ref: cast(ubyte) keySym_keyRef.get,
                block_size: blocksize,
                key_len: cast(ubyte) keySym_keyLenBits.get,
                pad_type: BLOCKCIPHER_PAD_TYPE_ZEROES, // BLOCKCIPHER_PAD_TYPE_PKCS5,
                local: true,
                cbc:     what_mode=="cbc",
                encrypt: what_enc_dec=="enc",
                perform_mse: true,
            };
//assumeWontThrow(writeln("crypt_sym_data.cbc: ", crypt_sym_data.cbc));
            if (cbc) {
version(OPENSC_VERSION_LATEST)
                crypt_sym_data.iv[0..blocksize] = what_iv[0..blocksize];
else
                crypt_sym_data.iv[0..blocksize] = 0;
            }
            try
            {
                enum string commands = `
                int rv;
                mixin(button_radioKeySym_cb_common2);

                sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &skFile.data[8], skFile.data[1], 0, -1);
                rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_CRYPTO);
                if (rv < 0)
                    return IUP_DEFAULT;

                rv= sc_card_ctl(card, SC_CARDCTL_ACOS5_ENCRYPT_SYM, &crypt_sym_data);
                if (crypt_sym_data.encrypt)
                    hstat.SetString(IUP_TITLE, (rv==SC_SUCCESS? "SUCCESS" : "FAILURE") ~": Encrypt data fromfile -> tofile");
                else
                    hstat.SetString(IUP_TITLE, (rv==SC_SUCCESS? "SUCCESS" : "FAILURE") ~": Decrypt data fromfile -> tofile");
`;
                mixin (connect_card!commands);
            }
            catch (Exception e) { printf("### Exception in btn_enc_dec_cb() \n"); /* todo: handle exception */ }
            break;

        default:  assert(0);
    } // switch (activeToggle)
    return IUP_DEFAULT;
} // button_radioKeySym_cb
