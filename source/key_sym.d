/*
 * Written in the D programming language, part of package acos5_64_gui.
 * keySym_AES_3DES.d: All about keys for symetric algorithms supported by ACOS5-64
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

module key_sym;

import core.memory : GC;
import core.runtime : Runtime;
import core.stdc.stdlib : exit;
import std.stdio;
import std.exception : assumeWontThrow, assumeUnique;
import std.conv: to, hexString;
import std.format;
import std.range : iota, chunks, indexed, chain;
import std.range.primitives : empty, front;//, back;
import std.array : array;
import std.algorithm.comparison : among, clamp, equal, min, max;
import std.algorithm.searching : canFind, countUntil, all, any, find, startsWith;
import std.algorithm.iteration : filter;
import std.algorithm.mutation : remove;
//import std.algorithm.iteration : uniq;
//import std.algorithm.sorting : sort;
import std.typecons : Tuple, tuple;
import std.string : /*chomp, */  toStringz, fromStringz, representation;
import std.signals;
import std.traits : EnumMembers;

import libopensc.opensc;
import libopensc.types;
import libopensc.errors;
import libopensc.log;
import libopensc.cards;
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

import util_opensc : lh, card, acos5_64_short_select, readFile, decompose, PKCS15Path_FileType, pkcs15_names,
    PKCS15_FILE_TYPE, fs, sitTypeFS, SKDF, AODF,
    util_connect_card, connect_card, PKCS15_ObjectTyp, errorDescription, PKCS15, iter_begin, appdf,
    tnTypePtr, /*populate_tree_fs,*/ itTypeFS, aid, cm_7_3_1_14_get_card_info, is_ACOSV3_opmodeV3_FIPS_140_2L3,
    my_pkcs15init_callbacks, tlv_Range_mod, file_type, getIdentifier, is_ACOSV3_opmodeV3_FIPS_140_2L3_active,
    cry_pso_7_4_3_6_2A_sym_encrypt, cry_pso_7_4_3_7_2A_sym_decrypt, cry_mse_7_4_2_1_22_set, getPath;

import libtasn1;
import pkcs11;

// tag types
//Obs
struct _keySym_algoStore{}
struct _keySym_keyRef{}

tnTypePtr   skdf;

bool isNewKeyId;
int  nextUniqueId; //= nextUniqueKeyId();

enum /* matrixKeySymRowName */ {
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

    r_keySym_algoType,                  // dropdown,  AES or DES-based
    r_keySym_keyLenBits,                // dropdown,  depends on AlgoType
//    r_keySym_algoStore,               // hidden, depends on AlgoType and keyLength

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
    r_iv,
    r_mode,
    r_enc_dec,
    r_change_calcSKDF,                  // readonly
}

Pub!_keySym_global_local          keySym_global_local;

Pub!_keySym_usageSKDF             keySym_usageSKDF;
Pub!_keySym_Id                    keySym_Id;
Pub!_keySym_Modifiable            keySym_Modifiable;
Pub!_keySym_authId                keySym_authId;

Pub!(_keySym_Label,string)        keySym_Label;
Pub!(_keySym_algoType,string)     keySym_algoType;
Pub!_keySym_keyLenBits            keySym_keyLenBits;

Pub!_keySym_fidAppDir             keySym_fidAppDir;
Pub!_keySym_fid                   keySym_fid;

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

void keySym_initialize_PubObs() {
    /* initialze the publisher/observer system for GenerateKeyPair_RSA_tab */
    // some variables are declared as publisher though they don't need to be, currently just for consistency, but that's not the most efficient way
//    keyPairLabel            = new Pub!(_keyPairLabel,string)  (r_keyPairLabel,            AA["matrixRsaAttributes"]);
    keySym_global_local          = new Pub!_keySym_global_local          (r_keySym_global_local,          AA["matrixKeySym"]);
    keySym_usageSKDF             = new Pub!_keySym_usageSKDF             (0/*r_keySym_usageSKDF,          AA["matrixKeySym"]*/); // visual representation removed
    keySym_Id                    = new Pub!_keySym_Id                    (r_keySym_Id,                    AA["matrixKeySym"]);
    keySym_Modifiable            = new Pub!_keySym_Modifiable            (r_keySym_Modifiable,            AA["matrixKeySym"]);
    keySym_authId                = new Pub!_keySym_authId                (r_keySym_authId,                AA["matrixKeySym"]);

    keySym_Label                 = new Pub!(_keySym_Label,string)        (r_keySym_Label,                 AA["matrixKeySym"]);
    keySym_algoType              = new Pub!(_keySym_algoType,string)     (r_keySym_algoType,              AA["matrixKeySym"]);
    keySym_keyLenBits            = new Pub!_keySym_keyLenBits            (r_keySym_keyLenBits,            AA["matrixKeySym"]);

    keySym_fid                   = new Pub!_keySym_fid                   (r_keySym_fid,                   AA["matrixKeySym"], true);
    keySym_fidAppDir             = new Pub!_keySym_fidAppDir             (r_keySym_fidAppDir,             AA["matrixKeySym"], true);

    keySym_ExtAuthYN             = new Pub!_keySym_ExtAuthYN             (r_keySym_ExtAuthYN,             AA["matrixKeySym"]);
    keySym_ExtAuthErrorCounterYN = new Pub!_keySym_ExtAuthErrorCounterYN (r_keySym_ExtAuthErrorCounterYN, AA["matrixKeySym"]);
    keySym_ExtAuthErrorCounterValue = new Pub!_keySym_ExtAuthErrorCounterValue (r_keySym_ExtAuthErrorCounterValue, AA["matrixKeySym"]);

    keySym_IntAuthYN             = new Pub!_keySym_IntAuthYN             (r_keySym_IntAuthYN,             AA["matrixKeySym"]);
    keySym_IntAuthUsageCounterYN = new Pub!_keySym_IntAuthUsageCounterYN (r_keySym_IntAuthUsageCounterYN, AA["matrixKeySym"]);
    keySym_IntAuthUsageCounterValue = new Pub!_keySym_IntAuthUsageCounterValue  (r_keySym_IntAuthUsageCounterValue, AA["matrixKeySym"]);

    keySym_algoStore             = new Obs_keySym_algoStore              (0/*r_keySym_algoStore,             AA["matrixKeySym"]*/); // visual representation removed
    keySym_bytesStockAES         = new Pub!(_keySym_bytesStockAES,ubyte[32])(r_keySym_bytesStockAES,            AA["matrixKeySym"]);
    keySym_bytesStockDES         = new Pub!(_keySym_bytesStockDES,ubyte[24])(r_keySym_bytesStockDES,            AA["matrixKeySym"]);
    keySym_ByteStringStore       = new Obs_keySym_ByteStringStore        (r_keySym_ByteStringStore,       AA["matrixKeySym"]);

    keySym_recordNo              = new Pub!_keySym_recordNo              (r_keySym_recordNo,              AA["matrixKeySym"]);
    keySym_keyRef                = new Obs_keySym_keyRef                 (0/*r_keySym_keyRef,             AA["matrixKeySym"]*/); // visual representation removed

    change_calcSKDF              = new Obs_change_calcSKDF               (r_change_calcSKDF,              AA["matrixKeySym"]);
//struct _AC_Update_SKDF{}       //SCB
//struct _AC_Update_keyFile{}    //SCB

//// dependencies
    keySym_Id                    .connect(&keySym_algoStore.watch);
    keySym_algoType              .connect(&keySym_algoStore.watch);
    keySym_keyLenBits            .connect(&keySym_algoStore.watch);

    keySym_Id                    .connect(&change_calcSKDF.watch);
    keySym_Label                 .connect(&change_calcSKDF.watch);
    keySym_Modifiable            .connect(&change_calcSKDF.watch);
    keySym_algoStore             .connect(&change_calcSKDF.watch);
    keySym_keyLenBits            .connect(&change_calcSKDF.watch);
    keySym_global_local          .connect(&change_calcSKDF.watch);
    keySym_recordNo              .connect(&change_calcSKDF.watch);
    keySym_keyRef                .connect(&change_calcSKDF.watch);

    keySym_recordNo                .connect(&keySym_keyRef.watch);
    keySym_global_local            .connect(&keySym_keyRef.watch);

    keySym_recordNo                .connect(&keySym_ByteStringStore.watch);
    keySym_algoStore               .connect(&keySym_ByteStringStore.watch);
    keySym_bytesStockAES           .connect(&keySym_ByteStringStore.watch);
    keySym_bytesStockDES           .connect(&keySym_ByteStringStore.watch);
    keySym_ExtAuthYN               .connect(&keySym_ByteStringStore.watch);
    keySym_IntAuthYN               .connect(&keySym_ByteStringStore.watch);
    keySym_ExtAuthErrorCounterYN   .connect(&keySym_ByteStringStore.watch);
    keySym_IntAuthUsageCounterYN   .connect(&keySym_ByteStringStore.watch);
    keySym_ExtAuthErrorCounterValue.connect(&keySym_ByteStringStore.watch);
    keySym_IntAuthUsageCounterValue.connect(&keySym_ByteStringStore.watch);

//// values to start with
    keySym_IntAuthUsageCounterValue.set(0xFFFE, true);
    keySym_ExtAuthErrorCounterValue.set(0x0E, true);
/*
    with (AA["matrixKeySym"]) {
        SetIntegerId(IUP_HEIGHT, r_keySym_ExtAuthErrorCounterYN,    0);
        SetIntegerId(IUP_HEIGHT, r_keySym_ExtAuthErrorCounterValue, 0);
        SetIntegerId(IUP_HEIGHT, r_keySym_IntAuthUsageCounterYN,    0);
        SetIntegerId(IUP_HEIGHT, r_keySym_IntAuthUsageCounterValue, 0);
    }
*/
//    keySym_Id             .set(3, true);
    ubyte[32] tmp= [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                  0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
    keySym_bytesStockAES.set(tmp, true);
    /*if (blocksize==8)*/ {
        import deimos.openssl.des : DES_cblock, DES_set_odd_parity, DES_is_weak_key;
        foreach (i; 0..3/*keyLen/blocksize*/) {
            auto p = cast(DES_cblock*)(tmp.ptr+i*8);
            DES_set_odd_parity (p);
            if (DES_is_weak_key(p) == 1)
            {    assert(0); }
        }
    }
    keySym_bytesStockDES.set(tmp[0..24], true);
    // set colours
    toggle_radioKeySym_cb(AA["toggle_sym_SKDF_change"].GetHandle, 1); // was set to active already
}

class Obs_keySym_keyRef {
    mixin(commonConstructor);

    @property int get() const @nogc nothrow /*pure*/ @safe { return _value; }

    void watch(string msg, int v) {
        switch(msg) {
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
////assumeWontThrow(writefln("  "~typeof(this).stringof~" object was set to value 0x%02X", _value));
        emit("_keySym_keyRef", _value);

        if (_h !is null) {
            _h.SetStringId2 ("", _lin, _col, format!"%02X"(_value));
            _h.Update;
        }
    }

    mixin Pub_boilerplate!(_keySym_algoStore, int);

    private :
    int    _keySym_recordNo;
    int    _keySym_global_local;

//    int    _value;
//    int    _lin;
//    int    _col;
//    Handle _h;
} // class Obs_keySym_keyRef

class Obs_keySym_algoStore {
    mixin(commonConstructor);

    void watch(string msg, string v) {
        switch(msg) {
            case "_keySym_algoType":
                  _keySym_algoType = v;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        calculate();
    }

    void watch(string msg, int v) {
        switch(msg) {
            case "_keySym_Id":
                  _keySym_algoType   = "";
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
        switch (_keySym_keyLenBits) {
            case  64:  _value = _keySym_algoType=="DES"? 0x05 : 0x02; break;
            case 128:  _value = _keySym_algoType=="DES"? 0x04 : 0x02; break;
            case 192:  _value = _keySym_algoType=="DES"? 0x14 : 0x12; break;
            case 256:  _value = _keySym_algoType=="DES"? 0x14 : 0x22; break;
            default:  goto case 192; // as long as _keySym_keyLenBits wasn't set
        }
////assumeWontThrow(writefln("  "~typeof(this).stringof~" object was set to value 0x%02X", _value));
        if (_keySym_keyLenBits && !_keySym_algoType.empty)
        emit("_keySym_algoStore", _value);

        if (_h !is null) {
            _h.SetStringId2 ("", _lin, _col, format!"0x%02X"(_value));
            _h.Update;
        }
    }

    mixin Pub_boilerplate!(_keySym_algoStore, int);

    private :
        string  _keySym_algoType;
        int     _keySym_keyLenBits;
//      int  _value;
} // class Obs_keySym_algoStore

class Obs_keySym_ByteStringStore {
    mixin(commonConstructor);

    @property ubyte[38] get()    const @nogc nothrow /*pure*/ @safe { return _value; }
    @property int       getLen() const @nogc nothrow /*pure*/ @safe { return _len; }

/*
    void watch(string msg, string v) {
        switch(msg) {
            case "_keySym_algoType":
                  _keySym_algoType = v;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        calculate();
    }
*/
    void watch(string msg, int v) {
        switch(msg) {
            case "_keySym_recordNo":
                  _keySym_recordNo = v;
                break;
            case "_keySym_algoStore":
                  _keySym_algoStore = v;
                break;
//            case "_keySym_keyLenBits":
//                  _keySym_keyLenBytes = v/8;
//                break;
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
    void watch(string msg, ubyte[32] v) {
        switch(msg) {
            case "_keySym_bytesStockAES":
                  _keySym_bytesStockAES = v;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        calculate();
    }
    void watch(string msg, ubyte[24] v) {
        switch(msg) {
            case "_keySym_bytesStockDES":
                  _keySym_bytesStockDES = v;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        calculate();
    }

    void calculate() {
        immutable _keySym_keyLenBytes =  keyLenBytesfromAlgoKeySym(_keySym_algoStore);
//        immutable blocksize = blocksizefromAlgoKeySym(_keySym_algoStore);
        _value = _value.init;
        _value[0] = 0x80 | cast(ubyte) _keySym_recordNo; // valid and key id (1-31) // Key ID 1 byte

        if (ctxTagNofromAlgoKeySym(_keySym_algoStore) != CtxTagNo.aesKey) // with AES, IntAuth and ExtAuth is unusable  TODO prevent that it can be set then
            _value[1] = cast(ubyte) (2*_keySym_IntAuthYN + _keySym_ExtAuthYN); // IntAuth and/or ExtAuth // Key Type 1 byte
        // Key Info  0-3 byte
        if (_keySym_IntAuthYN && _value[1]) // first UsageCounter, then ErrorCounterValueMod
            _value[2..4] = integral2uba!2(_keySym_IntAuthUsageCounterYN? _keySym_IntAuthUsageCounterValue : 0xFFFF)[0..2];
        if (_keySym_ExtAuthYN && _value[1])
            _value[2+2*_keySym_IntAuthYN] = cast(ubyte) (_keySym_ExtAuthErrorCounterYN? _keySym_ExtAuthErrorCounterValueMod : 0xFF);

        ubyte algoPos = cast(ubyte) (2+_value[1]); // 81 01 FF 14   010203...
        _value[algoPos] = cast(ubyte) _keySym_algoStore; // Algorithm Reference 1 byte
        _len = algoPos+1;
/*
        if (blocksizefromAlgoKeySym(_keySym_algoStore)==8) {
            import deimos.openssl.des : DES_cblock, DES_set_odd_parity, DES_is_weak_key;
            foreach (i; 0.._keySym_keyLenBytes/8) {
                DES_set_odd_parity (cast(DES_cblock*)(_keySym_bytesStock.ptr+i*8));
                if (DES_is_weak_key(cast(DES_cblock*)(_keySym_bytesStock.ptr+i*8)) == 1) {
                    _keySym_bytesStock = 0;
//                    return;
                }
            }
        }
*/
        if (blocksizefromAlgoKeySym(_keySym_algoStore)==16)
            _value[_len.._len+_keySym_keyLenBytes] = _keySym_bytesStockAES[0.._keySym_keyLenBytes];
        else
            _value[_len.._len+_keySym_keyLenBytes] = _keySym_bytesStockDES[0.._keySym_keyLenBytes];
        _len += _keySym_keyLenBytes;
////assumeWontThrow(writefln("  "~typeof(this).stringof~" object was set to value 0x %(%02X %)", _value[0.._len]));

        if (_h !is null) {
            _h.SetStringId2 ("", _lin, _col, ubaIntegral2string(_value[0.._len]));
            _h.Update;
        }
    }

//    mixin Pub_boilerplate!(_keySym_ByteStringStore, ubyte[37]);

    private :
    int        _keySym_recordNo;
    int        _keySym_algoStore =5;
//    int        _keySym_keyLenBytes;
    ubyte[32]  _keySym_bytesStockAES;
    ubyte[24]  _keySym_bytesStockDES;
    int        _keySym_ExtAuthYN;
    int        _keySym_IntAuthYN;
    int        _keySym_ExtAuthErrorCounterYN;
    int        _keySym_IntAuthUsageCounterYN;
    int        _keySym_ExtAuthErrorCounterValueMod;
    int        _keySym_IntAuthUsageCounterValue;

    int        _len;
    ubyte[38]  _value;
    int    _lin;
    int    _col;
    Handle _h;
} // class Obs_keySym_ByteStringStore

class Obs_change_calcSKDF {
    mixin(commonConstructor);

    @property  CtxTagNo*          getctn()           @nogc nothrow /*pure*/ @safe { return &ctn; }
    @property  PKCS15_ObjectTyp*  pkcs15_ObjectTyp() @nogc nothrow /*pure*/ @safe { return &_SKDFentry; }
    @property     const(int)      get()        const @nogc nothrow /*pure*/ @safe { return _value; }
//    @property     string          getKeyType() const @nogc nothrow /*pure*/ @safe { return keyType; }


    void watch(string msg, int v) {
        import core.bitop : bitswap;
        int asn1_result;
        int outLen;
        switch (msg) {
            case "_keySym_Id":
                if (_SKDFentry.structure_new !is null)
                    asn1_delete_structure(&_SKDFentry.structure_new);
                if (isNewKeyId) {
                    _SKDFentry = PKCS15_ObjectTyp.init;

                        /*
                        authId must be adapted
                        */
//A4 38 30 0A 0C 01 3F 03 02 06 C0 04 01 01 30 10 04 01 01 03 03 06 C0 00 03 02 03 B0 02 02 00 81 A0 04 02 02 00 C0 A1 12 30 10 30 0E 04 06 3F 00 41 00 41 02 02 01 01 80 01 00
                    _SKDFentry.der = (cast(immutable(ubyte)[])hexString!"A4 38 30 0A 0C 01 3F 03 02 06 C0 04 01 01 30 10 04 01 01 03 03 06 C0 00 03 02 03 B0 02 02 00 81 A0 04 02 02 00 C0 A1 12 30 10 30 0E 04 06 3F 00 41 00 41 02 02 01 01 80 01 00").dup;
                    ctn = cast(CtxTagNo) (_SKDFentry.der[0]-0xA0);
//                    keyType = name_SecretKeyType(ctn);
                    // all settings are preselected (except for keyAsym_authId) and must be set afterwards
////                    _SKDFentry.der[13] = cast(ubyte)keySym_authId.get; // FIXME
                    _SKDFentry.der[18] = cast(ubyte)nextUniqueId;
                    _SKDFentry.der[54] = cast(ubyte) keySym_recordNo.get;
                    _SKDFentry.der[31] = cast(ubyte)(keySym_recordNo.get | 0x80);

//                        _SKDFentry.der[30] = cast(ubyte)v;
                    /* CONVENTION, profile */
                    /* ATTENTION: _SKDFentry.structure will leak memory if no write operation occurs */
                    asn1_result = asn1_create_element(PKCS15, pkcs15_names[PKCS15_FILE_TYPE.PKCS15_SKDF][1], &_SKDFentry.structure); // "PKCS15.SecretKeyType"
                    if (asn1_result != ASN1_SUCCESS) {
                        assumeWontThrow(writeln("### Structure creation: ", asn1_strerror2(asn1_result)));
                        exit(1);
                    }
/+ +/
                        asn1_result = asn1_der_decoding(&_SKDFentry.structure, _SKDFentry.der, errorDescription);
                        if (asn1_result != ASN1_SUCCESS) {
                            assumeWontThrow(writeln("### asn1Decoding: ", errorDescription));
                            exit(1);
                        }
                        ubyte[16]  str; // verify, that a value for "...value.indirect.path.path" does exist for this Id
                        if ((asn1_result= asn1_read_value(_SKDFentry.structure, "des3Key.genericSecretKeyAttributes.value.indirect.path.path", str, outLen)) != ASN1_SUCCESS) {
                            assumeWontThrow(writefln("### asn1_read_value: %(%02X %)", _SKDFentry.der));
                            exit(1);
                        }
                        assert(v == getIdentifier(_SKDFentry, "des3Key.commonKeyAttributes.iD"));
/+ +/
                        tnTypePtr  skFile;
                        getNOR(skFile);
                        assert(skFile);

                        ubyte[16] tmp;
                        tmp[0..skFile.data[1]] = skFile.data[8..8+skFile.data[1]];
                        asn1_write_value(_SKDFentry.structure, (name_SecretKeyType(ctn)~".genericSecretKeyAttributes.value.indirect.path.path").toStringz, tmp.ptr, skFile.data[1]);
                }
                else {
                    /* never touch/change structure or der (only structure_new and der_new), except when updating to file ! */
                    int iD;
                    foreach (es; rangeExtractedSym(SKDF)) {
                        if (es.iD != v)
                            continue;
                        iD  = es.iD;
                        ctn = es.ctn;
//                        keyType = name_SecretKeyType(es.ctn);
                        _SKDFentry = es.elem;
                        break;
                    }
                    assert(iD>0);
                }

                assert(_SKDFentry.structure_new is null); // newer get's set in SKDF
                assert(_SKDFentry.der_new is null);       // newer get's set in SKDF
                _SKDFentry.structure_new = asn1_dup_node(_SKDFentry.structure, "");

////                assumeWontThrow(writefln("_old_encodedData of SKDFentry: %(%02X %)", _SKDFentry.der));

                break;
/+
            case "_keyAsym_authId":
                ubyte[1] authId = cast(ubyte)v; // optional
/*
                // remove, if authId==0, write if authId!=0
                if (authId==0)
                    asn1_write_value(_SKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.authId".ptr, null, 0);
                else
*/
                asn1_write_value(_SKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.authId", authId.ptr, 1);

                ubyte[1] flags; // optional
                asn1_result = asn1_read_value(_SKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.flags", flags, outLen);
                if (asn1_result != ASN1_SUCCESS) {
                    assumeWontThrow(writeln("### asn1_read_value privateRSAKey.commonObjectAttributes.flags: ", asn1_strerror2(asn1_result)));
                    break;
                }
                assert(outLen==2); // bits
                flags[0] = util_general.bitswap(flags[0]);

                ubyte[1] tmp = util_general.bitswap( cast(ubyte) ((flags[0]&0xFE) | (v!=0)) );
                asn1_write_value(_SKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.flags", tmp.ptr, 2); // 2 bits
                break;
+/
            case "_keySym_Modifiable":
                ubyte[1] flags; // optional
                asn1_result = asn1_read_value(_SKDFentry.structure_new, name_SecretKeyType(ctn)~".commonObjectAttributes.flags", flags, outLen);
                if (asn1_result != ASN1_SUCCESS) {
                    assumeWontThrow(writeln("### asn1_read_value "~name_SecretKeyType(ctn)~".commonObjectAttributes.flags: ", asn1_strerror2(asn1_result)));
                    break;
                }
//                assert(outLen==2); // bits
                flags[0] = util_general.bitswap(flags[0]);

                ubyte[1] tmp = util_general.bitswap( cast(ubyte) ((flags[0]&0xFD) | (v!=0)*2) );
                asn1_write_value(_SKDFentry.structure_new, (name_SecretKeyType(ctn)~".commonObjectAttributes.flags").toStringz, tmp.ptr, 2); // 2 bits
                break;

            case "_keySym_algoStore":
                ctn = ctxTagNofromAlgoKeySym(v);
////assumeWontThrow(writefln("##### ctn: %s", ctn));
//                keyType = name_SecretKeyType(ctn);
                break;

            case "_keySym_keyLenBits":
                ubyte[2] tmp = integral2uba!2(v);
                asn1_write_value(_SKDFentry.structure_new, (name_SecretKeyType(ctn)~".commonSecretKeyAttributes.keyLen").toStringz, tmp.ptr, cast(int)tmp.length);
                break;

            case "_keySym_global_local":
                tnTypePtr  skFile;
                getNOR(skFile);
                assert(skFile);

                ubyte[16] tmp;
                tmp[0..skFile.data[1]] = skFile.data[8..8+skFile.data[1]];
                asn1_write_value(_SKDFentry.structure_new, (name_SecretKeyType(ctn)~".genericSecretKeyAttributes.value.indirect.path.path").toStringz, tmp.ptr, skFile.data[1]);
                break;

            case "_keySym_recordNo":
                ubyte[1] index = [cast(ubyte)v];
                asn1_write_value(_SKDFentry.structure_new, (name_SecretKeyType(ctn)~".genericSecretKeyAttributes.value.indirect.path.index").toStringz, index.ptr, 1);
                break;

            case "_keySym_keyRef":
                ubyte[2] keyReference = integral2uba!2(v);
                asn1_write_value(_SKDFentry.structure_new, (name_SecretKeyType(ctn)~".commonKeyAttributes.keyReference").toStringz, keyReference.ptr, 2);
                break;

            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        present();
    }

    void watch(string msg, string v) {
        int asn1_result;
        switch (msg) {
            case "_keySym_Label":
                char[] label = v.dup ~ '\0';
//                GC.addRoot(cast(void*)label.ptr);
//                GC.setAttr(cast(void*)label.ptr, GC.BlkAttr.NO_MOVE);
                asn1_result = asn1_write_value(_SKDFentry.structure_new, (name_SecretKeyType(ctn)~".commonObjectAttributes.label").toStringz, label.ptr, 0);
                if (asn1_result != ASN1_SUCCESS)
                    assumeWontThrow(writeln("### asn1_write_value "~name_SecretKeyType(ctn)~".commonObjectAttributes.label: ", asn1_strerror2(asn1_result)));
                break;

            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        present();
    }

    void present()
    {
//        assert(_SKDFentry.posEnd); // it has been set
        _SKDFentry.der_new = new ubyte[_SKDFentry.der.length+32];
        int outDerLen;
        auto asn1_result = asn1_der_coding(_SKDFentry.structure_new, "", _SKDFentry.der_new, outDerLen, errorDescription);
        if (asn1_result != ASN1_SUCCESS)
        {
            printf ("\n### _SKDFentry.der_new encoding creation: ERROR  with Obs_change_calcSKDF\n");
//                    assumeWontThrow(writeln("### asn1Coding: ", errorDescription));
            return;
        }
        if (outDerLen)
            _SKDFentry.der_new.length = outDerLen;
        _value = cast(int)(_SKDFentry.der_new.length - _SKDFentry.der.length);


        if (ctn != CtxTagNo.unknown && _SKDFentry.der_new[0] != (0xA0|ctn)) {
////assumeWontThrow(writefln("#### mismatch [0] and ctn ! ctn: %s", ctn));
version(all) {
            _SKDFentry.der_new[0] = 0xA0|ctn;
            asn1_node  structure_new;
            asn1_result = asn1_create_element(PKCS15, pkcs15_names[PKCS15_FILE_TYPE.PKCS15_SKDF][1], &structure_new);

            if (asn1_result != ASN1_SUCCESS) {
                assumeWontThrow(writeln("### Structure creation: ", asn1_strerror2(asn1_result)));
                return;
            }
            asn1_result = asn1_der_decoding(&structure_new, _SKDFentry.der_new, errorDescription);
            if (asn1_result != ASN1_SUCCESS) {
                assumeWontThrow(writeln("### asn1Decoding: ", errorDescription));
                return;
            }
            asn1_delete_structure(&_SKDFentry.structure_new);
            _SKDFentry.structure_new = structure_new;
}
        }
////assumeWontThrow(writefln("  "~typeof(this).stringof~" object was set"));
////assumeWontThrow(writefln("  _new_encodedData of SKDFentry: %(%02X %)", _SKDFentry.der_new));
//        emit("_change_calcSKDF", _value);
        if (_h !is null) {
            _h.SetIntegerId2("", _lin, _col, _value);
            _h.Update;
        }
    }

//    mixin Signal!(string, int);

    private :
//        string    keyType;
        CtxTagNo  ctn = CtxTagNo.unknown;
        int               _value;
        PKCS15_ObjectTyp  _SKDFentry;

        int    _lin;
        int    _col;
        Handle _h;
}

struct ExtractedSym {
    CtxTagNo ctn;
    int iD;
    int recNo;
    ubyte[] path;
    PKCS15_ObjectTyp elem;
}

struct RangeExtractedSym {
    PKCS15_ObjectTyp[] arr;

    this(PKCS15_ObjectTyp[] in_arr) nothrow {
        arr = in_arr;
    }
/*
What do we want to know from SKDF ?

Welche iD kommen in SKDF vor

finde SKDFentry für bestimmte iD

welcher pfad gehört zu einem SKDFentry
welcher recordNo

            auto x = chain(SKDF.filter!(a => getPath(a, "des3Key.genericSecretKeyAttributes.value.indirect.path.path",false,false).length==4+2*keySym_global_local.get),
                           SKDF.filter!(a => getPath(a,  "aesKey.genericSecretKeyAttributes.value.indirect.path.path",false,false).length==4+2*keySym_global_local.get) );
foreach (i; indexed([EnumMembers!CtxTagNo], [2,3,1,0])) { //des3Key, aesKey, des2Key, desKey
*/
    int opApply(int delegate(ExtractedSym)  dg) nothrow {
        int result; /* continue as long as result==0 */
        ExtractedSym es;
        foreach (elem; arr) {
            if      ((es.iD= getIdentifier(elem, "des3Key.commonKeyAttributes.iD", false, false)) > 0)
                es.ctn = CtxTagNo.des3Key;
            else if ((es.iD= getIdentifier(elem,  "aesKey.commonKeyAttributes.iD", false, false)) > 0)
                es.ctn = CtxTagNo.aesKey;
            else if ((es.iD= getIdentifier(elem, "des2Key.commonKeyAttributes.iD", false, false)) > 0)
                es.ctn = CtxTagNo.des2Key;
            else if ((es.iD= getIdentifier(elem,  "desKey.commonKeyAttributes.iD", false, false)) > 0)
                es.ctn = CtxTagNo.desKey;
            else
            {    assert(0); }

            if ((es.recNo= getIdentifier(elem, name_SecretKeyType(es.ctn)~".genericSecretKeyAttributes.value.indirect.path.index")) < 0)
            {    assert(0); }

            if ((es.path=        getPath(elem, name_SecretKeyType(es.ctn)~".genericSecretKeyAttributes.value.indirect.path.path") ) is null)
            {    assert(0); }

            es.elem = elem;

            try // allow throwing foreach bodies
                if ((result= dg(es)) != 0)
                    break;
            catch (Exception e) { printf("### Exception in rangeExtractedSym.opApply\n"); /* todo: handle exception */ }
        }
        return result;
    }

}

RangeExtractedSym rangeExtractedSym(PKCS15_ObjectTyp[] skdf) nothrow { return RangeExtractedSym(skdf); }

enum CtxTagNo : ubyte {
    desKey  = 2,
    des2Key = 3,
    des3Key = 4,
    aesKey  = 15,

    unknown = 255
}

string name_SecretKeyType(CtxTagNo ctxTag) nothrow {
    final switch (ctxTag) {
        case CtxTagNo.desKey:   return "desKey";
        case CtxTagNo.des2Key:  return "des2Key";
        case CtxTagNo.des3Key:  return "des3Key";
        case CtxTagNo.aesKey:   return "aesKey";

        case CtxTagNo.unknown:  return "unknown";
    }
}

void synchronize_global_local_record_Id() nothrow {
    if (keySym_recordNo.get==0)
        return;

    foreach (es; rangeExtractedSym(SKDF)) {
        if (es.path.length==4+2*keySym_global_local.get && es.recNo==keySym_recordNo.get) {
            keySym_Id.set(es.iD, true);
            break;
        }
        AA["matrixKeySym"].SetStringId2 ("", r_keySym_Id, 1, "");
    }
}

int nextUniqueKeyId() nothrow {
    int[] keyIdAllowed = iota(1,31).array;

    foreach (es; rangeExtractedSym(SKDF))
        keyIdAllowed.remove!(a => a == es.iD);

    import util_opensc : PRKDF;
    foreach (ref elem; PRKDF)
        keyIdAllowed.remove!(a => a == getIdentifier(elem, "privateRSAKey.commonKeyAttributes.iD"));

    return keyIdAllowed.empty? -1 : keyIdAllowed.front;//result;
}

int searchID(ubyte recNo, ubyte global_local) nothrow {
    foreach (es; rangeExtractedSym(SKDF))
        if (es.path.length==4+2*global_local && es.recNo==recNo)
            return  es.iD;
    return 0;
}

void searchAndSetRecordNoUnused() nothrow {
            //check whether keySym_recordNo is not suitable because already used in SKDF

            bool doSelectNew;
            foreach (es; rangeExtractedSym(SKDF))
                if (es.path.length==4+2*keySym_global_local.get && es.recNo==keySym_recordNo.get) {
                    doSelectNew = true;
                    break;
                }
            if (doSelectNew) {
                tnTypePtr  dummy;
                int NOR = getNOR(dummy);

                int i;
outerLoop:
                foreach (j; 1..1+NOR) {
                    foreach (es; rangeExtractedSym(SKDF))
                        if (es.path.length==4+2*keySym_global_local.get && es.recNo==j)
                            continue outerLoop;
                    AA["matrixKeySym"].SetIntegerId("", ++i, j);
                    keySym_recordNo.set(j, true);
//                    synchronize_global_local_record_Id();
                    break;
                }
            }
}

int getNOR(out tnTypePtr  keySym_file) nothrow {
                ubyte NOR;
                sitTypeFS  pos_parent =  new sitTypeFS(keySym_global_local.get? appdf : fs.begin().node);
//                tnTypePtr  keySym_file;
                try {
                    keySym_file = fs.siblingRange(fs.begin(pos_parent), fs.end(pos_parent)).locate!"a[0]==b"(EFDB.Sym_Key_EF);
                    if (keySym_file)
                        NOR = keySym_file.data[5];
                }
                catch (Exception e) { printf("### Exception in matrixKeySym_drop_cb() for r_keySym_recordNo\n"); /* todo: handle exception */ }
                return NOR;
}

void set_more_for_global_local(int status_global_local) nothrow {
////    printf("set_more_for_global_local (%d)\n", status_global_local);
    keySym_fidAppDir.set(status_global_local? (appdf is null? 0 : ub22integral(appdf.data[2..4])) : 0x3F00, true);

    tnTypePtr  keySym_file;
    int NOR = getNOR(keySym_file);
    keySym_fid.set(keySym_file is null? 0 : ub22integral(keySym_file.data[2..4]), true);

    if (AA["radioKeySym"].GetStringVALUE() != "toggle_sym_create_write") {
        if (keySym_file && keySym_recordNo.get>NOR) {
//            AA["matrixKeySym"].SetStringId2 ("", r_keySym_recordNo, 1, "");
            keySym_recordNo.set(NOR, true);
            printf("################set_more_for_global_local (%d)\n", status_global_local);
        }
    }
    else {
            bool doSelectNew;
            foreach (es; rangeExtractedSym(SKDF))
                if (es.path.length==4+2*keySym_global_local.get && es.recNo==keySym_recordNo.get) {
                    doSelectNew = true;
                    break;
                }
            if (doSelectNew) {

                int i;
outerLoop:
                foreach (j; 1..1+keySym_file.data[5]) {
                    foreach (es; rangeExtractedSym(SKDF))
                        if (es.path.length==4+2*keySym_global_local.get && es.recNo==j)
                            continue outerLoop;
                    keySym_recordNo.set(j, true);
                    break;
                }
            }
    }
}

int set_more_for_keySym_Id(int keySym_Id) nothrow {
    assert(keySym_Id > 0);

    import core.bitop : bitswap;


//    immutable activeToggle = AA["radioKeySym"].GetStringVALUE();
////    assumeWontThrow(writefln("activeToggle: %s", activeToggle));
////    printf("set_more_for_keySym_Id (%d)\n", keySym_Id);

    int  asn1_result;
    int  outLen;

    CtxTagNo*          ctn       = change_calcSKDF.getctn;
    PKCS15_ObjectTyp*  SKDFentry = change_calcSKDF.pkcs15_ObjectTyp;
//    string             keyType   = change_calcSKDF.getKeyType;

    ubyte[1] flags; // optional
    asn1_result = asn1_read_value(SKDFentry.structure_new, name_SecretKeyType(*ctn)~".commonObjectAttributes.flags", flags, outLen);
    if (asn1_result != ASN1_SUCCESS)
        assumeWontThrow(writeln("### asn1_read_value "~name_SecretKeyType(*ctn)~".commonObjectAttributes.flags: ", asn1_strerror2(asn1_result)));
    else {
//        assert(outLen==2); // bits
        flags[0] = util_general.bitswap(flags[0]);

        keySym_Modifiable.set((flags[0]&2)/2, true);

//        if (!keyPairModifiable.get &&  activeToggle.among("toggle_RSA_key_pair_delete", "toggle_RSA_key_pair_regenerate") ) {
//            IupMessage("Feedback upon setting keyPairId",
//"The PrKDF entry for the selected keyPairId disallows modifying the RSA private key !\nThe toggle will be changed to toggle_RSA_PrKDF_PuKDF_change toggled");
//            AA["toggle_RSA_PrKDF_PuKDF_change"].SetIntegerVALUE(1);
//            toggle_RSA_cb(AA["toggle_RSA_PrKDF_PuKDF_change"].GetHandle, 1);
//        }
    }

    ubyte[1] authId; // optional
    asn1_result = asn1_read_value(SKDFentry.structure_new, name_SecretKeyType(*ctn)~".commonObjectAttributes.authId", authId, outLen);
    if (asn1_result != ASN1_SUCCESS) {
        assumeWontThrow(writeln("### asn1_read_value "~name_SecretKeyType(*ctn)~".commonObjectAttributes.authId: ", asn1_strerror2(asn1_result)));
    }
    else {
        assert(outLen==1);
        if (authId[0])
        {    assert(flags[0]&1); } // may run into a problem if asn1_read_value for flags failed
        keySym_authId.set(authId[0], true);
    }

    { // make label inaccessible when leaving the scope
        char[] label = new char[65]; // optional
        label[0..65] = '\0';
        asn1_result = asn1_read_value(SKDFentry.structure_new, name_SecretKeyType(*ctn)~".commonObjectAttributes.label", label, outLen);
        if (asn1_result != ASN1_SUCCESS) {
            assumeWontThrow(writeln("### asn1_read_value "~name_SecretKeyType(*ctn)~".commonObjectAttributes.label: ", asn1_strerror2(asn1_result)));
        }
        else
            keySym_Label.set(assumeUnique(label[0..outLen]), true);
    }

    ubyte[2] keyUsageFlags; // non-optional
    asn1_result = asn1_read_value(SKDFentry.structure_new, name_SecretKeyType(*ctn)~".commonKeyAttributes.usage", keyUsageFlags, outLen);
    if (asn1_result != ASN1_SUCCESS)
        assumeWontThrow(writeln("### asn1_read_value "~name_SecretKeyType(*ctn)~".commonKeyAttributes.usage: ", asn1_strerror2(asn1_result)));
    else {
//        assert(outLen==10); // bits
////assumeWontThrow(writefln("keyUsageFlags: %(%02X %)", keyUsageFlags));
        keySym_usageSKDF.set( bitswap(ub22integral(keyUsageFlags)<<16), true);
    }

    ubyte[2] keyLength; // non-optional
    asn1_result = asn1_read_value(SKDFentry.structure_new, name_SecretKeyType(*ctn)~".commonSecretKeyAttributes.keyLen", keyLength, outLen);
    if (asn1_result != ASN1_SUCCESS) //== ASN1_ELEMENT_NOT_FOUND)
        assumeWontThrow(writeln("### asn1_read_value "~name_SecretKeyType(*ctn)~".commonSecretKeyAttributes.keyLen: ", asn1_strerror2(asn1_result)));
    else {
      assert(outLen.among(1,2));
//assumeWontThrow(writefln("modulusLength set by set_more_for_keyPairId: %(%02X %)", modulusLength));
      immutable keyLenBits = ub22integral(keyLength);
      assert(keyLenBits%64==0 && keyLenBits>=64  && keyLenBits<=256);
      keySym_keyLenBits.set(keyLenBits, true);
// for des3Key only
//assert(keyLenBits==256);
    }
    keySym_algoType.set(*ctn==CtxTagNo.aesKey? "AES" : "DES", true);

    ubyte[1] index; // optional, but do require that here !
    asn1_result = asn1_read_value(SKDFentry.structure_new, name_SecretKeyType(*ctn)~".genericSecretKeyAttributes.value.indirect.path.index", index, outLen);
    if (asn1_result != ASN1_SUCCESS) { //== ASN1_ELEMENT_NOT_FOUND)
        assumeWontThrow(writeln("### asn1_read_value "~name_SecretKeyType(*ctn)~".commonKeyAttributes.keyReference: ", asn1_strerror2(asn1_result)));
        assert(0);
    }
    assert(outLen==1);
//assumeWontThrow(writefln("modulusLength set by set_more_for_keyPairId: %(%02X %)", modulusLength));
    keySym_recordNo.set(index[0], true);

    ubyte[] path = getPath(*SKDFentry, name_SecretKeyType(*ctn)~".genericSecretKeyAttributes.value.indirect.path.path", true, false);
    assert(path.length);
    keySym_global_local.set(path.length>4, true);

    ubyte[2] keyReference; // optional
    asn1_result = asn1_read_value(SKDFentry.structure_new, name_SecretKeyType(*ctn)~".commonKeyAttributes.keyReference", keyReference, outLen);
    if (asn1_result != ASN1_SUCCESS) //== ASN1_ELEMENT_NOT_FOUND)
        assumeWontThrow(writeln("### asn1_read_value "~name_SecretKeyType(*ctn)~".commonKeyAttributes.keyReference: ", asn1_strerror2(asn1_result)));
    else {
        assert(outLen.among(1,2));
//assumeWontThrow(writefln("modulusLength set by set_more_for_keyPairId: %(%02X %)", modulusLength));
        immutable keyRefInt = ub22integral(keyReference)/*&0x7F*/; // strip the local bit
        assert(keySym_keyRef.get == keyRefInt);
    }

/*
    name: commonKeyAttributes  type: SEQUENCE
      name: iD  type: OCT_STR  value: 01
      name: keyReference  type: INTEGER  value: 0x01
    name: genericSecretKeyAttributes  type: SEQUENCE
      name: value  type: CHOICE
        name: indirect  type: CHOICE
          name: path  type: SEQUENCE
            name: path  type: OCT_STR  value: 3f004100
*/
    isNewKeyId = false;

    return 0;
}

extern(C) nothrow :

//        case "toggle_sym_SKDF_change",
//             "toggle_sym_delete",
//             "toggle_sym_update",
//             "toggle_sym_updateSMkeyHost",
//             "toggle_sym_updateSMkeyCard",
//             "toggle_sym_create_write",
//             "toggle_sym_enc_dec":  break;
//activeToggle.among("toggle_sym_SKDF_change", "toggle_sym_delete", "toggle_sym_update", "toggle_sym_updateSMkeyHost", "toggle_sym_updateSMkeyCard", "toggle_sym_create_write", "toggle_sym_enc_dec")

int matrixKeySym_dropcheck_cb(Ihandle* /*self*/, int lin, int col) {
    if (col!=1 /*|| lin>r_keySym_global_local*/)
        return IUP_IGNORE; // draw nothing
//    printf("matrixKeySym_dropcheck_cb(%d, %d)\n", lin, col);
//    printf("matrixKeySym_dropcheck_cb  %s\n", AA["radioKeySym"].GetAttributeVALUE());
    immutable activeToggle = AA["radioKeySym"].GetStringVALUE();
    immutable isSelectedKeyId = AA["matrixKeySym"].GetIntegerId2("", r_keySym_Id, 1) != 0;
    switch (lin) {
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
                return IUP_DEFAULT; // show the dropdown/popup menu
            break;

        case r_keySym_algoType, r_keySym_keyLenBits:
            if (activeToggle.among("toggle_sym_update", "toggle_sym_create_write") && isSelectedKeyId)
                return IUP_DEFAULT; // show the dropdown/popup menu
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


int matrixKeySym_drop_cb(Ihandle* /*self*/, Ihandle* drop, int lin, int col) {
    if (col!=1 /*|| lin.among(r_keySym_global_local)*/)
        return IUP_IGNORE; // draw nothing
//    printf("matrixKeySym_drop_cb(%d, %d)\n", lin, col);
    immutable activeToggle = AA["radioKeySym"].GetStringVALUE();
//    ubyte[2]  str;
//    int outLen;
//    int asn1_result, rv;
    with (createHandle(drop))
    switch (lin) {
        case r_keySym_Id:
            if (activeToggle.among("toggle_sym_SKDF_change",
                                   "toggle_sym_delete",
                                   "toggle_sym_update",
                                   "toggle_sym_enc_dec"))
            {
                int i;
                foreach (es; rangeExtractedSym(SKDF))
                    SetIntegerId("", ++i, es.iD);
                SetAttributeId("", ++i, null);
                SetAttributeStr(IUP_VALUE, null);
                return IUP_DEFAULT; // show a dropdown field
            }
            break;

        case r_keySym_recordNo:
            if (activeToggle=="toggle_sym_create_write") {
                tnTypePtr  dummy;
                int NOR = getNOR(dummy);

                int i;
outerLoop:
                foreach (j; 1..1+NOR) {
                    foreach (es; rangeExtractedSym(SKDF))
                        if (es.path.length==4+2*keySym_global_local.get && es.recNo==j)
                            continue outerLoop;
                    SetIntegerId("", ++i, j);
                }
                SetAttributeId("", ++i, null);
                SetAttributeStr(IUP_VALUE, null);
                return IUP_DEFAULT; // show the dropdown/popup menu
            }
            break;

        case r_keySym_algoType:
            if (activeToggle.among("toggle_sym_update", "toggle_sym_create_write")) {
                SetAttributeId("", 1, "AES");
                SetAttributeId("", 2, "DES");
                SetAttributeId("", 3, null);
                SetAttributeStr(IUP_VALUE, null);
                return IUP_DEFAULT; // show a dropdown field
            }
            break;

        case r_keySym_keyLenBits:
            if (activeToggle.among("toggle_sym_update", "toggle_sym_create_write")) {
                if (keySym_algoType.get=="AES") {
                    SetAttributeId("", 1, "128");
                    SetAttributeId("", 2, "192");
                    SetAttributeId("", 3, "256");
                }
                else { // if (keySym_algoType.get=="DES")
                    SetAttributeId("", 1, "64");
                    SetAttributeId("", 2, "128");
                    SetAttributeId("", 3, "192");
                }
                SetAttributeId("", 4, null);
                SetAttributeStr(IUP_VALUE, null);
                return IUP_DEFAULT; // show a dropdown field
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
    if (v/*selected*/ && col==1) {
        Handle h = createHandle(self);

        switch (lin) {
            case r_keySym_Id:
                keySym_Id.set = h.GetIntegerVALUE;
                break;

            case r_keySym_algoType:
                keySym_algoType.set = h.GetStringVALUE();
                if (keySym_algoType.get=="AES") {
/*
                    with (AA["matrixKeySym"]) {
                        SetIntegerId(IUP_HEIGHT, r_keySym_ExtAuthYN,                0);
                        SetIntegerId(IUP_HEIGHT, r_keySym_ExtAuthErrorCounterYN,    0);
                        SetIntegerId(IUP_HEIGHT, r_keySym_ExtAuthErrorCounterValue, 0);
                        SetIntegerId(IUP_HEIGHT, r_keySym_IntAuthYN,                0);
                        SetIntegerId(IUP_HEIGHT, r_keySym_IntAuthUsageCounterYN,    0);
                        SetIntegerId(IUP_HEIGHT, r_keySym_IntAuthUsageCounterValue, 0);
                    }
*/
                    keySym_ExtAuthYN.set(0, true);
                    keySym_IntAuthYN.set(0, true);
//matrixKeySym_togglevalue_cb(Ihandle* /*self*/, int lin, int col, int status)
                }
                else {
/*
                    with (AA["matrixKeySym"]) {
                        SetIntegerId(IUP_HEIGHT, r_keySym_ExtAuthYN,              6);
//                        SetIntegerId(IUP_HEIGHT, r_keySym_ExtAuthErrorCounterYN,    0);
//                        SetIntegerId(IUP_HEIGHT, r_keySym_ExtAuthErrorCounterValue, 0);
                        SetIntegerId(IUP_HEIGHT, r_keySym_IntAuthYN,              6);
//                        SetIntegerId(IUP_HEIGHT, r_keySym_IntAuthUsageCounterYN,    0);
//                        SetIntegerId(IUP_HEIGHT, r_keySym_IntAuthUsageCounterValue, 0);
                    }
*/
                }
                break;

            case r_keySym_keyLenBits:
                keySym_keyLenBits.set = h.GetIntegerVALUE();
                break;

             case r_keySym_recordNo:
                keySym_recordNo.set = h.GetIntegerVALUE();
//                synchronize_global_local_record_Id();
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
    if (mode==1) {
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
        if (!isSelectedKeyId) {
            if (lin.among(r_keySym_Label))
                return IUP_IGNORE;
        }
        // readonly, condition  activeToggle
        switch (activeToggle) {
            case "toggle_sym_SKDF_change":
                if (lin.among(r_keySym_recordNo,

                              r_keySym_algoType,
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

                              r_keySym_algoType,
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

                              r_keySym_algoType,
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

                              r_keySym_algoType,
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

                              r_keySym_algoType,
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
    switch (lin) {
        case r_keySym_algoType:
            // postprocess for keySym_algoType, set in matrixKeySym_dropselect_cb
            if      (keySym_algoType.get=="AES" && keySym_keyLenBits.get==64)
              keySym_keyLenBits.set(128, true);
            else if (keySym_algoType.get=="DES" && keySym_keyLenBits.get==256)
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

            import deimos.openssl.des : DES_cblock, DES_set_odd_parity, DES_is_weak_key;
            foreach (i; 0..3/*keyLen/blocksize*/) {
                auto p = cast(DES_cblock*)(tmp.ptr+i*8);
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


/*
matrixKeySym_edition_cb(7, 1) mode: 1, update: 0

matrixKeySym_drop_cb(7, 1)
matrixKeyAsym_dropselect_cb(lin: 7, col: 1, text (t) of the item whose state was changed: AES, mumber (i) of the item whose state was changed: 1, selected (v): 1)
_keySym_algoType object was set to value AES

matrixKeySym_edition_cb(7, 1) mode: 0, update: 1
*/


int matrixKeySym_togglevalue_cb(Ihandle* /*self*/, int lin, int /*col*/, int status) {
//    assert(col==1 && lin.among(r_keyPairModifiable, r_storeAsCRTRSAprivate));
//    printf("matrixKeySym_togglevalue_cb(%d, %d) status: %d\n", lin, col, status);
//            bool isSelectedKeyId = AA["matrixKeySym"].GetIntegerId2("", r_keySym_Id, 1) != 0;
    switch (lin) {
        case r_keySym_Modifiable:
            keySym_Modifiable.set = status;
            break;

        case r_keySym_global_local:
            keySym_global_local.set = status;
//            synchronize_global_local_record_Id();
            break;

        case r_keySym_ExtAuthYN:
               keySym_ExtAuthYN.set = status;
/*
            with (AA["matrixKeySym"]) {
                SetIntegerId(IUP_HEIGHT, r_keySym_ExtAuthErrorCounterYN,    status? 6 : 0);
                SetIntegerId(IUP_HEIGHT, r_keySym_ExtAuthErrorCounterValue, status && keySym_ExtAuthErrorCounterYN.get? 6 : 0);
            }
*/
            break;

        case r_keySym_IntAuthYN:
               keySym_IntAuthYN.set = status;
/*
            with (AA["matrixKeySym"]) {
                SetIntegerId(IUP_HEIGHT, r_keySym_IntAuthUsageCounterYN,    status? 6 : 0);
                SetIntegerId(IUP_HEIGHT, r_keySym_IntAuthUsageCounterValue, status && keySym_IntAuthUsageCounterYN.get? 6 : 0);
            }
*/
            break;

        case r_keySym_ExtAuthErrorCounterYN:
               keySym_ExtAuthErrorCounterYN.set = status;
//            AA["matrixKeySym"].SetIntegerId(IUP_HEIGHT, r_keySym_ExtAuthErrorCounterValue, status? 6 : 0);
            break;

        case r_keySym_IntAuthUsageCounterYN:
               keySym_IntAuthUsageCounterYN.set = status;
//            AA["matrixKeySym"].SetIntegerId(IUP_HEIGHT, r_keySym_IntAuthUsageCounterValue, status? 6 : 0);
            break;

        default: break;
    }
    return IUP_DEFAULT;
}

int toggle_radioKeySym_cb(Ihandle* ih, int state)
{
////    printf("toggle_radioKeySym_cb (%d) %s\n", state, IupGetName(ih));
    if (state==0) { // for the toggle, that lost activated state
        /* if the keyAsym_Id is not valid (e.g. prior selected was "toggle_RSA_key_pair_create_and_generate" but no creation was invoked)
           then select a valid one */
        Handle h = AA["matrixKeySym"];
        immutable inactivatedToggle = IupGetName(ih).fromStringz.idup;
        //check whether keySym_recordNo is suitable because used in SKDF
        if (inactivatedToggle=="toggle_sym_create_write") {
            bool doSelectNew = true;
            int recNo;
            foreach (es; rangeExtractedSym(SKDF)) {
                if (es.path.length!=4+2*keySym_global_local.get)
                    continue;
                recNo = es.recNo;
                if (es.recNo==keySym_recordNo.get) {
                    doSelectNew = false;
                    break;
                }
            }
            if (doSelectNew) {
                if (recNo>0) {
                    keySym_recordNo.set(recNo, true);
                    synchronize_global_local_record_Id();
                }
                else {
                    keySym_global_local.set(!keySym_global_local.get, true);
                    foreach (es; rangeExtractedSym(SKDF)) {
                        if (es.path.length!=4+2*keySym_global_local.get)
                            continue;
                        keySym_recordNo.set(es.recNo, true);
                        break;
                    }
                    synchronize_global_local_record_Id();
                }
            }
        }
        AA["statusbar"].SetString(IUP_TITLE, "statusbar");
        return IUP_DEFAULT;
    }

    Handle hButton = AA["button_radioKeySym"];
    string activeToggle = AA["radioKeySym"].GetStringVALUE();
    with (AA["matrixKeySym"])
    switch (activeToggle) {
        case "toggle_sym_SKDF_change":
            hButton.SetString(IUP_TITLE, "SKDF only: Change some administrative (PKCS#15) data");
            SetRGBId2(IUP_BGCOLOR, r_keySym_Id,           1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_recordNo,     1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_global_local, 1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keySym_Label,       1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_Modifiable,  1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_algoType,    1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_keyLenBits,  1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthYN,                1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthUsageCounterYN,    1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthUsageCounterValue, 1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthYN,                1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthErrorCounterYN,    1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthErrorCounterValue, 1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keySym_bytesStockAES, 1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_bytesStockDES, 1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_fromfile,          1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_tofile,            1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_iv,                1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_mode,              1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_enc_dec,           1,  255,255,255);
            break;
        case "toggle_sym_delete":
            hButton.SetString(IUP_TITLE, "Delete key record's content (select by key id)");
            SetRGBId2(IUP_BGCOLOR, r_keySym_Id,           1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_recordNo,     1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_global_local, 1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keySym_Label,       1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_Modifiable,  1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_algoType,    1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_keyLenBits,  1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthYN,                1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthUsageCounterYN,    1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthUsageCounterValue, 1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthYN,                1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthErrorCounterYN,    1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthErrorCounterValue, 1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keySym_bytesStockAES, 1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_bytesStockDES, 1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_fromfile,          1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_tofile,            1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_iv,                1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_mode,              1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_enc_dec,           1,  255,255,255);
            break;
        case "toggle_sym_update":
            hButton.SetString(IUP_TITLE, "Update/Write a key file record");
            SetRGBId2(IUP_BGCOLOR, r_keySym_Id,           1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_recordNo,     1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_global_local, 1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keySym_Label,       1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_Modifiable,  1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_algoType,    1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_keyLenBits,  1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthYN,                1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthUsageCounterYN,    1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthUsageCounterValue, 1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthYN,                1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthErrorCounterYN,    1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthErrorCounterValue, 1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_keySym_bytesStockAES, 1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_bytesStockDES, 1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_fromfile,          1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_tofile,            1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_iv,                1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_mode,              1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_enc_dec,           1,  255,255,255);
            break;

        case "toggle_sym_updateSMkeyHost":
            hButton.SetString(IUP_TITLE, "Update/Write a key file record");
            SetRGBId2(IUP_BGCOLOR, r_keySym_Id,           1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_recordNo,     1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_global_local, 1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keySym_Label,       1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_Modifiable,  1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_algoType,    1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_keyLenBits,  1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthYN,                1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthUsageCounterYN,    1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthUsageCounterValue, 1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthYN,                1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthErrorCounterYN,    1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthErrorCounterValue, 1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_keySym_bytesStockAES, 1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_bytesStockDES, 1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_fromfile,          1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_tofile,            1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_iv,                1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_mode,              1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_enc_dec,           1,  255,255,255);
// if key SMkeyHost doesn't exist already, then this is not suitable: change to "toggle_sym_create_write" with some pre-settings
// otherwise select the iD and set it
            int iD = searchID(1,1);
            assert(iD>0);
            keySym_Id.set(iD, true);
            keySym_ExtAuthYN.set(true,  true);
            keySym_IntAuthYN.set(false, true);
            break;

        case "toggle_sym_updateSMkeyCard":
            hButton.SetString(IUP_TITLE, "Update/Write a key file record");
            SetRGBId2(IUP_BGCOLOR, r_keySym_Id,           1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_recordNo,     1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_global_local, 1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keySym_Label,       1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_Modifiable,  1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_algoType,    1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_keyLenBits,  1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthYN,                1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthUsageCounterYN,    1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthUsageCounterValue, 1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthYN,                1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthErrorCounterYN,    1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthErrorCounterValue, 1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keySym_bytesStockAES, 1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_bytesStockDES, 1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_fromfile,          1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_tofile,            1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_iv,                1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_mode,              1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_enc_dec,           1,  255,255,255);

// if key SMkeyCard doesn't exist already, then this is not suitable: change to "toggle_sym_create_write" with some pre-settings
// otherwise select the iD and set it
            int iD = searchID(2,1);
            assert(iD>0);
            keySym_Id.set(iD, true);
//            keySym_recordNo.set(2, true);
//            keySym_global_local.set(true, true);
//            synchronize_global_local_record_Id();
//            keySym_algoType.set("DES", true);
//            keySym_keyLenBits.set(192, true);
            keySym_ExtAuthYN.set(false, true);
            keySym_IntAuthYN.set(true,  true);
            break;

        case "toggle_sym_create_write":
            hButton.SetString(IUP_TITLE, "Write new key file record and add to SKDF");
            SetRGBId2(IUP_BGCOLOR, r_keySym_Id,           1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_recordNo,     1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_global_local, 1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_keySym_Label,       1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_Modifiable,  1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_algoType,    1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_keyLenBits,  1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthYN,                1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthUsageCounterYN,    1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthUsageCounterValue, 1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthYN,                1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthErrorCounterYN,    1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthErrorCounterValue, 1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_keySym_bytesStockAES, 1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_bytesStockDES, 1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_fromfile,          1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_tofile,            1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_iv,                1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_mode,              1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_enc_dec,           1,  255,255,255);
            // must select a record in file global/local, that isn't present in SKDF
            // similar task for matrixKeySym_drop_cb for keySym_recordNo
            searchAndSetRecordNoUnused();
            isNewKeyId = true;
            nextUniqueId = nextUniqueKeyId();
            assert(nextUniqueId>0);
            keySym_Id.set(nextUniqueId, true);
            break;

        case "toggle_sym_enc_dec":
            hButton.SetString(IUP_TITLE, "Encrypt or Decrypt fromfile -> tofile");
            SetRGBId2(IUP_BGCOLOR, r_keySym_Id,           1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keySym_recordNo,     1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_global_local, 1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keySym_Label,       1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_Modifiable,  1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_algoType,    1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_keyLenBits,  1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthYN,                1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthUsageCounterYN,    1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_IntAuthUsageCounterValue, 1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthYN,                1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthErrorCounterYN,    1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_ExtAuthErrorCounterValue, 1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_keySym_bytesStockAES, 1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keySym_bytesStockDES, 1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_fromfile,          1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_tofile,            1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_iv,                1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_mode,              1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_enc_dec,           1,  152,251,152);
            break;

        default:
            break;
    }
    return IUP_DEFAULT;
}


ubyte algoECB_MSEfromAlgoKeySym(int algoKeySym) {
    switch (algoKeySym) {
        case 0x02, 0x03, 0x12, 0x13, 0x22, 0x23: /*  AES */ return 4;
        case 0x04, 0x14:                         /* 3DES */ return 0;
        case 0x05:                               /*  DES */ return 1;
        case 0x00, 0x01: // mixed (3)DES / AES : don't use that
                assert(0);
       default: assert(0);
    }
}

ubyte blocksizefromAlgoKeySym(int algoKeySym) {
    switch (algoKeySym) {
        case 0x02, 0x03, 0x12, 0x13, 0x22, 0x23: /*  AES */ return 16;
        case 0x04, 0x14,                         /* 3DES */
             0x05:                               /*  DES */ return 8;
        case 0x00, 0x01: // mixed (3)DES / AES : don't use that
                assert(0);
       default: assert(0);
    }
}

ubyte keyLenBytesfromAlgoKeySym(int algoKeySym) {
    switch (algoKeySym) {
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

CtxTagNo ctxTagNofromAlgoKeySym(int algoKeySym) {
    switch (algoKeySym) {
        case 0x02, 0x03: /*  AES */ return CtxTagNo.aesKey;
        case 0x12, 0x13: /*  AES */ return CtxTagNo.aesKey;
        case 0x22, 0x23: /*  AES */ return CtxTagNo.aesKey;
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
//    ubyte keyLen =  keyLenBytesfromAlgoKeySym(keySym_algoStore.get);
//    ubyte blocksize = blocksizefromAlgoKeySym(keySym_algoStore.get);
    int rv;
    ubyte[32] tmp;
    if ((rv= RAND_bytes(tmp.ptr, 32/*keyLen*/)) == 0) {
//        mixin (log!(__FUNCTION__, "Generate random error: %i", "rv"));
        return IUP_DEFAULT;
    }
    keySym_bytesStockAES.set(tmp, true);
    /*if (blocksize==8)*/ {
        import deimos.openssl.des : DES_cblock, DES_set_odd_parity, DES_is_weak_key;
        foreach (i; 0..3/*keyLen/blocksize*/) {
            auto p = cast(DES_cblock*)(tmp.ptr+i*8);
            DES_set_odd_parity (p);
            if (DES_is_weak_key(p) == 1)
                return IUP_DEFAULT;
//              return IUP_IGNORE;
        }
    }
    keySym_bytesStockDES.set(tmp[0..24], true);

    return IUP_DEFAULT;
}

/+
int btnExternalAuth_cb(Ihandle* ih)
{
    import util_opensc : aa_7_2_6_82_external_authentication;
    enum string commands = `
//    auto path_val = cast(immutable(ubyte)[])hexString!"3F 00 41 00";
//    sc_path_set(&path, SC_PATH_TYPE.SC_PATH_TYPE_FILE_ID, path_val.ptr, path_val.length, 0, -1);
    int rv;
    sc_path path;
    sc_format_path("3F004100", &path);
    if ((rv= sc_select_file(card, &path, null)) != SC_SUCCESS)
        return IUP_DEFAULT;

//    ubyte[24] key = keySym_bytesStockDES.get[0..keySym_keyLenBits.get/8]; //cast(immutable(ubyte)[])hexString!"F1E0D0C1B0A1890807164504130201F189FEB3C837451694";
    if ((rv= aa_7_2_6_82_external_authentication(card, cast(ubyte)keySym_keyRef.get /*0x81, null, key*/)) != SC_SUCCESS) {
        mixin (log!(__FUNCTION__,  "external_authentication failed with error code %d", "rv"));
        return IUP_DEFAULT;
    }

/+ some relicts from other tasks / sc_update_record
    auto newData = cast(immutable(ubyte)[])hexString!"0102030405060708090A0B0C0D0E0F10";
    auto path    = cast(immutable(ubyte)[])hexString!"3F 00 41 00 39 06";

    foreach (ub2 fid; chunks(path, 2)) {
        if ((rv= acos5_64_short_select(card, fid)) != SC_SUCCESS)
        return IUP_DEFAULT;
    }
/*
    ub8 pw = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
    int tries_left;
    if ((rv= sc_verify(card, SC_AC.SC_AC_CHV, 129, pw.ptr, pw.length, &tries_left)) != SC_SUCCESS) {
        mixin (log!(__FUNCTION__,  "sc_verify failed with error code %d", "rv"));
        return IUP_DEFAULT;
    }
    sc_path path2;
    sc_path_set(&path2, SC_PATH_TYPE.SC_PATH_TYPE_FILE_ID, path.ptr+4, path.length-4, 0, -1);
*/
    if ((rv= sc_update_record(card, 2, newData.ptr, newData.length, 0)) != SC_SUCCESS) {
        mixin (log!(__FUNCTION__,  "sc_update_record failed with error code %d", "rv"));
        return IUP_DEFAULT;
    }
+/
`;
    mixin (connect_card!commands);
    return IUP_DEFAULT;
}


int btn_enc_dec_cb(Ihandle* ih)
{
    import std.file : getSize;
    Handle hstat = AA["statusbar"];
    Handle mtx = AA["matrixKeySym"];
    immutable fromfile     = mtx.GetStringId2("", r_fromfile, 1);
    immutable tofile       = mtx.GetStringId2("", r_tofile, 1);
    immutable what_enc_dec = mtx.GetStringId2("", r_enc_dec, 1);
    immutable what_mode    = mtx.GetStringId2("", r_mode, 1);
    immutable what_iv      = string2ubaIntegral(mtx.GetStringId2("", r_iv, 1)).idup;
    assert(what_iv.length==16);
    immutable cbc = what_mode=="cbc";
    immutable ub2 fid      = integral2uba!2(keySym_fidAppDir.get); /* */
    immutable ubyte algoECB_MSE = algoECB_MSEfromAlgoKeySym(keySym_algoStore.get); /* */
    ubyte blocksize             =   blocksizefromAlgoKeySym(keySym_algoStore.get); /* */

    ubyte algoMSE = algoECB_MSE;
    ubyte[] tlv_crt_sym_encdec = (cast(immutable(ubyte)[])hexString!"B8 FF  95 01 40  80 01 FF  83 01 FF").dup;
    if (cbc) {
        algoMSE += 2;
        tlv_crt_sym_encdec ~= [ubyte(0x87), blocksize] ~ what_iv[0..blocksize];
    }
    tlv_crt_sym_encdec[1]  = cast(ubyte) (tlv_crt_sym_encdec.length-2);
    tlv_crt_sym_encdec[7]  = algoMSE;
    tlv_crt_sym_encdec[10] = cast(ubyte) keySym_keyRef.get; /* */

    try {
        auto f = File(fromfile, "rb");
        immutable sizeFromfile = getSize(fromfile);
//        assumeWontThrow(writeln("sizeFromfile", sizeFromfile));
        auto inData = f.rawRead(new ubyte[sizeFromfile]);
        f.close();
////        writefln("%(%02X %)", inData);

        if (what_enc_dec=="enc") {
            enum string commands = `
            int rv;
            acos5_64_short_select(card, fid);
            ub8 pbuf = [ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 ];
            int  tries_left;
            rv = sc_verify(card, SC_AC.SC_AC_CHV, 0x81, pbuf.ptr, pbuf.length, &tries_left);
            if (rv != SC_SUCCESS) {
                writefln("### sc_verify failed: Received rv: %s", rv);
                return IUP_DEFAULT;
            }

            if ((rv= cry_mse_7_4_2_1_22_set(card, tlv_crt_sym_encdec)) < 0) {
                writeln("  ### FAILED: Something went wrong with set MSE for sym_encrypt");
                return IUP_DEFAULT;
            }

            ubyte[]  ciphertext = new ubyte[multipleGreaterEqual(sizeFromfile, blocksize)];
            if ((rv= cry_pso_7_4_3_6_2A_sym_encrypt(card, inData, ciphertext, blocksize, cbc)) < 0)
                writeln("  ### FAILED: Something went wrong with cry_pso_7_4_3_6_2A_sym_encrypt");
////        writefln("[ %(%02X %) ]", ciphertext);
            toFile(ciphertext, tofile);
            hstat.SetString(IUP_TITLE, "SUCCESS: Encrypt data fromfile -> tofile");
`;
            mixin (connect_card!commands);
        }
        else if (what_enc_dec=="dec") {
            enum string commands = `
            int rv;
            acos5_64_short_select(card, fid);
            ub8 pbuf = [ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 ];
            int  tries_left;
            rv = sc_verify(card, SC_AC.SC_AC_CHV, 0x81, pbuf.ptr, pbuf.length, &tries_left);
            if (rv != SC_SUCCESS) {
                writefln("### sc_verify failed: Received rv: %s", rv);
                return IUP_DEFAULT;
            }

            ubyte[]  ciphertext_decrypted = new ubyte[sizeFromfile];
	        if ((rv= cry_pso_7_4_3_7_2A_sym_decrypt(card, inData, ciphertext_decrypted, blocksize, cbc, tlv_crt_sym_encdec, fid)) < 0)
                writeln("  ### FAILED: Something went wrong with cry_pso_7_4_3_7_2A_sym_decrypt");
////        writefln("[ %(%02X %) ]", ciphertext_decrypted);
            toFile(ciphertext_decrypted, tofile);
            hstat.SetString(IUP_TITLE, "SUCCESS: Decrypt data fromfile -> tofile");
`;
            mixin (connect_card!commands);
        }

    }
    catch (Exception e) { printf("### Exception in btn_enc_dec_cb() \n"); /* todo: handle exception */ }
//source/key_sym.d-mixin-892(977,17): Error: return expression expected

    return IUP_DEFAULT; // .GetIntegerId2("", r_keyAsym_Id, 1)
} // btn_enc_dec_cb
+/

const char[] button_radioKeySym_cb_common1 =`
            int diff;
            diff = doDelete? change_calcSKDF.pkcs15_ObjectTyp.posStart - change_calcSKDF.pkcs15_ObjectTyp.posEnd : change_calcSKDF.get;

            ubyte[] zeroAdd = new ubyte[ diff>=0? 0 : abs(diff) ];
            auto haystack = find!((a,b) => b == getIdentifier(a, name_SecretKeyType(*change_calcSKDF.getctn)~".commonKeyAttributes.iD", false, false))(SKDF, keySym_Id.get);
            assert(!haystack.empty);
            // change_calcSKDF.pkcs15_ObjectTyp shall be identical to resulting haystack.front (except the _new components)!) !

            asn1_node  tmp = haystack.front.structure;
            with (change_calcSKDF.pkcs15_ObjectTyp)
            if (!doDelete) {
                haystack.front.der       = der       = der_new.dup;
                haystack.front.structure = structure = asn1_dup_node(structure_new, "");
                asn1_delete_structure(&tmp);
            }
/*
  ATTENTION with asn1_delete_structure(&tmp):
  change_calcSKDF.pkcs15_ObjectTyp.structure points to deleted content ! It MUST not be referenced any more
*/
            ubyte[] buf;
            change_calcSKDF.pkcs15_ObjectTyp.posEnd +=  diff;
            foreach (i, ref elem; haystack) {
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
            const(char)*     opt_profile      = "acos5_64"; //"pkcs15";
            const(char)*     opt_card_profile = "acos5_64";
            sc_file*         file;

            sc_pkcs15init_set_callbacks(&my_pkcs15init_callbacks);

            /* Bind the card-specific operations and load the profile */
            rv= sc_pkcs15init_bind(card, opt_profile, opt_card_profile, null, &profile);
            if (rv < 0) {
                printf("Couldn't bind to the card: %s\n", sc_strerror(rv));
                return IUP_DEFAULT; //return 1;
            }
            rv = sc_pkcs15_bind(card, &aid, &p15card);

            file = sc_file_new();
            scope(exit) {
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
    immutable activeToggle = AA["radioKeySym"].GetStringVALUE();
    assert(skdf);
    tnTypePtr  skFile;
    getNOR(skFile);
    assert(skFile);

    switch (activeToggle) {
//        case "toggle_sym_SKDF_change",
//             "toggle_sym_delete",
//             "toggle_sym_update",
//             "toggle_sym_updateSMkeyHost",
//             "toggle_sym_updateSMkeyCard",
//             "toggle_sym_create_write",
//             "toggle_sym_enc_dec":  break;
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
            assert(rv==buf.length);

            // update record
            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &skFile.data[8], skFile.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);
            if (rv < 0)
                return IUP_DEFAULT;
            ubyte MRL = skFile.data[4];
            auto buf_delete = new ubyte[MRL];
            rv= sc_update_record(card, keySym_recordNo.get, buf_delete.ptr, buf_delete.length, 0);
            assert(rv == buf_delete.length);
`;
            mixin (connect_card!commands);
            hstat.SetString(IUP_TITLE, "SUCCESS: Delete key");

            immutable keySym_Id_old = keySym_Id.get;
            int i, offset_remove;

            Handle h = AA["matrixKeySym"];
            // set to another keySym_Id, the first found
            foreach (es; rangeExtractedSym(SKDF)) {
                ++i;
                if (es.iD==keySym_Id_old)
                    continue;
                h.SetIntegerId2("", r_keySym_Id, 1, es.iD);
                matrixKeySym_dropselect_cb(h.GetHandle, r_keySym_Id, 1, null, es.iD.to!string.toStringz, i, 1);
                break;
            }

            foreach (es; rangeExtractedSym(SKDF)) {
                if (es.iD==keySym_Id_old) {
                    SKDF = remove(SKDF, offset_remove);
                    break;
                }
                ++offset_remove;
            }
////assumeWontThrow(writeln(SKDF));
            asn1_delete_structure(&tmp);
            GC.collect(); // just a check
            break; // case "toggle_sym_delete"

        case "toggle_sym_update", "toggle_sym_updateSMkeyHost", "toggle_sym_updateSMkeyCard":
//            assumeWontThrow(writeln("switch (activeToggle)   toggle_sym_update"));
            immutable bool doDelete;// = false;
            mixin(button_radioKeySym_cb_common1);

            enum string commands = `
            int rv;
            mixin(button_radioKeySym_cb_common2);

            // update SKDF; essential: don't allow to be called if the file isn't sufficiently sized
            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &skdf.data[8], skdf.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);

            if (rv == SC_SUCCESS) {
                if (buf.length) {
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
                rv= sc_update_record(card, keySym_recordNo.get, keySym_ByteStringStore.get.ptr, keySym_ByteStringStore.getLen, 0);
                assert(rv == keySym_ByteStringStore.getLen);
            }
`;
            mixin (connect_card!commands);
            break; // case "toggle_sym_update", "toggle_sym_updateSMkeyHost", "toggle_sym_updateSMkeyCard":

        case "toggle_sym_create_write":
            enum string commands = `
            int rv;
            mixin(button_radioKeySym_cb_common2);

            // update SKDF; essential: don't allow to be called if the file isn't sufficiently sized
            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &skdf.data[8], skdf.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);

            if (rv == SC_SUCCESS) {
                ubyte keySym_IdCurrent = cast(ubyte)keySym_Id.get;
                int skdfPosEnd =  !SKDF.empty? SKDF[$ - 1].posEnd : 0;
                PKCS15_ObjectTyp*  SKDFentry = change_calcSKDF.pkcs15_ObjectTyp; // get's returned by ref, thus an alias
                SKDF ~= PKCS15_ObjectTyp(skdfPosEnd, cast(int)(skdfPosEnd+SKDFentry.der_new.length),
                SKDFentry.der_new.dup,                      null,
                asn1_dup_node(SKDFentry.structure_new, ""), null);

                SKDFentry.der       = SKDF[$-1].der;
                asn1_delete_structure(&SKDFentry.structure);
                SKDFentry.structure = SKDF[$-1].structure;

                if (SKDFentry.der_new.length)
                    rv = sc_update_binary(card, skdfPosEnd, SKDFentry.der_new.ptr, SKDFentry.der_new.length, 0);
                assert(rv==SKDFentry.der_new.length);

                // update record
                sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &skFile.data[8], skFile.data[1], 0, -1);
                rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);
                if (rv < 0)
                    return IUP_DEFAULT;
                rv= sc_update_record(card, keySym_recordNo.get, keySym_ByteStringStore.get.ptr, keySym_ByteStringStore.getLen, 0);
                assert(rv == keySym_ByteStringStore.getLen);
            }
`;
            mixin (connect_card!commands);
            break; // case "toggle_sym_create_write"

        case "toggle_sym_enc_dec":
            import std.file : getSize;
//            Handle hstat = AA["statusbar"];
            Handle mtx = AA["matrixKeySym"];
            immutable fromfile     = mtx.GetStringId2("", r_fromfile, 1);
            immutable tofile       = mtx.GetStringId2("", r_tofile, 1);
            immutable what_enc_dec = mtx.GetStringId2("", r_enc_dec, 1);
            immutable what_mode    = mtx.GetStringId2("", r_mode, 1);
            immutable what_iv      = string2ubaIntegral(mtx.GetStringId2("", r_iv, 1)).idup;
            assert(what_iv.length==16);
            immutable cbc = what_mode=="cbc";
            immutable ub2 fid      = integral2uba!2(keySym_fidAppDir.get); /* */
            immutable ubyte algoECB_MSE = algoECB_MSEfromAlgoKeySym(keySym_algoStore.get); /* */
            ubyte blocksize             =   blocksizefromAlgoKeySym(keySym_algoStore.get); /* */

            ubyte algoMSE = algoECB_MSE;
            ubyte[] tlv_crt_sym_encdec = (cast(immutable(ubyte)[])hexString!"B8 FF  95 01 40  80 01 FF  83 01 FF").dup;
            if (cbc) {
                algoMSE += 2;
                tlv_crt_sym_encdec ~= [ubyte(0x87), blocksize] ~ what_iv[0..blocksize];
            }
            tlv_crt_sym_encdec[1]  = cast(ubyte) (tlv_crt_sym_encdec.length-2);
            tlv_crt_sym_encdec[7]  = algoMSE;
            tlv_crt_sym_encdec[10] = cast(ubyte) keySym_keyRef.get; /* */

            try {
                auto f = File(fromfile, "rb");
                immutable sizeFromfile = getSize(fromfile);
//                assumeWontThrow(writeln("sizeFromfile", sizeFromfile));
                auto inData = f.rawRead(new ubyte[sizeFromfile]);
                f.close();
////                writefln("%(%02X %)", inData);

                if (what_enc_dec=="enc") {
                    enum string commands = `
                    int rv;
                    mixin(button_radioKeySym_cb_common2);

                    sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &skFile.data[8], skFile.data[1], 0, -1);
                    rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_CRYPTO);
                    if (rv < 0)
                        return IUP_DEFAULT;

                    if ((rv= cry_mse_7_4_2_1_22_set(card, tlv_crt_sym_encdec)) < 0) {
                        writeln("  ### FAILED: Something went wrong with set MSE for sym_encrypt");
                        return IUP_DEFAULT;
                    }

                    ubyte[]  ciphertext = new ubyte[multipleGreaterEqual(sizeFromfile, blocksize)];
                    if ((rv= cry_pso_7_4_3_6_2A_sym_encrypt(card, inData, ciphertext, blocksize, cbc)) < 0)
                        writeln("  ### FAILED: Something went wrong with cry_pso_7_4_3_6_2A_sym_encrypt");
////                writefln("[ %(%02X %) ]", ciphertext);
                    toFile(ciphertext, tofile);
                    hstat.SetString(IUP_TITLE, "SUCCESS: Encrypt data fromfile -> tofile");
`;
                    mixin (connect_card!commands);
                }
                else if (what_enc_dec=="dec") {
                    enum string commands = `
                    int rv;
                    mixin(button_radioKeySym_cb_common2);

                    sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &skFile.data[8], skFile.data[1], 0, -1);
                    rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_CRYPTO);
                    if (rv < 0)
                        return IUP_DEFAULT;

                    ubyte[]  ciphertext_decrypted = new ubyte[sizeFromfile];
	                if ((rv= cry_pso_7_4_3_7_2A_sym_decrypt(card, inData, ciphertext_decrypted, blocksize, cbc, tlv_crt_sym_encdec, fid)) < 0)
                        writeln("  ### FAILED: Something went wrong with cry_pso_7_4_3_7_2A_sym_decrypt");
////                writefln("[ %(%02X %) ]", ciphertext_decrypted);
                    toFile(ciphertext_decrypted, tofile);
                    hstat.SetString(IUP_TITLE, "SUCCESS: Decrypt data fromfile -> tofile");
`;
                    mixin (connect_card!commands);
                }
            }
            catch (Exception e) { printf("### Exception in btn_enc_dec_cb() \n"); /* todo: handle exception */ }
            break;

        default:  assert(0);
    } // switch (activeToggle)
    return IUP_DEFAULT;
} // button_radioKeySym_cb

