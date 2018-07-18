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
import std.range : iota, chunks, indexed;
import std.range.primitives : empty, front;//, back;
import std.array : array;
import std.algorithm.comparison : among, clamp, equal, min, max;
import std.algorithm.searching : canFind, countUntil, all, any, find;
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
    util_connect_card, connect_card, PKCS15_ObjectTyp, errorDescription, PKCS15, iter_begin, appdf, prkdf, pukdf, tnTypePtr,
    /*populate_tree_fs,*/ itTypeFS, aid, cm_7_3_1_14_get_card_info, is_ACOSV3_opmodeV3_FIPS_140_2L3, is_ACOSV3_opmodeV3_FIPS_140_2L3_active,
    my_pkcs15init_callbacks, tlv_Range_mod, file_type, getIdentifier;

import libtasn1;
import pkcs11;

// tag types
//struct _keySym_keyRef{}
//Obs
struct _keySym_algoStore{}

enum /* matrixKeySymRowName */ {
    r_keySym_global_local = 1,

    r_keySym_Id,
//    r_keySym_recordNo,
//    r_keySym_keyRef,

    r_keySym_Label,
    r_keySym_Modifiable,
    r_keySym_usageSKDF,
    r_keySym_authId,

    r_keySym_algoType,   // AES or DES-based
    r_keySym_keyLenBits,  // depends on AlgoType
    r_keySym_algoStore, // depends on AlgoType and keyLength
    r_keySym_ExtAutStore,
    r_keySym_ExtAut_ErrorCounterYN,
    r_keySym_ExtAut_ErrorCounterValue,

    r_keySym_IntAutStore,
    r_keySym_IntAut_UsageCounterYN,
    r_keySym_IntAut_UsageCounterValue,

    r_keySym_valueStore,
    r_keySym_ByteStringStore,

    r_keySym_fid,
    r_keySym_fidAppDir,
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

Pub!_keySym_ExtAutStore           keySym_ExtAutStore;
Pub!_keySym_ExtAut_ErrorCounterYN keySym_ExtAut_ErrorCounterYN;
Pub!_keySym_IntAutStore                keySym_IntAutStore;
Pub!_keySym_IntAut_UsageCounterYN keySym_IntAut_UsageCounterYN;

Obs_keySym_algoStore              keySym_algoStore;
Obs_keySym_ByteStringStore        keySym_ByteStringStore;

void set_some(int status) nothrow {
    keySym_fidAppDir.set(status? (appdf is null? 0 : ub22integral(appdf.data[2..4])) : 0x3F00, true);

    sitTypeFS  pos_parent =  new sitTypeFS(status? appdf : fs.begin().node);
    tnTypePtr  keySym_file;
    try
        keySym_file = fs.siblingRange(fs.begin(pos_parent), fs.end(pos_parent)).locate!"a[0]==b"(EFDB.Sym_Key_EF);
    catch (Exception e) { printf("### Exception in matrixKeySym_togglevalue_cb()\n"); /* todo: handle exception */ }
    keySym_fid.set(keySym_file is null? 0 : ub22integral(keySym_file.data[2..4]), true);
}

void keySym_initialize_PubObs() {
    /* initialze the publisher/observer system for GenerateKeyPair_RSA_tab */
    // some variables are declared as publisher though they don't need to be, currently just for consistency, but that's not the most efficient way
//    keyPairLabel            = new Pub!(_keyPairLabel,string)  (r_keyPairLabel,            AA["matrixRsaAttributes"]);
    keySym_global_local          = new Pub!_keySym_global_local         (r_keySym_global_local,          AA["matrixKeySym"]);
    keySym_usageSKDF             = new Pub!_keySym_usageSKDF                   (r_keySym_usageSKDF,                    AA["matrixKeySym"]);
    keySym_Id                    = new Pub!_keySym_Id                   (r_keySym_Id,                    AA["matrixKeySym"]);
    keySym_Modifiable            = new Pub!_keySym_Modifiable           (r_keySym_Modifiable,            AA["matrixKeySym"]);
    keySym_authId                = new Pub!_keySym_authId               (r_keySym_authId,                AA["matrixKeySym"]);

    keySym_Label                 = new Pub!(_keySym_Label,string)       (r_keySym_Label,                 AA["matrixKeySym"]);
    keySym_algoType              = new Pub!(_keySym_algoType,string)    (r_keySym_algoType,              AA["matrixKeySym"]);
    keySym_keyLenBits            = new Pub!_keySym_keyLenBits           (r_keySym_keyLenBits,             AA["matrixKeySym"]);

    keySym_fid                   = new Pub!_keySym_fid                  (r_keySym_fid,                   AA["matrixKeySym"], true);
    keySym_fidAppDir             = new Pub!_keySym_fidAppDir            (r_keySym_fidAppDir,             AA["matrixKeySym"], true);

    keySym_ExtAutStore           = new Pub!_keySym_ExtAutStore           (r_keySym_ExtAutStore,          AA["matrixKeySym"]);
    keySym_ExtAut_ErrorCounterYN = new Pub!_keySym_ExtAut_ErrorCounterYN (r_keySym_ExtAut_ErrorCounterYN,AA["matrixKeySym"]);
    keySym_IntAutStore           = new Pub!_keySym_IntAutStore           (r_keySym_IntAutStore,          AA["matrixKeySym"]);
    keySym_IntAut_UsageCounterYN = new Pub!_keySym_IntAut_UsageCounterYN (r_keySym_IntAut_UsageCounterYN,AA["matrixKeySym"]);

    keySym_algoStore             = new Obs_keySym_algoStore              (r_keySym_algoStore,            AA["matrixKeySym"]);
    keySym_ByteStringStore       = new Obs_keySym_ByteStringStore        (r_keySym_ByteStringStore,      AA["matrixKeySym"]);


//// dependencies
//    keySym_global_local   .connect(& .watch);
    keySym_algoType              .connect(&keySym_algoStore.watch);
    keySym_keyLenBits            .connect(&keySym_algoStore.watch);

//// values to start with
//    fidRSADir              .set(appdf is null? 0 : ub22integral(appdf.data[2..4]), true);
    keySym_global_local   .set(true, true);
    set_some(1);
//    keySym_usageSKDF             .set(3);
    keySym_Id             .set(1, true);
}

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
            case  64:  _value = _keySym_algoType=="DES"? 0x05 :    0; break;
            case 128:  _value = _keySym_algoType=="DES"? 0x04 : 0x02; break;
            case 192:  _value = _keySym_algoType=="DES"? 0x14 : 0x12; break;
            case 256:  _value = _keySym_algoType=="DES"?    0 : 0x22; break;
            default:   _value = 0; break;
        }
assumeWontThrow(writefln(typeof(this).stringof~" object was set to value 0x%02X", _value));
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
} // class Obs_algoStore

class Obs_keySym_ByteStringStore {
    mixin(commonConstructor);

//    void watch(string msg, string v) {
//        switch(msg) {
//            case "_keySym_algoType":
//                  _keySym_algoType = v;
//                break;
//            default:
//                writeln(msg); stdout.flush();
//                assert(0, "Unknown observation");
//        }
//        calculate();
//    }

    void watch(string msg, int v) {
        switch(msg) {
            case "_keySym_algoStore":
                  _keySym_algoStore = v;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        calculate();
    }

    void calculate()
    {
assumeWontThrow(writefln(typeof(this).stringof~" object was set to value 0x%(%02X %)", _value));

        if (_h !is null) {
////            _h.SetStringId2 ("", _lin, _col, format!"0x%02X"(_value));
            _h.Update;
        }
    }

//    mixin Pub_boilerplate!(_keySym_algoStore, int);

    private :
        string  _keySym_algoType;
         int        _len;

    ubyte[37]  _value;
    int    _lin;
    int    _col;
    Handle _h;
} // class Obs_algoStore

/+
class Pub(T, V=int)
{
//    this(int lin/*, int col*/, Handle control = null, bool hexRep = false) {
//        _lin = lin;
//        _col = 1;
//        _h   = control;
//        _hexRep = hexRep;
//    }

    @property V set(V v, bool programmatically=false)  nothrow {
//        try {
//            _value = v;
////assumeWontThrow(writefln(T.stringof~" object was set to value %s", _value));
//            static if (is(T==_keySym_usageSKDF)) {
//                if (_h !is null) {
////assumeWontThrow(writefln(T.stringof~" object was set to value %s and translate int", _value));
//                    _h.SetStringId2 ("", _lin, _col, keyUsageFlagsInt2string(_value));
//                }
//            }
//            else static if (is(T==_keySym_Label) || is(T==_keySym_algoType)) {
//                if (programmatically && _h !is null) {
////assumeWontThrow(writefln(T.stringof~" object was set to value %s and translate int", _value));
//                    _h.SetStringId2 ("", _lin, _col, _value);
//                }
//            }
/+
            else static if (is(T==_AC_Update_PrKDF_PuKDF) || is(T==_AC_Delete_Create_RSADir) ||
                is(T==_AC_Update_Delete_RSAprivateFile) || is(T==_AC_Update_Delete_RSApublicFile)) {
                if (programmatically && _h !is null) {
                    _h.SetStringId2 ("", _lin, _col, format!"%02X"(_value[0])  ~" / "~format!"%02X"(_value[1]));
                }
            }
            else
+/
//            else static if (is(T==_keySym_fidAppDir) || is(T==_keySym_fid)) {
//                if (programmatically &&  _h !is null)
//                    _h.SetStringId2 ("", _lin, _col, _hexRep? format!"%04X"(_value) : _value.to!string);
//            }
//            else {
//                if (programmatically &&  _h !is null)
//                    _h.SetStringId2 ("", _lin, _col, _hexRep? format!"%X"(_value)   : _value.to!string);
//            }

            emit(T.stringof, _value);
            static if (is (T == _keySym_Id))
                set_more_for_keySym_Id(_value);
            /* this is critical for _keyPairId:
             * First change_calcPrKDF.watch and change_calcPuKDF.watch must run: They create/dup structure to structure_new
             * only then: set_more_for_keyPairId */
//            static if (is (T == _keyPairId))
//                set_more_for_keyPairId(_value);
//        }
//        catch (Exception e) { printf("### Exception in Pub.set()\n"); /* todo: handle exception */ }
//        return _value;
    }

//    mixin Pub_boilerplate!(T,V);
}
+/
enum ctxTagNo : ubyte {
    desKey  = 2,
    des2Key = 3,
    des3Key = 4,
    aesKey  = 15,

    unknown = 255
}

string name_SecretKeyType(ctxTagNo ctxTag) nothrow {
    final switch (ctxTag) {
        case ctxTagNo.desKey:   return "desKey";
        case ctxTagNo.des2Key:  return "des2Key";
        case ctxTagNo.des3Key:  return "des3Key";
        case ctxTagNo.aesKey:   return "aesKey";

        case ctxTagNo.unknown:  return "unknown";
    }
}

int set_more_for_keySym_Id(int keyId) nothrow {
    import core.bitop : bitswap;

    string activeToggle = AA["radioKeySym"].GetStringVALUE();
    assumeWontThrow(writefln("activeToggle: %s", activeToggle));
    printf("set_more_for_keySym_Id (%d)\n", keyId);

    int  asn1_result;
    int  outLen;
    PKCS15_ObjectTyp  SKDFentry;

    assert(keyId > 0);
//desKey,  0x05
//des2Key, 0x04  assuming this denotes  128-bit 3DES
//des3Key, 0x14  assuming this denotes  192-bit 3DES
// thus for the des types, the naming includes the keyLen, whereas aes has 1 name, but 3 different possible keyLen
//aesKey,  0x02, 0x12, 0x22
    ctxTagNo ctxTag = ctxTagNo.unknown;
    string keyType = name_SecretKeyType(ctxTag);
    PKCS15_ObjectTyp[] haystack;
    foreach (i; indexed([EnumMembers!ctxTagNo], [2,3,1,0])) {
        keyType = name_SecretKeyType(i);
        haystack = find!((a,b) => b == getIdentifier(a, keyType~".commonKeyAttributes.iD"))(SKDF, keyId);
        if (!haystack.empty) {
            ctxTag = i;
            SKDFentry = haystack.front;
            break;
        }
    }

    assert(!haystack.empty);
    keySym_algoType.set("DES", true);

/*
SecretKeyObject ::= SEQUENCE { -- PKCS15Object {CommonKeyAttributes, CommonSecretKeyAttributes, GenericSecretKeyAttributes}
    commonObjectAttributes    CommonObjectAttributes,
    commonKeyAttributes        CommonKeyAttributes,
    commonSecretKeyAttributes     [0] CommonSecretKeyAttributes OPTIONAL,
    genericSecretKeyAttributes    [1] EXPLICIT GenericSecretKeyAttributes
}
*/
    ubyte[1] flags; // optional
    asn1_result = asn1_read_value(SKDFentry.structure, keyType~".commonObjectAttributes.flags", flags, outLen);
    if (asn1_result != ASN1_SUCCESS)
        assumeWontThrow(writeln("### asn1_read_value "~keyType~".commonObjectAttributes.flags: ", asn1_strerror2(asn1_result)));
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
    asn1_result = asn1_read_value(SKDFentry.structure, keyType~".commonObjectAttributes.authId", authId, outLen);
    if (asn1_result != ASN1_SUCCESS) {
        assumeWontThrow(writeln("### asn1_read_value "~keyType~".commonObjectAttributes.authId: ", asn1_strerror2(asn1_result)));
    }
    else {
        assert(outLen==1);
        if (authId[0])
            assert(flags[0]&1); // may run into a problem if asn1_read_value for flags failed
        keySym_authId.set(authId[0], true);
    }

    { // make label inaccessible when leaving the scope
        char[] label = new char[65]; // optional
        label[0..65] = '\0';
        asn1_result = asn1_read_value(SKDFentry.structure, keyType~".commonObjectAttributes.label", label, outLen);
        if (asn1_result != ASN1_SUCCESS) {
            assumeWontThrow(writeln("### asn1_read_value "~keyType~".commonObjectAttributes.label: ", asn1_strerror2(asn1_result)));
        }
        else
            keySym_Label.set(assumeUnique(label[0..outLen]), true);
    }

    ubyte[2] keyUsageFlags; // non-optional
    asn1_result = asn1_read_value(SKDFentry.structure, keyType~".commonKeyAttributes.usage", keyUsageFlags, outLen);
    if (asn1_result != ASN1_SUCCESS)
        assumeWontThrow(writeln("### asn1_read_value "~keyType~".commonKeyAttributes.usage: ", asn1_strerror2(asn1_result)));
    else {
//        assert(outLen==10); // bits
//assumeWontThrow(writefln("keyUsageFlags: %(%02X %)", keyUsageFlags));
        keySym_usageSKDF.set( bitswap(ub22integral(keyUsageFlags)<<16), true);
    }

    ubyte[2] keyLength; // non-optional
    asn1_result = asn1_read_value(SKDFentry.structure, keyType~".commonSecretKeyAttributes.keyLen", keyLength, outLen);
    if (asn1_result != ASN1_SUCCESS) //== ASN1_ELEMENT_NOT_FOUND)
        assumeWontThrow(writeln("### asn1_read_value "~keyType~".commonSecretKeyAttributes.keyLen: ", asn1_strerror2(asn1_result)));
    else {
      assert(outLen.among(1,2));
//assumeWontThrow(writefln("modulusLength set by set_more_for_keyPairId: %(%02X %)", modulusLength));
      ushort keyLenBits = ub22integral(keyLength);
      assert(keyLenBits%64==0 && keyLenBits>=64  && keyLenBits<=256);
      keySym_keyLenBits.set(keyLenBits, true);
// for des3Key only
assert(keyLenBits==192);
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
    return 0;
}

extern(C) nothrow :


int matrixKeySym_dropcheck_cb(Ihandle* /*self*/, int lin, int col) {
    if (col!=1 || lin>r_keySym_IntAut_UsageCounterYN)
        return IUP_IGNORE; // draw nothing
//    printf("matrixKeySym_dropcheck_cb(%d, %d)\n", lin, col);
//    printf("matrixRsaAttributes_dropcheck_cb  %s\n", AA["radio_RSA"].GetAttributeVALUE());
//    string activeToggle = AA["radio_RSA"].GetStringVALUE();
//    bool isSelectedKeyPairId = AA["matrixRsaAttributes"].GetIntegerId2("", r_keyPairId, 1) != 0;
    switch (lin) {
    /* dropdown */
/*
        case r_keyPairId:
            if (activeToggle != "toggle_RSA_key_pair_create_and_generate")
                return IUP_DEFAULT; // show the dropdown/popup menu
            return     IUP_IGNORE; // draw nothing

        case r_authIdRSAprivate:
            if (!activeToggle.among("toggle_RSA_key_pair_delete", "toggle_RSA_key_pair_try_sign")  &&  isSelectedKeyPairId)
                return IUP_DEFAULT; // show the dropdown/popup menu
            return     IUP_IGNORE; // draw nothing
*/
        case r_keySym_algoType:
//            if ( !activeToggle.among("toggle_RSA_PrKDF_PuKDF_change", "toggle_RSA_key_pair_delete", "toggle_RSA_key_pair_try_sign")  &&  isSelectedKeyPairId)
                return IUP_DEFAULT; // show the dropdown/popup menu
//            return     IUP_IGNORE; // draw nothing
        case r_keySym_keyLenBits:
                return IUP_DEFAULT; // show the dropdown/popup menu

    /* toggle */
        case r_keySym_global_local:
//            if ( !activeToggle.among("toggle_RSA_PrKDF_PuKDF_change", "toggle_RSA_key_pair_delete", "toggle_RSA_key_pair_try_sign"))
                return IUP_CONTINUE; // show and enable the toggle button ; this short version works with TOGGLECENTERED only !
//            return     IUP_IGNORE; // draw nothing

        case r_keySym_Modifiable:
                return IUP_CONTINUE;

        case r_keySym_ExtAut_ErrorCounterYN:
                return IUP_CONTINUE;

        case r_keySym_IntAut_UsageCounterYN:
                return IUP_CONTINUE;

        case r_keySym_ExtAutStore:
//            if (!activeToggle.among("toggle_RSA_key_pair_delete", "toggle_RSA_key_pair_try_sign")  &&  isSelectedKeyPairId)
                return IUP_CONTINUE; // show and enable the toggle button ; this short version works with TOGGLECENTERED only !
//            return     IUP_IGNORE; // draw nothing

        case r_keySym_IntAutStore:
//            if (!activeToggle.among("toggle_RSA_key_pair_delete", "toggle_RSA_key_pair_try_sign")  &&  isSelectedKeyPairId)
                return IUP_CONTINUE; // show and enable the toggle button ; this short version works with TOGGLECENTERED only !
//            return     IUP_IGNORE; // draw nothing

        default:  return IUP_IGNORE; // draw nothing
    }
} // matrixKeySym_dropcheck_cb

int matrixKeySym_drop_cb(Ihandle* /*self*/, Ihandle* drop, int lin, int col) {
    if (col!=1 || lin>r_keySym_IntAut_UsageCounterYN)
        return IUP_IGNORE; // draw nothing
    printf("matrixKeySym_drop_cb(%d, %d)\n", lin, col);
    string activeToggle = AA["radioKeySym"].GetStringVALUE();
    ubyte[2]  str;
    int outLen;
    int asn1_result, rv;
    with (createHandle(drop))
    switch (lin) {
        case r_keySym_algoType:
//            if (activeToggle != "toggle_RSA_key_pair_create_and_generate") {
                SetAttributeId("", 1, "AES");
                SetAttributeId("", 2, "DES");
                SetAttributeId("", 3, null);
                SetAttributeStr(IUP_VALUE, null);
                return IUP_DEFAULT; // show a dropdown field
//            }
//            return     IUP_IGNORE;  // show a text-edition field
        case r_keySym_keyLenBits:
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

        default:
            return IUP_IGNORE;
    }
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
    printf("matrixKeyAsym_dropselect_cb(lin: %d, col: %d, text (t) of the item whose state was changed: %s, mumber (i) of the item whose state was changed: %d, selected (v): %d)\n", lin, col, t, i, v);
    if (v/*selected*/ && col==1) {
        Handle h = createHandle(self);

        switch (lin) {
            case r_keySym_algoType:
//                assert(i>=1  && i<=15);
//                keyAsym_RSAmodulusLenBits.set =  (17-i)*256;
                keySym_algoType.set = h.GetStringVALUE();
                break;

            case r_keySym_keyLenBits:
//                assert(i>=1  && i<=15);
//                keyAsym_RSAmodulusLenBits.set =  (17-i)*256;
                keySym_keyLenBits.set = h.GetIntegerVALUE();
                break;

            default: break;
        }
    }
    return IUP_CONTINUE; // return IUP_DEFAULT;
}

int matrixKeySym_edition_cb(Ihandle* ih, int lin, int col, int mode, int update)
{
//mode: 1 if the cell has entered the edition mode, or 0 if the cell has left the edition mode
//update: used when mode=0 to identify if the value will be updated when the callback returns with IUP_DEFAULT. (since 3.0)
//matrixRsaAttributes_edition_cb(1, 1) mode: 1, update: 0
//matrixRsaAttributes_edition_cb(1, 1) mode: 0, update: 1
    printf("matrixKeySym_edition_cb(%d, %d) mode: %d, update: %d\n", lin, col, mode, update);
    if (mode==1) {
        return IUP_DEFAULT; // anything else here means readonly
    }
    //mode==0
    // shortcut for dropdown and toggle
    if (lin.among(//r_keyAsym_RSAmodulusLenBits,  // obj.val set.method in matrixKeyAsym_dropselect_cb
                  //r_keyAsym_Id,                 // obj.val set.method in matrixKeyAsym_dropselect_cb
                  //r_keyAsym_authId,             // obj.val set.method in matrixKeyAsym_dropselect_cb
                  r_keySym_global_local,          // obj.val set.method in matrixKeyAsym_togglevalue_cb
                  r_keySym_Modifiable,            // obj.val set.method in matrixKeyAsym_togglevalue_cb
                  r_keySym_ExtAutStore,           // obj.val set.method in matrixKeyAsym_togglevalue_cb
                  r_keySym_ExtAut_ErrorCounterYN, // obj.val set.method in matrixKeyAsym_togglevalue_cb
                  r_keySym_IntAutStore,           // obj.val set.method in matrixKeyAsym_togglevalue_cb
                  r_keySym_IntAut_UsageCounterYN, // obj.val set.method in matrixKeyAsym_togglevalue_cb
    ))
        return IUP_DEFAULT;
    if (lin==r_keySym_algoType) {
        if      (keySym_algoType.get=="AES" && keySym_keyLenBits.get==64)
            keySym_keyLenBits.set(128, true);
        else if (keySym_algoType.get=="DES" && keySym_keyLenBits.get==256)
            keySym_keyLenBits.set(192, true);
    }

    return IUP_DEFAULT;
}

/*
matrixKeySym_edition_cb(7, 1) mode: 1, update: 0

matrixKeySym_drop_cb(7, 1)
matrixKeyAsym_dropselect_cb(lin: 7, col: 1, text (t) of the item whose state was changed: AES, mumber (i) of the item whose state was changed: 1, selected (v): 1)
_keySym_algoType object was set to value AES

matrixKeySym_edition_cb(7, 1) mode: 0, update: 1
*/
int matrixKeySym_togglevalue_cb(Ihandle* /*self*/, int lin, int col, int status)
{
//    assert(col==1 && lin.among(r_keyPairModifiable, r_storeAsCRTRSAprivate));
    printf("matrixKeySym_togglevalue_cb(%d, %d) status: %d\n", lin, col, status);
    switch (lin) {
        case r_keySym_Modifiable:
//            bool isSelectedKeyId = AA["matrixKeySym"].GetIntegerId2("", r_keySym_Id, 1) != 0;
//            if (isSelectedKeyId)
                keySym_Modifiable.set = status;
//            else
//                assert(0);
            break;

        case r_keySym_global_local:
            keySym_global_local.set = status;
            set_some(status);
            break;

        case r_keySym_ExtAutStore:
            keySym_ExtAutStore.set = status;
            break;

        case r_keySym_ExtAut_ErrorCounterYN:
            keySym_ExtAut_ErrorCounterYN.set = status;
            break;

        case r_keySym_IntAutStore:
            keySym_IntAutStore.set = status;
            break;

        case r_keySym_IntAut_UsageCounterYN:
            keySym_IntAut_UsageCounterYN.set = status;
            break;

        default: break;
    }
    return IUP_DEFAULT;
}


