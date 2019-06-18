/*
 * pub.d: Program acos5_64_gui's generic publisher class (observer pattern)
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

module pub;

import core.stdc.stdio : printf;
import std.signals;// : Signal;
import std.format : format;
import std.conv: to;
import std.exception : assumeWontThrow;
import std.stdio;
import std.typecons : Tuple;

import iup.iup_plusD : Handle;
import util_general;
import acos5_64_shared : EFDB, ub2;

import util_opensc : fs, appdf, tnTypePtr, decompose;

import key_asym : set_more_for_keyAsym_Id;

bool isNewKeyPairId;

// tag types
struct _keyAsym_RSAmodulusLenBits{}
struct _keyAsym_crtModeGenerate{}
struct _keyAsym_usageGenerate{}  // refers to the private key
struct _keyAsym_usagePrKDF{}

struct _keyAsym_Id{}
struct _keyAsym_Label{}
struct _keyAsym_Modifiable{}
struct _keyAsym_authId{}
struct _keyAsym_fidAppDir{}

struct _AC_Update_PrKDF_PuKDF{}            //SCB
//struct _AC_Update_Delete_RSAprivateFile{}
//struct _AC_Update_Delete_RSApublicFile{}
struct _AC_Create_Delete_RSADir{}
//Obs
//struct _keyAsym_usagePuKDF{}

import key_sym : /*set_more_for_keySym_Id,*/ set_more_for_global_local;
// tag types
struct _keySym_algoFamily{}
struct _keySym_keyLenBits{}
struct _keySym_usageSKDF{}

struct _keySym_ExtAuthYN{}
struct _keySym_ExtAuthErrorCounterYN{}
struct _keySym_ExtAuthErrorCounterValue{}
struct _keySym_IntAuthYN{}
struct _keySym_IntAuthUsageCounterYN{}
struct _keySym_IntAuthUsageCounterValue{}

struct _keySym_Id{}
struct _keySym_recordNo{}

struct _keySym_Label{}
struct _keySym_Modifiable{}
struct _keySym_authId{}
struct _keySym_fidAppDir{}
struct _keySym_global_local{}
struct _keySym_bytesStockAES{}
struct _keySym_bytesStockDES{}

struct _AC_Update_SKDF{}       //SCB
struct _AC_Update_keyFile{}    //SCB

//PubA2
struct _fidRSAprivate{}
struct _fidRSApublic{}
struct _keySym_fid{}

string keyUsageFlagsInt2string(int flags) nothrow
{
    import std.math : pow;//    import core.bitop;
    import std.string : chomp;
    immutable string[10] textKeyUsageFlags = [
        "encrypt",
        "decrypt",
        "sign",
        "signRecover",
        "wrap",
        "unwrap",
        "verify",
        "verifyRecover",
        "derive",
        "nonRepudiation",
    ];// 1+16+64+128+256=465 <-> 2+4+8+32+512=558

    string result;
    foreach (i; 0..10)
        if (flags & pow(2,i))
            result ~= textKeyUsageFlags[i] ~ ",";
    return  chomp(result, ",");
}

enum string commonConstructor =`
    this(int lin/*, int col*/, Handle control = null)
    {
        _lin = lin;
        _col = 1;
        _h   = control;
    }
`;

mixin template Pub_boilerplate(T,V)
{
    @property V get() const @nogc nothrow /*pure*/ @safe { return _value; }

    void emit_self() nothrow
    {
        try
            emit(T.stringof, _value);
        catch (Exception e) { printf("### Exception in emit_self()\n"); /* todo: handle exception */ }
    }

    // Mix in all the code we need to make Foo into a signal
    mixin Signal!(string, V);


    private :
    V      _value;
    int    _lin;
    int    _col;
    Handle _h;
    bool   _hexRep; // whether the user-communication is based on a hexadecimal representation: true: requires int <-> hex conversion
}


class Pub(T, V=int)
{
    this(int lin/*, int col*/, Handle control = null, bool hexRep = false)
    {
        _lin = lin;
        _col = 1;
        _h   = control;
        _hexRep = hexRep;
    }

    @property V set(V v, bool programmatically=false)  nothrow
    {
        try
        {
            _value = v;
////assumeWontThrow(writefln(T.stringof~" object was set to value %s", _value));

            static if (is(T==_keyAsym_usageGenerate) || is(T==_keyAsym_usagePrKDF) || is(T==_keySym_usageSKDF))  /*|| is(T==_keyAsym_usagePuKDF)*/
            {
                if (_h !is null)
                    _h.SetStringId2 ("", _lin, _col, keyUsageFlagsInt2string(_value));
            }
            else static if (is(T==_keyAsym_Label) || is(T==_keySym_Label) || is(T==_keySym_algoFamily))
            {
                if (programmatically && _h !is null)
                    _h.SetStringId2 ("", _lin, _col, _value);
            }
            else static if (is(T==_AC_Update_PrKDF_PuKDF) || is(T==_AC_Create_Delete_RSADir)
                /* || is(T==_AC_Update_Delete_RSAprivateFile) || is(T==_AC_Update_Delete_RSApublicFile)*/)
            {
                if (programmatically && _h !is null)
                    _h.SetStringId2 ("", _lin, _col, format!"%02X"(_value[0])  ~" / "~format!"%02X"(_value[1]));
            }
            else static if (is(T==_keySym_fidAppDir) || is(T==_keySym_fid))
            {
                if (programmatically &&  _h !is null)
                    _h.SetStringId2 ("", _lin, _col, _hexRep? format!"%04X"(_value) : _value.to!string);
            }
            else static if (is(T==_keySym_bytesStockAES) || is(T==_keySym_bytesStockDES))
            {
                if (programmatically &&  _h !is null)
                    _h.SetStringId2 ("", _lin, _col, ubaIntegral2string(_value));
            }
            else
            {
                if (programmatically &&  _h !is null)
                    _h.SetStringId2 ("", _lin, _col, _hexRep? format!"%X"(_value) : _value.to!string);
            }
            emit(T.stringof, _value);
            /* this is critical for _keyAsym_Id:
             * First change_calcPrKDF.watch and change_calcPuKDF.watch must run: They create/dup structure to structure_new
             * only then: set_more_for_keyAsym_Id */

            static if (is (T == _keyAsym_Id))
                set_more_for_keyAsym_Id(_value);
//            static if (is (T == _keySym_Id))
//                set_more_for_keySym_Id(_value);
            static if (is (T == _keySym_global_local))
                set_more_for_global_local();

        }
        catch (Exception e) { printf("### Exception in Pub.set()\n"); /* todo: handle exception */ }
        return _value;
    }

    mixin Pub_boilerplate!(T,V);
}


class PubA2(T, V=int)
{
    mixin(commonConstructor);

    @property ub2    getub2()    const nothrow /*pure*/ @safe { return  fidub2; }
    @property ushort getushort() const nothrow /*pure*/ @safe { return  ub22integral(fidub2); }
    @property int    size()      const nothrow /*pure*/ @safe { return  _value[1]; }

/*
V[2] mapping:
 0: fid
 1: fid_size for transparent EF or fidMRL for record-based EF

 if locate fid within appDF fails, set both to zero

 accepts a new fid from v[0] only, if acceptable
 and depending on that, retrieves the file's size into v[1];

 usable for both fidRSAprivate and fidRSApublic
*/
    @property void set(V[2] v, bool programmatically=false)  nothrow
    {
//assumeWontThrow(writeln(T.stringof~" object is about to be set"));
        auto t = Tuple!(ushort, ubyte, ubyte)(0,0,0);
        tnTypePtr  privORpub;
//        sitTypeFS  pos_parent;
        try
        {
        /*if (v != _value)*/
        {
            /* locate */
/*
            ub2 ub2keyAsym_fidAppDir = integral2uba!2(keyAsym_fidAppDir.get)[0..2];
            if (equal([0,0], ub2keyAsym_fidAppDir[]))
                appdf = fs.preOrderRange(fs.begin(), fs.end()).locate!"a[6]==b"(PKCS15_FILE_TYPE.PKCS15_APPDF);
            else
                appdf = fs.preOrderRange(fs.begin(), fs.end()).locate!"equal(a[2..4], b[])"(ub2keyAsym_fidAppDir);
            if (appdf is null) {
                _value = [0,0];
                programmatically = true;
                goto end;
            }
*/
//            pos_parent = new sitTypeFS(appdf);
            privORpub = fs.rangeSiblings(appdf).locate!"equal(a.data[2..4], b)"(integral2uba!2(v[0]));
            if (privORpub is null)
            {
                programmatically = true;
                _value = isNewKeyPairId? [v[0],0] : [0,0];
            }
            else
            {
                t = decompose(cast(EFDB) privORpub.data[0], privORpub.data[4..6]);

                static if (is(T==_keySym_fid))
                {
                    v[1] = t[1]; // MRL
                }
                else
                {
                    v[1] = t[0];
                }
                _value = v;
            }
//end:
            fidub2 = integral2uba!2(_value[0])[0..2];
////assumeWontThrow(writefln(T.stringof~" object was set to values %04X, %s", _value[0], _value[1]));
            if (programmatically &&  _h !is null)
                _h.SetStringId2 ("", _lin, _col, format!"%04X"(_value[0]));
            emit(T.stringof, _value);
            }
            return;
        }
        catch (Exception e) { printf("### Exception in PubA2.set()\n"); /* todo: handle exception */ }
////assumeWontThrow(writefln(T.stringof~"### object was set (without emit) to values %04X, %s", _value[0], _value[1]));
    }

    mixin Pub_boilerplate!(T,V[2]);

    ub2  fidub2;
}
