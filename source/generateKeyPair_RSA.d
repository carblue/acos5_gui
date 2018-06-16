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

module generateKeyPair_RSA;

import core.memory : GC;
import core.runtime : Runtime;
import core.stdc.stdlib : strtol, strtoull, exit;
import std.signals;
import std.stdio;
import std.exception : assumeWontThrow, assumeUnique;
import std.conv: to;
import std.format;
import std.range : iota;
import std.range.primitives : empty, front;
import std.array : array;
import std.algorithm.comparison : among, clamp, equal, min, max;
import std.algorithm.searching : canFind, countUntil, all, any, find;
//import std.algorithm.iteration : uniq;
//import std.algorithm.sorting : sort;
import std.typecons : Tuple, tuple;
//import std.ascii : isHexDigit;
import std.string : /*chomp, */  toStringz, fromStringz;
import std.digest; // : toHexString;

import libopensc.opensc;
import libopensc.types;
import libopensc.errors;
import libopensc.log;

import iup.iup_plusD;

import libintl : _, __;

import util_general;// : ub22integral;
import acos5_64_shared;

import util_opensc : lh, card, acos5_64_short_select, readFile, decompose, PKCS15Path_FileType, pkcs15_names,
    PKCS15_FILE_TYPE, fs, sitTypeFS, PRKDF, PUKDF, AODF, cry_____7_4_4___46_generate_keypair_RSA,
    util_connect_card, connect_card, PKCS15_ObjectTyp, errorDescription, PKCS15, iter_begin, appdf, prkdf, pukdf, tnTypePtr;

//import asn1_pkcs15 : CIO_RSA_private, CIO_RSA_public, CIO_Auth_Pin, encodeEntry_PKCS15_PRKDF, encodeEntry_PKCS15_PUKDF;
import libtasn1;


int getIdentifier(const ref PKCS15_ObjectTyp ot, string nodeName, bool new_=true) nothrow {
    /* Identifier ::= OCTET STRING (SIZE (0..255)) */
    ubyte[2]  str;
    int outLen;
    int asn1_result;
    if ((asn1_result= asn1_read_value(new_? ot.structure_new : ot.structure, nodeName, str, outLen)) != ASN1_SUCCESS) {
        assumeWontThrow(writefln("### asn1_read_value %s: %s", nodeName, asn1_strerror2(asn1_result)));
        return -1;
    }
    assert(outLen==1);
    return str[0];
}
/+
long getLong(const ref PKCS15_ObjectTyp ot, string nodeName, bool new_=true) nothrow {
    ubyte[8]  str;
    int len = str.length;
    if (asn1_read_value(new_? ot.structure_new : ot.structure, nodeName.toStringz, &str[0], &len) != ASN1_SUCCESS)
        return -1;
    assert(len<=8 && str[0]<0x80);
    return ub82integral(str);
}
ulong getUlong(const ref PKCS15_ObjectTyp ot, string nodeName, bool new_=true) nothrow {
    ubyte[8]  str;
    int len = str.length;
    if (asn1_read_value(new_? ot.structure_new : ot.structure, nodeName.toStringz, &str[0], &len) != ASN1_SUCCESS)
        return 0;
    assert(len<=8);
    return ub82integral(str);
}
+/

enum /* matrixRowName */ {
    r_keyPairId = 1, // 5
      r_keyPairModifiable,
      r_usageRSAprivateKeyPrKDF,
    r_usageRSApublicKeyPuKDF,
      r_keyPairLabel,
      r_authIdRSAprivateFile,  // 13

      r_sizeNewRSAModulusBits,
      r_valuePublicExponent,   // 14,

    r_acos_internal,
    r_storeAsCRTRSAprivate,
    r_usageRSAprivateKeyACOS,

//    r_keyPairId, // 5

    r_fidRSAprivate, // 7
    r_fidRSApublic, // 8
    r_fidRSADir, // 6

    r_change_calcPrKDF, // 11
    r_change_calcPuKDF, // 12

    r_sizeNewRSAprivateFile, // 9
    r_sizeNewRSApublicFile, // 10


    r_statusInput,
    r_AC_Update_PrKDF_PuKDF,

    r_AC_Update_Delete_RSAprivateFile,
    r_AC_Update_Delete_RSApublicFile,
    r_AC_Create_Delete_RSADir,
}

// tag txpes
struct _sizeNewRSAModulusBits{}
struct _storeAsCRTRSAprivate{}
struct _usageRSAprivateKeyACOS{}
struct _usageRSAprivateKeyPrKDF{}


struct _keyPairId{}
struct _fidRSADir{}
struct _fidRSAprivate{}
struct _fidRSApublic{}

struct _valuePublicExponent{}
struct _keyPairLabel{}
struct _keyPairModifiable{}
struct _authIdRSAprivateFile{}

struct _AC_Update_PrKDF_PuKDF{}
struct _AC_Update_Delete_RSAprivateFile{}
struct _AC_Update_Delete_RSApublicFile{}

Pub!_sizeNewRSAModulusBits   sizeNewRSAModulusBits;
Pub!_storeAsCRTRSAprivate    storeAsCRTRSAprivate;
Pub!_usageRSAprivateKeyACOS  usageRSAprivateKeyACOS;  // interrelates with usageRSAprivateKeyPrKDF
Pub!_usageRSAprivateKeyPrKDF usageRSAprivateKeyPrKDF; // interrelates with usageRSAprivateKeyACOS
Obs_usageRSApublicKeyPuKDF   usageRSApublicKeyPuKDF;

Pub!_keyPairId               keyPairId;
Pub!_keyPairModifiable       keyPairModifiable;
Pub!_fidRSADir               fidRSADir;
PubA2!_fidRSAprivate         fidRSAprivate;
PubA2!_fidRSApublic          fidRSApublic;


Obs_sizeNewRSAprivateFile    sizeNewRSAprivateFile;
Obs_sizeNewRSApublicFile     sizeNewRSApublicFile;

Obs_change_calcPrKDF         change_calcPrKDF;
Obs_change_calcPuKDF         change_calcPuKDF;

PubA16!_valuePublicExponent  valuePublicExponent;

Pub!(_keyPairLabel,string)   keyPairLabel;
Pub!_authIdRSAprivateFile    authIdRSAprivateFile;

Obs_statusInput              statusInput;

Pub!(_AC_Update_PrKDF_PuKDF,          ubyte[2])  AC_Update_PrKDF_PuKDF;
Pub!(_AC_Update_Delete_RSAprivateFile,ubyte[2])  AC_Update_Delete_RSAprivateFile;
Pub!(_AC_Update_Delete_RSApublicFile, ubyte[2])  AC_Update_Delete_RSApublicFile;

mixin template Pub_boilerplate(T,V)
{
  @property V get() const /*@nogc*/ nothrow /*pure*/ /*@safe*/ { return _value; }
//  Handle handle() nothrow         { return _h1; }
//  void   handle(Handle h) nothrow { _h1 = h; }
/+
  void emit_self() nothrow {
    try
       emit(T.stringof, _value);
     catch (Exception e) { /* todo: handle exception */ }
  }
+/
  // Mix in all the code we need to make Foo into a signal
  mixin Signal!(string, V);


    private :
    V      _value;
    int    _lin;
    int    _col;
    Handle _h1;
    bool   _hexRep; // whether the user-communication is based on a hexadecimal representation: true: requires int <-> hex conversion
}

class Pub(T, V=int)
{
    this(int lin/*, int col*/, Handle control = null, bool hexRep = false) {
        _lin = lin;
        _col = 1;
        _h1  = control;
        _hexRep = hexRep;
        if (_h1 !is null)
            _h1.SetAttributeStr(T.stringof, cast(char*)this);
    }

    @property V get() const @nogc nothrow /*pure*/ @safe { return _value; }

    @property V set(V v, bool programmatically=false)  nothrow {
        try {
            _value = v;
assumeWontThrow(writefln(T.stringof~" object was set to value %s", _value));
            static if (is(T==_usageRSAprivateKeyACOS) || is(T==_usageRSAprivateKeyPrKDF) /*|| is(T==_usageRSApublicKeyPuKDF)*/) {
                if (_h1 !is null) {
//assumeWontThrow(writefln(T.stringof~" object was set to value %s and translate int", _value));
                    _h1.SetStringId2 ("", _lin, _col, keyUsageFlagsInt2string(_value));
                }
            }
            else static if (is(T==_keyPairLabel)) {
                if (programmatically && _h1 !is null) {
//assumeWontThrow(writefln(T.stringof~" object was set to value %s and translate int", _value));
                    _h1.SetStringId2 ("", _lin, _col, _value);
                }
            }
            else static if (is(T==_AC_Update_PrKDF_PuKDF) || is(T==_AC_Update_Delete_RSAprivateFile) || is(T==_AC_Update_Delete_RSApublicFile)) {
                if (programmatically && _h1 !is null) {
                    _h1.SetStringId2 ("", _lin, _col, format!"%02X"(_value[0])  ~" / "~format!"%02X"(_value[1]));
                }
            }
            else {
                if (programmatically &&  _h1 !is null)
                    _h1.SetStringId2 ("", _lin, _col, _hexRep? format!"%X"(_value) : _value.to!string);
            }
            emit(T.stringof, _value);
            /* this is critical for _keyPairId:
             * First change_calcPrKDF.watch and change_calcPuKDF.watch must run: They create/dup structure to structure_new
             * only then: set_more_for_keyPairId */
            static if (is (T == _keyPairId))
                set_more_for_keyPairId(_value);
        }
        catch (Exception e) { /* todo: handle exception */ }
        return _value;
    }

    mixin Pub_boilerplate!(T,V);
}

class PubA2(T, V=int)
{
    this(int lin/*, int col*/, Handle control = null) {
        _lin = lin;
        _col = 1;
        _h1  = control;
        if (_h1 !is null)
            _h1.SetAttributeStr(T.stringof, cast(char*)this);
    }

/*
V[2] mapping:
 0: fid
 1: fid_size

 if locate fid within appDF fails, both set to zero

 accepts a new fid from v[0] only, if acceptable
 and depending on that, retrieves the file's size into v[1];

 usable for both fidRSAprivate and fidRSApublic

    @property size_t length() const
    {
        return data.length ? data.length - 1 : 0;
    }

    //+ an extra slot for ref-count
    @property void length(size_t len)

*/
    @property void set(V[2] v, bool programmatically=false)  nothrow {
//assumeWontThrow(writeln(T.stringof~" object is about to be set"));
        auto t = Tuple!(ushort, ubyte, ubyte)(0,0,0);
        ub2  size_or_MRL_NOR;
        tnTypePtr  privORpub;
        sitTypeFS  pos_parent;
        try {
        /*if (v != _value)*/ {
            /* locate */
//            ub2 ub2fidRSADir = integral2ub!2(fidRSADir.get)[0..2];
//            if (equal([0,0], ub2fidRSADir[]))
//                appdf = fs.preOrderRange(fs.begin(), fs.end()).locate!"a[6]==b"(PKCS15_FILE_TYPE.PKCS15_APPDF);
//            else
//                appdf = fs.preOrderRange(fs.begin(), fs.end()).locate!"equal(a[2..4], b[])"(ub2fidRSADir);
//            if (appdf is null) {
//                _value = [0,0];
//                programmatically = true;
//                goto end;
//            }

            pos_parent = new sitTypeFS(appdf);
            privORpub = fs.siblingRange(fs.begin(pos_parent), fs.end(pos_parent)).locate!"equal(a[2..4], b[])"(integral2ub!2(v[0]));
            if (privORpub is null) {
                _value = [0,0];
                programmatically = true;
                goto end;
            }

            size_or_MRL_NOR = privORpub.data[4..6];
            t = decompose(cast(EFDB) privORpub.data[0], size_or_MRL_NOR);
            v[1] = t[0];
            _value = v;
end:
assumeWontThrow(writefln(T.stringof~" object was set to values %04X, %s", _value[0], _value[1]));
            if (programmatically &&  _h1 !is null)
                _h1.SetStringId2 ("", _lin, _col, format!"%4X"(_value[0]));
            emit(T.stringof, _value);
            }
            return;
        }
        catch (Exception e) { /* todo: handle exception */ }
assumeWontThrow(writefln(T.stringof~" object was set (without emit) to values %04X, %s", _value[0], _value[1]));
    }

    mixin Pub_boilerplate!(T,V[2]);
}

class PubA16(T, V=ubyte)
{
    this(int lin/*, int col*/, Handle control = null) {
        _lin = lin;
        _col = 1;
        _h1  = control;
        if (_h1 !is null)
            _h1.SetAttributeStr(T.stringof, cast(char*)this);
    }

    @property V[16] set(V[16] v, bool programmatically=false)  nothrow {
//    void set(V v, int pos /*position in V[8], 0-basiert*/, bool programmatically=false)  nothrow {
//int    BN_is_prime_ex(const(BIGNUM)* p,int nchecks, BN_CTX* ctx, BN_GENCB* cb);
        import deimos.openssl.bn : BIGNUM, BN_prime_checks, BN_CTX, BN_CTX_new, BN_is_prime_ex, BN_bin2bn, BN_free, BN_CTX_free;
        try
        if (v != _value) {
            BN_CTX* ctx = BN_CTX_new();
            BIGNUM* p  = BN_bin2bn(v.ptr, v.length, null);
            scope(exit) {
                BN_free(p);
                BN_CTX_free(ctx);
            }
            _value = BN_is_prime_ex(p, BN_prime_checks, ctx, /*BN_GENCB* cb*/ null)? v : typeof(v).init;
            if (programmatically &&  _h1 !is null) {
                // trim leading zero bytes
                ptrdiff_t  pos = clamp(_value[].countUntil!"a>0", -1,15);
                _h1.SetStringId2 ("", _lin, _col, format!"%(%02X%)"(pos==-1? [ubyte(0)] : _value[pos..$]));
            }
            emit(T.stringof, _value);
        }
        catch (Exception e) { /* todo: handle exception */ }
assumeWontThrow(writefln(T.stringof~" object (was set to) values %(%02X %)", _value));
        return _value;
    }

    mixin Pub_boilerplate!(T,V[16]);
}

class Obs_usageRSApublicKeyPuKDF {
    this(int lin/*, int col*/, Handle control = null) {
        _lin = lin;
        _col = 1;
        _h = control;
    }

    @property int get() const @nogc nothrow /*pure*/ @safe { return _value; }
    void watch(string msg, int v) {
        switch(msg) {
            case "_usageRSAprivateKeyPrKDF":
                _usageRSAprivateKeyPrKDF = v;
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

assumeWontThrow(writefln(typeof(this).stringof~" object was set to value %s", _value));
        emit("_usageRSApublicKeyPuKDF", _value);

        if (_h !is null) {
            _h.SetStringId2 ("", _lin, _col, keyUsageFlagsInt2string(_value));
            _h.Update;
        }
    }

    mixin Signal!(string, int);

    private :
        int  _usageRSAprivateKeyPrKDF;

        int    _value;
        int    _lin;
        int    _col;
        Handle _h;
}

class Obs_sizeNewRSAprivateFile { // T für tag Klassen _KULIR1, _RLTGv, _RLTGn
    this(int lin/*, int col*/, Handle control = null) {
        _lin = lin;
        _col = 1;
        _h = control;
    }

    @property int get() const @nogc nothrow /*pure*/ @safe { return _value; }

    void watch(string msg, int[2] v) {
        switch(msg) {
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

    void watch(string msg, int v) {
        switch(msg) {
            case "_sizeNewRSAModulusBits":
                _sizeNewRSAModulusBits = v;
                break;
            case "_storeAsCRTRSAprivate":
                _storeAsCRTRSAprivate = v;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        _value =  _sizeNewRSAModulusBits<=0? 0 : 5 + _sizeNewRSAModulusBits/16*(_storeAsCRTRSAprivate ? 5 : 2);
        present();
    }

    void present()
    {
//        emit("_sizeNewRSAprivateFile", _value);
assumeWontThrow(writefln(typeof(this).stringof~" object was set to _fidRSAprivate(%04X), _fidSizeRSAprivate(%s), _value(%s)", _fidRSAprivate, _fidSizeRSAprivate, _value));

        if (_h !is null) {
            _h.SetStringId2 ("", _lin, _col, _fidSizeRSAprivate.to!string ~" / "~ _value.to!string);
            _h.Update;
        }
    }

//    mixin Signal!(string, int);

    private :
        int  _fidRSAprivate;
        int  _fidSizeRSAprivate;

        int  _sizeNewRSAModulusBits;
        int  _storeAsCRTRSAprivate;

//ubyte[] old;
//ubyte[] new_;

        int    _value;
        int    _lin;
        int    _col;
        Handle _h;
} // class Obs_sizeNewRSAprivateFile

class Obs_sizeNewRSApublicFile {
    this(int lin/*, int col*/, Handle control = null) {
        _lin = lin;
        _col = 1;
        _h = control;
    }

    @property int get() const @nogc nothrow /*pure*/ @safe { return _value; }
    void watch(string msg, int[2] v) {
        switch(msg) {
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
    void watch(string msg, int v) {
        switch(msg) {
            case "_sizeNewRSAModulusBits":
                _sizeNewRSAModulusBits = v;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        _value =  _sizeNewRSAModulusBits<=0? 0 : 21 + _sizeNewRSAModulusBits/8;
        present();
    }
    void present()
    {
//        emit("_sizeNewRSApublicFile", _value);
assumeWontThrow(writefln(typeof(this).stringof~" object was set to _fidRSApublic(%04X), _fidSizeRSApublic(%s), _value(%s)", _fidRSApublic, _fidSizeRSApublic, _value));

        if (_h !is null) {
            _h.SetStringId2 ("", _lin, _col, _fidSizeRSApublic.to!string ~" / "~ _value.to!string);
            _h.Update;
        }
    }

//    mixin Signal!(string, int);

    private :
        int  _fidRSApublic;
        int  _fidSizeRSApublic;
        int  _sizeNewRSAModulusBits;

        int    _value;
        int    _lin;
        int    _col;
        Handle _h;
} // class Obs_sizeNewRSApublicFile

class Obs_change_calcPrKDF {
    this(int lin/*, int col*/, Handle control = null) {
        _lin = lin;
        _col = 1;
        _h = control;
    }

    @property ref PKCS15_ObjectTyp  pkcs15_ObjectTyp() @nogc nothrow /*pure*/ @safe { return _PrKDFentry; }
    @property     const(int)        get()        const @nogc nothrow /*pure*/ @safe { return _value; }

    void watch(string msg, int v) {
        import core.bitop : bitswap;
        int asn1_result;
        int outLen;
        switch (msg) {
            case "_keyPairId":
                {
                    auto haystackPriv= find!((a,b) => getIdentifier(a, "privateRSAKey.commonKeyAttributes.iD", false) == b)(PRKDF, v);
                    assert(!haystackPriv.empty);
                    _PrKDFentry = haystackPriv.front;
                    assert(_PrKDFentry.structure_new is null); // newer get's set in PRKDF
                    assert(_PrKDFentry.der_new is null);       // newer get's set in PRKDF
                    _PrKDFentry.structure_new = asn1_dup_node(_PrKDFentry.structure, "");

////                    assumeWontThrow(writefln("_old_encodedData of PrKDFentry: %(%02X %)", _PrKDFentry.der));
                }
                break;

            case "_authIdRSAprivateFile":
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
                if (asn1_result != ASN1_SUCCESS) {
                    assumeWontThrow(writeln("### asn1_read_value privateRSAKey.commonObjectAttributes.flags: ", asn1_strerror2(asn1_result)));
                    break;
                }
                assert(outLen==2); // bits
                flags[0] = util_general.bitswap(flags[0]);

                ubyte[1] tmp = util_general.bitswap( cast(ubyte) ((flags[0]&0xFE) | (v!=0)) );
                asn1_write_value(_PrKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.flags", tmp.ptr, 2); // 2 bits
                break;

            case "_keyPairModifiable":
                ubyte[1] flags; // optional
                asn1_result = asn1_read_value(_PrKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.flags", flags, outLen);
                if (asn1_result != ASN1_SUCCESS) {
                    assumeWontThrow(writeln("### asn1_read_value privateRSAKey.commonObjectAttributes.flags: ", asn1_strerror2(asn1_result)));
                    break;
                }
                assert(outLen==2); // bits
                flags[0] = util_general.bitswap(flags[0]);

                ubyte[1] tmp = util_general.bitswap( cast(ubyte) ((flags[0]&0xFD) | (v!=0)*2) );
                asn1_write_value(_PrKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.flags", tmp.ptr, 2); // 2 bits
                break;

            case "_sizeNewRSAModulusBits":
                ubyte[] tmp = integral2ub!2(v);
                asn1_write_value(_PrKDFentry.structure_new, "privateRSAKey.privateRSAKeyAttributes.modulusLength", tmp.ptr, cast(int)tmp.length);
                break;

            case "_usageRSAprivateKeyPrKDF":
                ubyte[] tmp = integral2ub!4(bitswap(v));
                asn1_write_value(_PrKDFentry.structure_new, "privateRSAKey.commonKeyAttributes.usage", tmp.ptr, 10); // 10 bits
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
            case "_keyPairLabel":
                char[] label = v.dup ~ '\0';
                GC.addRoot(cast(void*)label.ptr);
                GC.setAttr(cast(void*)label.ptr, GC.BlkAttr.NO_MOVE);
                asn1_result = asn1_write_value(_PrKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.label", label.ptr, 0);
                if (asn1_result != ASN1_SUCCESS)
                    assumeWontThrow(writeln("### asn1_write_value privateRSAKey.commonObjectAttributes.label: ", asn1_strerror2(asn1_result)));
                break;

            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        present();
    }

    void present()
    {
        assert(_PrKDFentry.posEnd); // it has been set
        _PrKDFentry.der_new = new ubyte[_PrKDFentry.der.length+32];
        int outDerLen;
        int asn1_result = asn1_der_coding(_PrKDFentry.structure_new, "", _PrKDFentry.der_new, outDerLen, errorDescription);
        if (asn1_result != ASN1_SUCCESS)
        {
            printf ("\n### _PrKDFentry.der_new encoding creation: ERROR  with Obs_change_calcPrKDF\n");
//                    assumeWontThrow(writeln("### asn1Coding: ", errorDescription));
            return;
        }
        if (outDerLen)
            _PrKDFentry.der_new.length = outDerLen;
        _value = cast(int)(_PrKDFentry.der_new.length - _PrKDFentry.der.length);
//        emit("_change_calcPrKDF", _value);
assumeWontThrow(writefln(typeof(this).stringof~" object was set"));
////assumeWontThrow(writefln("_new_encodedData of PrKDFentry: %(%02X %)", _PrKDFentry.der_new));
        if (_h !is null) {
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

class Obs_change_calcPuKDF {
    this(int lin/*, int col*/, Handle control = null) {
        _lin = lin;
        _col = 1;
        _h = control;
    }

//    @property const(ubyte[]) old_encodedData() const @nogc nothrow /*pure*/ @safe { return _PuKDFentry.der; }
//    @property const(ubyte[]) new_encodedData() const @nogc nothrow /*pure*/ @safe { return _PuKDFentry.der_new; }
    @property ref PKCS15_ObjectTyp  pkcs15_ObjectTyp() @nogc nothrow /*pure*/ @safe { return _PuKDFentry; }
    @property     const(int)        get()        const @nogc nothrow /*pure*/ @safe { return _value; }

    void watch(string msg, int v) {
        import core.bitop : bitswap;
        int asn1_result;
        int outLen;
        switch (msg) {
            case "_keyPairId":
                {
                    auto haystackPubl= find!((a,b) => getIdentifier(a, "publicRSAKey.commonKeyAttributes.iD", false) == b)(PUKDF, v);
                    assert(!haystackPubl.empty);
                    _PuKDFentry = haystackPubl.front;
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

            case "_keyPairModifiable":
                ubyte[1] flags; // optional
                asn1_result = asn1_read_value(_PuKDFentry.structure_new, "publicRSAKey.commonObjectAttributes.flags", flags, outLen);
                if (asn1_result != ASN1_SUCCESS) {
                    assumeWontThrow(writeln("### asn1_read_value publicRSAKey.commonObjectAttributes.flags: ", asn1_strerror2(asn1_result)));
                    break;
                }
                assert(outLen==2); // bits
                flags[0] = util_general.bitswap(flags[0]);

////                _PuKDFentry.commonObjectAttributes.flags = (_PuKDFentry.commonObjectAttributes.flags&~2) | (v!=0)*2;
                ubyte[1] tmp = util_general.bitswap( cast(ubyte) ((flags[0]&0xFD) | (v!=0)*2) );
                asn1_write_value(_PuKDFentry.structure_new, "publicRSAKey.commonObjectAttributes.flags", tmp.ptr, 2); // 2 bits
                break;

            case "_sizeNewRSAModulusBits":
                ubyte[] tmp = integral2ub!2(v);
                asn1_write_value(_PuKDFentry.structure_new, "publicRSAKey.publicRSAKeyAttributes.modulusLength", tmp.ptr, cast(int)tmp.length);
                break;

            case "_usageRSApublicKeyPuKDF":
                ubyte[] tmp = integral2ub!4(bitswap(v));
                asn1_write_value(_PuKDFentry.structure_new, "publicRSAKey.commonKeyAttributes.usage", tmp.ptr, 10); // 10 bits
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
            case "_keyPairLabel":
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
        assert(_PuKDFentry.posEnd); // it has been set
        _PuKDFentry.der_new = new ubyte[_PuKDFentry.der.length+32];
        int outDerLen;
        int asn1_result = asn1_der_coding(_PuKDFentry.structure_new, "", _PuKDFentry.der_new, outDerLen, errorDescription);
        if (asn1_result != ASN1_SUCCESS)
        {
            printf ("\n### _PuKDFentry.der_new encoding creation: ERROR  with Obs_change_calcPuKDF\n");
//                    assumeWontThrow(writeln("### asn1Coding: ", errorDescription));
            return;
        }
        if (outDerLen)
            _PuKDFentry.der_new.length = outDerLen;
        _value = cast(int)(_PuKDFentry.der_new.length - _PuKDFentry.der.length);
//        emit("_change_calcPuKDF", _value);
assumeWontThrow(writefln(typeof(this).stringof~" object was set"));
////assumeWontThrow(writefln("_new_encodedData of PuKDFentry: %(%02X %)", _PuKDFentry.der_new));
        if (_h !is null) {
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


class Obs_statusInput {
    this(int lin/*, int col*/, Handle control = null) {
        _lin = lin;
        _col = 1;
        _h = control;
    }

  @property bool[5] get() const /*@nogc*/ nothrow /*pure*/ /*@safe*/ { return _value; }

//    @property bool[4] val() const @nogc nothrow /*pure*/ @safe { return _value; }

    void watch(string msg, int[2] v) {
        switch(msg) {
            case "_fidRSAprivate":
                _value[2] = all(v[]);
                break;
            case "_fidRSApublic":
                _value[3] = all(v[]);
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        calculate();
    }
    void watch(string msg, int v) {
        switch(msg) {
            case "_fidRSADir":
                _value[1] = v>0;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        calculate();
    }
    void calculate() {
        _value[0] = all(_value[1..$]);
//        emit("_statusInput", _value);
assumeWontThrow(writefln(typeof(this).stringof~" object was set to values %(%s %)", _value));

        with (_h) if (_h !is null) {
            if (_value[0]) {
                SetStringId2 ("", _lin, _col, "Okay, subject to authentication");
                SetRGBId2(IUP_BGCOLOR, _lin, _col, 0, 255, 0);
            }
            else {
                SetStringId2 ("", _lin, _col, "Something is missing");
                SetRGBId2(IUP_BGCOLOR, _lin, _col, 255, 0, 0);
            }
            _h.Update;
        }
    }

//    mixin Signal!(string, bool[5]);

    private :
/*
bool[10] mapping:
 0==true: overall okay;
 1==true: appdf !is null, i.e. appDir exists
 2==true: fidRSAprivate exists and is below appDir in same directory as fidRSApublic
 3==true: fidRSApublic exists  and is below appDir in same directory as fidRSAprivate
 4==true  fidRSAprivate and fidRSApublic are a key pair with common key id; may also read priv file from pub in order to verify


 00a40000024100
00c0000032
00200081083132333435363738

002201 B6 0A 800110 8102 4131 950180
002201 B6 0A 800110 8102 41F1 950140
00460000 02 2004

*/
        bool[5]  _value = [false,  false, false, false,  true ];
        int       _lin;
        int       _col;
        Handle    _h;
}
/+
class Obs_statusAuth {
    this(int lin/*, int col*/, Handle control = null) {
        _lin = lin;
        _col = 1;
        _h = control;
    }

    private :

        int    _value;
        int    _lin;
        int    _col;
        Handle _h;
}
+/
/*

00A40000024100
00C0000032
00A40000024131
00C0000020
00A400000241F1
00C0000020

Beginning script execution...

Sending: 00 A4 00 00 02 41 00
Received: 61 32
0x32 bytes of response still available.

Sending: 00 C0 00 00 32
Received: 6F 30 83 02 41 00 88 01 00 8A 01 05 82 02 38 00
8D 02 41 03 84 10 41 43 4F 53 50 4B 43 53 2D 31
35 76 31 2E 30 30 8C 08 7F 03 FF 00 01 01 01 01
AB 00 90 00
Normal processing.

Sending: 00 A4 00 00 02 41 31
Received: 61 20
0x20 bytes of response still available.

Sending: 00 C0 00 00 20
Received: 6F 1E 83 02 41 31 88 01 11 8A 01 05 82 02 09 00
80 02 02 15 8C 08 7F 01 FF 00 01 00 01 00 AB 00
90 00
Normal processing.

Sending: 00 A4 00 00 02 41 F1
Received: 61 20
0x20 bytes of response still available.

Sending: 00 C0 00 00 20
Received: 6F 1E 83 02 41 F1 88 01 11 8A 01 05 82 02 09 00
80 02 05 05 8C 08 7F 01 FF 00 01 01 01 FF AB 00
90 00
Normal processing.

priv 4112 54==0x36
3034300F0C0662616C6F6F6E030206C0040101300F0401040303062000030203B8020104A110300E300804063F00410041F402020C00

public 4113 51=0x33
3031300C0C0662616C6F6F6E03020640300F040104030306020003020348020104A110300E300804063F004100413402020C00
*/

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

int set_more_for_keyPairId(int keyPairId) nothrow
{
    import core.bitop : bitswap;

//assumeWontThrow(writefln("toggle_RSA_: %s", AA["toggle_RSA_"].GetIntegerVALUE()));
    printf("set_more_for_keyPairId (%d)\n", keyPairId);

    int  asn1_result;
    int  outLen;

    assert(keyPairId > 0);
    auto haystackPriv= find!((a,b) => getIdentifier(a, "privateRSAKey.commonKeyAttributes.iD", false) == b)(PRKDF, keyPairId);
    assert(!haystackPriv.empty);
    PKCS15_ObjectTyp  PrKDFentry = haystackPriv.front; // by reference

    auto haystackPubl= find!((a,b) => getIdentifier(a, "publicRSAKey.commonKeyAttributes.iD", false) == b)(PUKDF, keyPairId);
    assert(!haystackPubl.empty);
    PKCS15_ObjectTyp  PuKDFentry = haystackPubl.front;

    ubyte[1] flags; // optional
    asn1_result = asn1_read_value(PrKDFentry.structure, "privateRSAKey.commonObjectAttributes.flags", flags, outLen);
    if (asn1_result != ASN1_SUCCESS)
        assumeWontThrow(writeln("### asn1_read_value privateRSAKey.commonObjectAttributes.flags: ", asn1_strerror2(asn1_result)));
    else {
        assert(outLen==2); // bits
        flags[0] = util_general.bitswap(flags[0]);

        keyPairModifiable.set((flags[0]&2)/2, true);

        if (!keyPairModifiable.get &&  (/+ AA["toggle_RSA_key_pair_delete"].GetIntegerVALUE() || +/
                                        AA["toggle_RSA_key_pair_generate"].GetIntegerVALUE() ) ) {
            IupMessage("Feedback upon setting keyPairId",
"The PrKDF entry for the selected keyPairId disallows modifying the RSA private key !\nThe toggle will be changed to toggle_RSA_PrKDF_PuKDF_change toggled");
            AA["toggle_RSA_PrKDF_PuKDF_change"].SetIntegerVALUE(1);
        }
    }
    ubyte[1] authId; // optional
    asn1_result = asn1_read_value(PrKDFentry.structure, "privateRSAKey.commonObjectAttributes.authId", authId, outLen);
    if (asn1_result != ASN1_SUCCESS) {
        assumeWontThrow(writeln("### asn1_read_value privateRSAKey.commonObjectAttributes.authId: ", asn1_strerror2(asn1_result)));
    }
    else {
        assert(outLen==1);
        if (authId[0])
            assert(flags[0]&1); // may run into a problem if asn1_read_value for flags failed
        authIdRSAprivateFile.set(authId[0], true);
    }


    { // make label inaccessible when leaving the scope
        char[] label = new char[65]; // optional
        label[0..65] = '\0';
        asn1_result = asn1_read_value(PrKDFentry.structure, "privateRSAKey.commonObjectAttributes.label", label, outLen);
        if (asn1_result != ASN1_SUCCESS) {
            assumeWontThrow(writeln("### asn1_read_value privateRSAKey.commonObjectAttributes.label: ", asn1_strerror2(asn1_result)));
        }
        else
            keyPairLabel.set(assumeUnique(label[0..outLen]), true);
    }

    ubyte[2] keyUsageFlags; // non-optional
    asn1_result = asn1_read_value(PrKDFentry.structure, "privateRSAKey.commonKeyAttributes.usage", keyUsageFlags, outLen);
    if (asn1_result != ASN1_SUCCESS)
        assumeWontThrow(writeln("### asn1_read_value privateRSAKey.commonKeyAttributes.usage: ", asn1_strerror2(asn1_result)));
    else {
        assert(outLen==10); // bits
//assumeWontThrow(writefln("keyUsageFlags: %(%02X %)", keyUsageFlags));
        usageRSAprivateKeyPrKDF.set( bitswap(ub22integral(keyUsageFlags)<<16), true);
    }

//        with (PrKDFentry.privateRSAKeyAttributes) {

    ubyte[2] modulusLength; // non-optional
    asn1_result = asn1_read_value(PrKDFentry.structure, "privateRSAKey.privateRSAKeyAttributes.modulusLength", modulusLength, outLen);
    if (asn1_result == ASN1_ELEMENT_NOT_FOUND)
        assumeWontThrow(writeln("### asn1_read_value privateRSAKey.privateRSAKeyAttributes.modulusLength: ", asn1_strerror2(asn1_result)));
    assert(outLen==2);
//assumeWontThrow(writefln("modulusLength: %(%02X %)", modulusLength));
    sizeNewRSAModulusBits.set(ub22integral(modulusLength), true);

    ubyte[16]  str;
    asn1_result = asn1_read_value(PrKDFentry.structure, "privateRSAKey.privateRSAKeyAttributes.value.indirect.path.path", str, outLen);
    if (asn1_result == ASN1_ELEMENT_NOT_FOUND) {
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
//            usageRSApublicKeyPuKDF.set(usage, true);
            assert(PrKDFentry.commonKeyAttributes.keyReference  == keyReference);
        }
+/

    asn1_result = asn1_read_value(PuKDFentry.structure, "publicRSAKey.publicRSAKeyAttributes.value.indirect.path.path", str, outLen);
    if (asn1_result == ASN1_ELEMENT_NOT_FOUND) {
        assumeWontThrow(writeln("### asn1_read_value publicRSAKey.publicRSAKeyAttributes.value.indirect.path.path: ", asn1_strerror2(asn1_result)));
        exit(1);
    }
    assert(outLen>=2);
    fidRSApublic.set( [ub22integral(str[outLen-2..outLen]), 0], true );


    tnTypePtr rsaPub;
    with (AA["matrixRsaAttributes"])
    try {
        ub2 ub2fidRSAPriv = integral2ub!2(fidRSAprivate.get[0])[0..2];
        tnTypePtr rsaPriv = fs.preOrderRange(iter_begin, fs.end()).locate!"equal(a[2..4], b[])"(ub2fidRSAPriv);
//        SetStringId2("", r_AC_Update_Delete_RSAprivateFile, 1, rsaPriv is null? "unknown / unknown" : format!"%02X"(rsaPriv.data[25])~" / "~format!"%02X"(rsaPriv.data[30]));
        AC_Update_Delete_RSAprivateFile.set(rsaPriv is null? [ubyte(0xFF), ubyte(0xFF)] : [rsaPriv.data[25], rsaPriv.data[30]], true);

        ub2 ub2fidRSAPub  = integral2ub!2(fidRSApublic.get[0])[0..2];
        rsaPub  = fs.preOrderRange(iter_begin, fs.end()).locate!"equal(a[2..4], b[])"(ub2fidRSAPub);
//        SetStringId2("", r_AC_Update_Delete_RSApublicFile,  1, rsaPub is null?  "unknown / unknown" : format!"%02X"(rsaPub.data[25]) ~" / "~format!"%02X"(rsaPub.data[30]));
        AC_Update_Delete_RSApublicFile.set(rsaPub is null? [ubyte(0xFF), ubyte(0xFF)]   : [rsaPub.data[25],  rsaPub.data[30]], true);
    }
    catch (Exception e) {}
////
    enum string commands = `
import std.range : chunks;
int rv;
foreach (ub2 fid; chunks(rsaPub.data[8..8+rsaPub.data[1]], 2))
    rv= acos5_64_short_select(card, null, fid, true);
assert(rv==0);
ub16 buf;
rv= sc_get_data(card, 5, buf.ptr, buf.length);
assert(rv==buf.length);
valuePublicExponent.set(buf, true);
`;
    mixin (connect_card!commands);
    return 0;
}

/+
void updatePrKDFPuKDF() {
    if (equal(change_calcPrKDF.old_encodedData, change_calcPrKDF.new_encodedData) &&
        equal(change_calcPuKDF.old_encodedData, change_calcPuKDF.new_encodedData)) { // replace 1 PrKDFentry only
        AA["statusbar"].SetString(IUP_TITLE, "SUCCESS: Nothing had to be done for PrKDF and PuKDF");
        return;
    }
    int rc;
    auto haystackPriv= find!"a.cio_RSA_private.commonKeyAttributes.iD == b"(PrKDF, keyPairId.get);
    assert(!haystackPriv.empty);
    uint posStartPriv = haystackPriv.front.posStart;
    uint posEnd1Priv  = haystackPriv.front.posEnd;
    uint posEnd2Priv  = haystackPriv[$-1].posEnd;
//    CIO_RSA_private  PrKDFentry = haystackPriv.front.cio_RSA_private;
    if (change_calcPrKDF.get==0) { // replace 1 PrKDFentry only
        if (equal(change_calcPrKDF.old_encodedData, change_calcPrKDF.new_encodedData)) {
            AA["statusbar"].SetString(IUP_TITLE, "SUCCESS: Nothing had to be done for PrKDF");
            return;
        }

//	    rc = sc_update_binary(card, posStartPriv, const(ubyte)* buf, posEnd1Priv-posStartPriv, 0);
    }
    else {

    }
//
    auto haystackPubl= find!"a.cio_RSA_public.commonKeyAttributes.iD == b"(PuKDF, keyPairId.get);
    assert(!haystackPubl.empty);
//    CIO_RSA_public   PuKDFentry = haystackPubl.front.cio_RSA_public;
    uint posStartPubl = haystackPubl.front.posStart;
    uint posEnd1Publ  = haystackPubl.front.posEnd;
    uint posEnd2Publ  = haystackPubl[$-1].posEnd;
}
+/

extern(C) nothrow
{

int matrixRsaAttributes_dropcheck_cb(Ihandle* self, int lin, int col) {
//  printf("matrixRsaAttributes_dropcheck_cb(%d, %d)\n", lin, col);
//  printf("matrixRsaAttributes_dropcheck_cb %s\n", AA["radio_RSA"].GetStringVALUE().toStringz);
    if (col==2)
        return IUP_IGNORE; // draw nothing
    Handle hR = AA["radio_RSA"];
    Handle hM = AA["matrixRsaAttributes"];
    switch (lin) {
    /* dropdown */
        case r_keyPairId:
            if (hR.GetStringVALUE()!="toggle_RSA_key_pair_create_and_generate")
                return IUP_DEFAULT; // show the dropdown/popup menu
            return     IUP_IGNORE; // draw nothing

        case r_authIdRSAprivateFile:
            if (hR.GetStringVALUE()!="toggle_RSA_key_pair_delete"  &&
                  hM.GetIntegerId2("", r_keyPairId, 1) != 0)
                return IUP_DEFAULT; // show the dropdown/popup menu
            return     IUP_IGNORE; // draw nothing

        case r_sizeNewRSAModulusBits:
            if (hR.GetStringVALUE()!="toggle_RSA_PrKDF_PuKDF_change"  &&
                hR.GetStringVALUE()!="toggle_RSA_key_pair_delete"  &&
                  hM.GetIntegerId2("", r_keyPairId, 1) != 0)
                return IUP_DEFAULT; // show the dropdown/popup menu
            return     IUP_IGNORE; // draw nothing

    /* toggle */
        case r_storeAsCRTRSAprivate:
            if (hR.GetStringVALUE()!="toggle_RSA_PrKDF_PuKDF_change"  &&
                hR.GetStringVALUE()!="toggle_RSA_key_pair_delete")
                return IUP_CONTINUE; // show and enable the toggle button ; this short version works with TOGGLECENTERED only !
            return     IUP_IGNORE; // draw nothing

        case r_keyPairModifiable:
            if (hR.GetStringVALUE()!="toggle_RSA_key_pair_delete"  &&
                  hM.GetIntegerId2("", r_keyPairId, 1) != 0)
                return IUP_CONTINUE; // show and enable the toggle button ; this short version works with TOGGLECENTERED only !
            return     IUP_IGNORE; // draw nothing

        default:  return IUP_IGNORE; // draw nothing
    }
} // matrixRsaAttributes_dropcheck_cb

int matrixRsaAttributes_drop_cb(Ihandle* self, Ihandle* drop, int lin, int col) {
    printf("matrixRsaAttributes_drop_cb(%d, %d)\n", lin, col);
    if (col==2)
        return IUP_IGNORE; // draw nothing
//    Handle h = createHandle(drop);
    Handle hR = AA["radio_RSA"];
    ubyte[2]  str;
    int outLen;
    int asn1_result, rv;
    with (createHandle(drop))
    switch (lin) {
        case r_keyPairId:
            if (hR.GetStringVALUE()!="toggle_RSA_key_pair_create_and_generate") {
                int i = 1;
                foreach (const ref elem; PRKDF) {
                    if ((rv= getIdentifier(elem, "privateRSAKey.commonKeyAttributes.iD", false)) < 0)
                        continue;
                    SetIntegerId("", i++, rv);
                }
                SetAttributeId("", i, null);
                SetAttributeStr(IUP_VALUE, "");
                return IUP_DEFAULT;
            }
            return     IUP_IGNORE; // assert(0);

        case r_authIdRSAprivateFile:
            if (hR.GetStringVALUE()!="toggle_RSA_key_pair_delete") {
                int i = 1;
////                SetIntegerId("", i++, 0);
                foreach (const ref elem; AODF) {
                    asn1_result = asn1_read_value(elem.structure_new, "pinAuthObj.commonAuthenticationObjectAttributes.authId", str, outLen);
                    if (asn1_result == ASN1_ELEMENT_NOT_FOUND) {
                        if (asn1_read_value(elem.structure_new, "biometricAuthObj.commonAuthenticationObjectAttributes.authId", str, outLen) != ASN1_SUCCESS)
                            continue;
                    }
                    else if (asn1_result != ASN1_SUCCESS)
                        continue;
                    assert(outLen==1);
                    SetIntegerId("", i++, str[0]);
                }
                SetAttributeId("", i, null);
                SetAttributeStr(IUP_VALUE, "");
                return IUP_DEFAULT;
            }
            return     IUP_IGNORE; // assert(0);

        case r_sizeNewRSAModulusBits:
            foreach (i; 1..16)
                SetIntegerId("", i, 4096-(i-1)*256);
            SetAttributeId("", 16, null);
            SetAttributeStr(IUP_VALUE, "");
            return IUP_DEFAULT;

        default:
            return IUP_IGNORE; // assert(0);
    }
}

int matrixRsaAttributes_dropselect_cb(Ihandle* self, int lin, int col, Ihandle* /*drop*/, const(char)* t, int i, int v)
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
    printf("matrixRsaAttributes_dropselect_cb(%d, %d, %s, %d, %d)\n", lin, col, t, i, v);
    if (v && col==1) {
        Handle h = createHandle(self);

        switch (lin) {
            case r_sizeNewRSAModulusBits:
                sizeNewRSAModulusBits.set =  (17-i)*256;
                break;

            case r_keyPairId:
                keyPairId.set = h.GetIntegerVALUE;
                break;

            case r_authIdRSAprivateFile:
                authIdRSAprivateFile.set = h.GetIntegerVALUE;
                break;

            default:
                assert(0);//break;
        }
    }
    return IUP_CONTINUE; // return IUP_DEFAULT;
}

int matrixRsaAttributes_edition_cb(Ihandle* ih, int lin, int col, int mode, int update)
{
    printf("matrixRsaAttributes_edition_cb(%d, %d) mode: %d, update: %d\n", lin, col, mode, update);
    if (mode==1) {
        AA["statusbar"].SetString(IUP_TITLE, "statusbar");
        if (AA["matrixRsaAttributes"].GetIntegerId2("", r_keyPairId, 1)==0 && lin.among(r_keyPairModifiable,
                                                                                        r_usageRSAprivateKeyPrKDF,
                                                                                        r_keyPairLabel,
                                                                                        r_sizeNewRSAModulusBits))
            return IUP_IGNORE;
        if (AA["matrixRsaAttributes"].GetIntegerId2("", r_keyPairId, 1)==0 && lin==r_authIdRSAprivateFile &&
            AA["radio_RSA"].GetStringVALUE()!="toggle_RSA_key_pair_delete")
            return IUP_IGNORE;
        switch (AA["radio_RSA"].GetStringVALUE()) { // the active radio button
            case "toggle_RSA_PrKDF_PuKDF_change":
                if (col==2 ||lin.among(r_acos_internal,
//                                     r_keyPairId,
                                       r_sizeNewRSAModulusBits,
                                       r_storeAsCRTRSAprivate,
                                       r_usageRSAprivateKeyACOS,
//                                     r_keyPairLabel,
                                       r_fidRSADir,
                                       r_fidRSAprivate,
                                       r_fidRSApublic,
                                       r_sizeNewRSAprivateFile,
                                       r_sizeNewRSApublicFile,
                                       r_change_calcPrKDF,
                                       r_change_calcPuKDF,
//                                     r_authIdRSAprivateFile,
                                       r_valuePublicExponent,
                                       r_statusInput,
//                                     r_usageRSAprivateKeyPrKDF,
                                       r_usageRSApublicKeyPuKDF
//                                     r_keyPairModifiable
                )) // read_only
                    return IUP_IGNORE;
                else
                    return IUP_DEFAULT;
            case "toggle_RSA_key_pair_delete":
                if (col==2 ||lin.among(r_acos_internal,
//                                     r_keyPairId,
                                       r_sizeNewRSAModulusBits,
                                       r_storeAsCRTRSAprivate,
                                       r_usageRSAprivateKeyACOS,
                                       r_keyPairLabel,
                                       r_fidRSADir,
                                       r_fidRSAprivate,
                                       r_fidRSApublic,
                                       r_sizeNewRSAprivateFile,
                                       r_sizeNewRSApublicFile,
                                       r_change_calcPrKDF,
                                       r_change_calcPuKDF,
                                       r_authIdRSAprivateFile,
                                       r_valuePublicExponent,
                                       r_statusInput,
                                       r_usageRSAprivateKeyPrKDF,
                                       r_usageRSApublicKeyPuKDF,
                                       r_keyPairModifiable
                )) // read_only
                    return IUP_IGNORE;
                else
                    return IUP_DEFAULT;

            case "toggle_RSA_key_pair_generate",
                 "toggle_RSA_key_pair_create_and_generate":
                if (col==2 ||lin.among(r_acos_internal,
//                                     r_keyPairId,
//                                       r_sizeNewRSAModulusBits,
//                                       r_storeAsCRTRSAprivate,
//                                       r_usageRSAprivateKeyACOS,
//                                       r_keyPairLabel,
                                       r_fidRSADir,
                                       r_fidRSAprivate,
                                       r_fidRSApublic,
                                       r_sizeNewRSAprivateFile,
                                       r_sizeNewRSApublicFile,
                                       r_change_calcPrKDF,
                                       r_change_calcPuKDF,
//                                       r_authIdRSAprivateFile,
//                                       r_valuePublicExponent,
                                       r_statusInput,
//                                       r_usageRSAprivateKeyPrKDF,
                                       r_usageRSApublicKeyPuKDF
//                                       r_keyPairModifiable
                )) // read_only
                    return IUP_IGNORE;
                else
                    return IUP_DEFAULT;

            default:  assert(0);
        }
    }
    //mode==0
    if (lin.among(r_sizeNewRSAModulusBits, // obj.val set.method in matrixRsaAttributes_dropselect_cb
                  r_keyPairId,             // obj.val set.method in matrixRsaAttributes_dropselect_cb
                  r_authIdRSAprivateFile,  // obj.val set.method in matrixRsaAttributes_dropselect_cb
                  r_storeAsCRTRSAprivate,  // obj.val set.method in matrixRsaAttributes_togglevalue_cb
                  r_keyPairModifiable,     // obj.val set.method in matrixRsaAttributes_togglevalue_cb
    ))
        return IUP_DEFAULT;

    Handle h = createHandle(ih);
    char* cptr;
    switch (lin) {
        case r_fidRSADir:
            try {
                if ((cptr = h.GetAttributeStr("_fidRSADir")) != null) {
                    auto obj  = cast(Pub!_fidRSADir) cptr;
                    assert(obj !is null);
                    obj.set = cast(int) strtol(h.GetAttributeVALUE, null, 16);
                }
            } catch (Exception e) {}
            break;
/*
        case r_usageRSApublicKeyPuKDF:
            {
                invmp = clamp(h.GetIntegerVALUE & 209, 0, 1023);
                usageRSApublicKeyPuKDF.set(tmp, true); // strange, doesn't update with new string
                h.SetStringVALUE (keyUsageFlagsInt2string(tmp));
            }
            break;
*/
        case r_usageRSAprivateKeyPrKDF:
            {
                IupMessage("Feedback upon setting usageRSAprivateKeyPrKDF",
"Be carefull changing this: It was basically set to 'sign and/or decrypt' + possibly more when the key pair was generated.\nThis is the sole hint available about the actual key usage capability, which is not retrievable any more, hidden by non-readability of private key file.\nIf something gets set here that is outside generated key's usage capability, then don't be surprised if RSA operation(s) won't (all) work as You might expect !");
                int tmp = clamp(h.GetIntegerVALUE & 558, 0, 1023);
                usageRSAprivateKeyPrKDF.set(tmp, true); // strange, doesn't update with new string
                h.SetStringVALUE(keyUsageFlagsInt2string(tmp));
            }
            break;

        case r_usageRSAprivateKeyACOS:
            {
                int tmp = clamp(h.GetIntegerVALUE & 6, 2, 6);
                usageRSAprivateKeyACOS.set(tmp, true); // strange, doesn't update with new string
                h.SetStringVALUE(keyUsageFlagsInt2string(tmp));
            }
            break;

        case r_valuePublicExponent:
            {
                string tmp_str = h.GetStringVALUE();
                assert(tmp_str.length<=32 );
                while (tmp_str.length<32)
                    tmp_str = "0" ~ tmp_str;
                string tmp_str2 = tmp_str[ 0..16] ~ '\0' ~ tmp_str[16..32] ~ '\0';
                ub16 tmp_arr;
                tmp_arr[0.. 8] = integral2ub!8(strtoull(tmp_str2.ptr,    null, 16))[0..8];
                tmp_arr[8..16] = integral2ub!8(strtoull(tmp_str2.ptr+17, null, 16))[0..8];
                valuePublicExponent.set(tmp_arr, true); // strange, doesn't update with new string
                if (!any(valuePublicExponent.get[]))
                    h.SetStringVALUE("");
            }
            break;

        case r_keyPairLabel:
            keyPairLabel.set = h.GetStringVALUE();
            break;

        case r_authIdRSAprivateFile:
            authIdRSAprivateFile.set = cast(int) strtol(h.GetAttributeVALUE, null, 16);
            break;

        default:
            break;
    }
    return IUP_DEFAULT;
}

int matrixRsaAttributes_togglevalue_cb(Ihandle* self, int lin, int col, int status)
{
    printf("matrixRsaAttributes_togglevalue_cb(%d, %d) status: %d\n", lin, col, status);
    if (col==1 && lin==r_storeAsCRTRSAprivate)
        storeAsCRTRSAprivate.set = status;
    else if (col==1 && lin==r_keyPairModifiable && AA["matrixRsaAttributes"].GetIntegerId2("", r_keyPairId, 1)!=0)
        keyPairModifiable.set = status;
    return IUP_DEFAULT;
}
/+
int matrixRsaAttributes_click_cb(Ihandle* ih, int lin, int col, char* status)
{
  if (col>0 || lin>3)
    return IUP_DEFAULT;
  printf("matrixRsaAttributes_click_cb(%d, %d) status: %s\n", lin, col, status);
  return IUP_DEFAULT;
}
+/

int toggle_RSA_cb(Ihandle* ih, int state)
{
    if (state==0) {
        AA["statusbar"].SetString(IUP_TITLE, "statusbar");
        return IUP_DEFAULT;
    }
    printf("toggle_RSA_cb (%d)\n", state);
    Handle hButton = AA["btn_RSA"];
    Handle hRadio  = AA["radio_RSA"];
    with (AA["matrixRsaAttributes"])
    switch (hRadio.GetStringVALUE()) { // the active radio button
        case "toggle_RSA_PrKDF_PuKDF_change":            hButton.SetString(IUP_TITLE, "PrKDF/PuKDF only: Change some administrative (PKCS#15) data");
            SetRGBId2(IUP_BGCOLOR, r_keyPairModifiable,       1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_usageRSAprivateKeyPrKDF, 1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyPairLabel,            1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_authIdRSAprivateFile,    1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_sizeNewRSAModulusBits,   1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_valuePublicExponent,     1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_storeAsCRTRSAprivate,    1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_usageRSAprivateKeyACOS,  1,  255,255,255);
            break;
        case "toggle_RSA_key_pair_delete":               hButton.SetString(IUP_TITLE, "RSA key pair: Delete key pair files");
            SetRGBId2(IUP_BGCOLOR, r_keyPairModifiable,       1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_usageRSAprivateKeyPrKDF, 1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keyPairLabel,            1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_authIdRSAprivateFile,    1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_sizeNewRSAModulusBits,   1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_valuePublicExponent,     1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_storeAsCRTRSAprivate,    1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_usageRSAprivateKeyACOS,  1,  255,255,255);
            break;
        case "toggle_RSA_key_pair_generate":             hButton.SetString(IUP_TITLE, "RSA key pair: Regenerate RSA key pair content in existing files");
            SetRGBId2(IUP_BGCOLOR, r_keyPairModifiable,       1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_usageRSAprivateKeyPrKDF, 1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyPairLabel,            1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_authIdRSAprivateFile,    1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_sizeNewRSAModulusBits,   1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_valuePublicExponent,     1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_storeAsCRTRSAprivate,    1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_usageRSAprivateKeyACOS,  1,  152,251,152);
            break;
        case "toggle_RSA_key_pair_create_and_generate":  hButton.SetString(IUP_TITLE, "RSA key pair: Create new RSA key pair files and generate RSA key pair content");
            SetRGBId2(IUP_BGCOLOR, r_keyPairModifiable,       1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_usageRSAprivateKeyPrKDF, 1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyPairLabel,            1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_authIdRSAprivateFile,    1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_sizeNewRSAModulusBits,   1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_valuePublicExponent,     1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_storeAsCRTRSAprivate,    1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_usageRSAprivateKeyACOS,  1,  152,251,152);
            break;
        default:  assert(0);
    }
    return IUP_DEFAULT;
}

const char[] btn_RSA_cb_common1 =`
            int diff = change_calcPrKDF.get;
            ubyte[] zeroAdd = new ubyte[ diff>=0? 0 : abs(diff) ];
            auto haystackPriv = find!((a,b) => getIdentifier(a, "privateRSAKey.commonKeyAttributes.iD", false) == b)(PRKDF, keyPairId.get);
            assert(!haystackPriv.empty);
            // change_calcPrKDF.pkcs15_ObjectTyp shall be identical to resulting haystackPriv.front (except the _new components)!) !

            change_calcPrKDF.pkcs15_ObjectTyp.posEnd +=  diff;
            if (change_calcPrKDF.pkcs15_ObjectTyp.der_new !is null)
                haystackPriv.front.der = change_calcPrKDF.pkcs15_ObjectTyp.der =  change_calcPrKDF.pkcs15_ObjectTyp.der_new.dup;

            asn1_node  structurePriv;
            asn1_delete_structure(&haystackPriv.front.structure);
            int asn1_result = asn1_create_element(PKCS15, pkcs15_names[PKCS15_FILE_TYPE.PKCS15_PRKDF][3], &structurePriv);
            if (asn1_result != ASN1_SUCCESS) {
                assumeWontThrow(writeln("### Structure creation: ", asn1_strerror2(asn1_result)));
                return IUP_DEFAULT;
            }
            asn1_result = asn1_der_decoding(&structurePriv, haystackPriv.front.der, errorDescription);
            if (asn1_result != ASN1_SUCCESS) {
                assumeWontThrow(writeln("### asn1Decoding: ", errorDescription));
                return IUP_DEFAULT;
            }
            haystackPriv.front.structure                = structurePriv;
            change_calcPrKDF.pkcs15_ObjectTyp.structure = structurePriv;

            ubyte[] bufPriv;
            foreach (i, ref elem; haystackPriv) {
                bufPriv ~= elem.der;
                if (i>0)
                    elem.posStart += diff;
                elem.posEnd       += diff;
            }
            bufPriv ~=  zeroAdd;
            assert(prkdf);
//assumeWontThrow(writeln("  ### check change_calcPrKDF.pkcs15_ObjectTyp: ", change_calcPrKDF.pkcs15_ObjectTyp));
//assumeWontThrow(writeln("  ### check haystackPriv:                      ", haystackPriv));


            diff = change_calcPuKDF.get;
            zeroAdd = new ubyte[ diff>=0? 0 : abs(diff) ];
            auto haystackPubl = find!((a,b) => getIdentifier(a, "publicRSAKey.commonKeyAttributes.iD", false) == b)(PUKDF, keyPairId.get);
            assert(!haystackPubl.empty);
            // change_calcPuKDF.pkcs15_ObjectTyp shall be identical to resulting haystackPubl.front (except the _new components)!) !

            change_calcPuKDF.pkcs15_ObjectTyp.posEnd +=  diff;
            if (change_calcPuKDF.pkcs15_ObjectTyp.der_new !is null)
                haystackPubl.front.der = change_calcPuKDF.pkcs15_ObjectTyp.der =  change_calcPuKDF.pkcs15_ObjectTyp.der_new.dup;

            asn1_node  structurePubl;
            asn1_delete_structure(&haystackPubl.front.structure);
            asn1_result = asn1_create_element(PKCS15, pkcs15_names[PKCS15_FILE_TYPE.PKCS15_PUKDF][3], &structurePubl);
            if (asn1_result != ASN1_SUCCESS) {
                assumeWontThrow(writeln("### Structure creation: ", asn1_strerror2(asn1_result)));
                return IUP_DEFAULT;
            }
            asn1_result = asn1_der_decoding(&structurePubl, haystackPubl.front.der, errorDescription);
            if (asn1_result != ASN1_SUCCESS) {
                assumeWontThrow(writeln("### asn1Decoding: ", errorDescription));
                return IUP_DEFAULT;
            }
            haystackPubl.front.structure                = structurePubl;
            change_calcPuKDF.pkcs15_ObjectTyp.structure = structurePubl;

            ubyte[] bufPubl;
            foreach (i, ref elem; haystackPubl) {
                bufPubl ~= elem.der;
                if (i>0)
                    elem.posStart += diff;
                elem.posEnd       += diff;
            }
            bufPubl ~=  zeroAdd;
            assert(prkdf);
//assumeWontThrow(writeln("  ### check change_calcPuKDF.pkcs15_ObjectTyp: ", change_calcPuKDF.pkcs15_ObjectTyp));
//assumeWontThrow(writeln("  ### check haystackPubl:                      ", haystackPubl));
`;
//mixin(btn_RSA_cb_common1);


int btn_RSA_cb(Ihandle* ih)
{
    import std.math : abs;

    if (!statusInput.get()[0]) {
        assumeWontThrow(writeln("  ### statusInput doesn't allow the action requested"));
        return -1;
    }

    ubyte code(int storeAsCRTRSAprivate, int usageRSAprivateKeyACOS) nothrow {
        ubyte pre_result;
        switch (usageRSAprivateKeyACOS) {
            case 4: pre_result = 1; break;
            case 2: pre_result = 2; break;
            case 6: pre_result = 3; break;
            default: assert(0);
        }
        return cast(ubyte) (pre_result+ (storeAsCRTRSAprivate? 3 : 0));
    }

    Handle hstat = AA["statusbar"];

    switch (AA["radio_RSA"].GetStringVALUE()) { // the active radio button
        case "toggle_RSA_PrKDF_PuKDF_change":
            if (equal(change_calcPrKDF.pkcs15_ObjectTyp.der, change_calcPrKDF.pkcs15_ObjectTyp.der_new) &&
                equal(change_calcPuKDF.pkcs15_ObjectTyp.der, change_calcPuKDF.pkcs15_ObjectTyp.der_new) ) {
                IupMessage("Feedback", "Nothing changed! Won't write anything to files");
                return IUP_DEFAULT;
            }

            //Does statusInput check, that the bytes to be written to PrKDF and PuKDF are there in "free space"
//            {} // behavior changed: cases seem to introduce a new scope
            mixin(btn_RSA_cb_common1);
/+
int sc_verify(sc_card_t *card, unsigned int type, int ref,
	      const u8 *pin, size_t pinlen, int *tries_left)
{
	struct sc_pin_cmd_data data;

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_VERIFY;
	data.pin_type = type;
	data.pin_reference = ref;
	data.pin1.data = pin;
	data.pin1.len = pinlen;

	return sc_pin_cmd(card, &data, tries_left);
}
int sc_pin_cmd(sc_card* card, sc_pin_cmd_data*, int* tries_left);
sc_pin_cmd_data  pin_cmd_data = {SC_PIN_CMD.SC_PIN_CMD_VERIFY, SC_PIN_CMD_NEED_PADDING ... };

//	int sc_verify(sc_card* card,  uint type, int ref_, const(ubyte)* buf, size_t buflen, int* tries_left);
//rv= sc_verify(card,  SC_AC.SC_AC_CHV,  pinLocal? 0x80 | pinReference : pinReference, p_pinHex, 8, &tries_left);

            ub2 ac =  AC_Update_PrKDF_PuKDF.get;
            assert(ac[0] == ac[1], "PrKDF and PuKDF shall have the same SCB: Either both always readable or protected by the same pin");
            assert(ac[0] != 0xFF);
            int       tries_left;
            int       pinLocal = 1;
            int       pinReference = 1;
            char[32]  pin = "\0";
            ubyte*    p_pinHex = cast(ubyte*)pin.ptr;
            if (ac[0] != 0) {
                int r = IupGetParam("Pin requested for authorization (SCB "~toHexString!(Order.increasing,LetterCase.upper)(ac[0])~")", &param_action, null/* void* user_data*/, /*format*/
                    "&Pin local (User)? If local==No, then it's the Security Officer Pin:%b[No,Yes]\n" ~
                    "&Pin reference (1-31; selects the record# in pin file):%i\n" ~
                    "Pin (minLen: 4, maxLen: 8):%s\n", &pinLocal, &pinLocal, pin.ptr, null);
                assumeWontThrow(writeln("Value from IupGetParam: ", pin));
                assumeWontThrow(writefln("Value from IupGetParam hex: %(%02X %)", p_pinHex[0..8]));
                assumeWontThrow(writefln("Return button pressed: %s", r));
//Returns: a status code 1 if the button 1 was pressed, 0 if the button 2 was pressed or if an error occurred.
//IupGetParam - Button1 (OK)
//Value from IupGetParam: 12345678
//Value from IupGetParam hex: 31 32 33 34 35 36 37 38
//Return button pressed: 1

//IupGetParam - Button2 (Cancel)
//Value from IupGetParam:
//Value from IupGetParam hex: 00 00 00 00 00 00 00 00
//Return button pressed: 0
            }
+/

            import core.stdc.string : strlen;
            enum string commands = `
            import std.range : chunks;
            import core.stdc.string : strlen;
            int rv;
            // check whether auth is required for updating PrKDF and/or PuKDF
            ub2 ac =  AC_Update_PrKDF_PuKDF.get;
            assert(ac[0] == ac[1], "PrKDF and PuKDF shall have the same SCB: Either both always readable or protected by the same pin");
            assert(ac[0] != 0xFF); // PrKDF and PuKDF MUST BE updatable
            int       tries_left;
            int       pinLocal = 1;     // the default: to be changed in GetParamDialog
            int       pinReference = 1; // the default: to be changed in GetParamDialog
            char[32]  pin = '\0';       // TODO: how to protect against very long pin entries, exceeding 31 ?
            ubyte*    p_pinHex = cast(ubyte*)pin.ptr;
            if (ac[0] != 0) {
                rv = IupGetParam(toStringz("Pin requested for authorization (SCB "~toHexString!(Order.increasing,LetterCase.upper)([ubyte(ac[0])])~")"),
                    &param_action, null/* void* user_data*/, /*format*/
                    "&Pin local (User)? If local==No, then it's the Security Officer Pin:%b[No,Yes]\n" ~
                    "&Pin reference (1-31; selects the record# in pin file):%i\n" ~
                    "Pin (minLen: 4, maxLen: 8):%s\n", &pinLocal, &pinLocal, pin.ptr, null);
                size_t  pinLen = strlen(pin.ptr);
                if (rv != 1 || pinReference<1 || pinReference>31 || pinLen<4 || pinLen>8)
                    return IUP_DEFAULT;
//                assumeWontThrow(writeln("Value from IupGetParam: ", pin));
//                assumeWontThrow(writefln("Value from IupGetParam hex: %(%02X %)", p_pinHex[0..8]));
//                assumeWontThrow(writefln("Return button pressed: %s", rv));
            }

            foreach (ub2 fid; chunks(prkdf.data[8..8+prkdf.data[1]], 2))
                rv= acos5_64_short_select(card, null, fid, true);
            assert(rv==0);
            if (ac[0]) {
                rv = sc_verify(card, SC_AC.SC_AC_CHV, pinLocal? 0x80 | pinReference : pinReference, p_pinHex, 8, &tries_left);
                if (rv != SC_SUCCESS)
                    return IUP_DEFAULT;
            }
            rv = sc_update_binary(card, haystackPriv.front.posStart, bufPriv.ptr, bufPriv.length, 0);
            assert(rv==bufPriv.length);

            foreach (ub2 fid; chunks(pukdf.data[8..8+pukdf.data[1]], 2))
                rv= acos5_64_short_select(card, null, fid, true);
            assert(rv==0);
            // not required if opensc pin caching covers that ?
            if (ac[1]) {
                rv = sc_verify(card, SC_AC.SC_AC_CHV, pinLocal? 0x80 | pinReference : pinReference, p_pinHex, 8, &tries_left);
                if (rv != SC_SUCCESS)
                    return IUP_DEFAULT;
            }
            rv = sc_update_binary(card, haystackPubl.front.posStart, bufPubl.ptr, bufPubl.length, 0);
            assert(rv==bufPubl.length);
`;
            mixin(connect_card!commands);
            hstat.SetString(IUP_TITLE, "SUCCESS: Change some administrative (PKCS#15) data");
            return IUP_DEFAULT; // case "toggle_RSA_PrKDF_PuKDF_change"

        case "toggle_RSA_key_pair_generate":
            mixin(btn_RSA_cb_common1);
            enum string commands = `
            import std.range : chunks, chain;
            int rv;
            uba  lv_key_len_type_data = [0x02, cast(ubyte)(sizeNewRSAModulusBits.get/128), code(storeAsCRTRSAprivate.get, usageRSAprivateKeyACOS.get)];
            if (any(valuePublicExponent.get[0..8]) || ub82integral(valuePublicExponent.get[8..16])!=0x10001) {
                lv_key_len_type_data[0] = 0x12;
                lv_key_len_type_data ~= valuePublicExponent.get;
            }

//            auto scbs = chain(AC_Update_Delete_RSAprivateFile.get[], AC_Update_Delete_RSApublicFile.get[]).sort.uniq.array;
            ub2 scbs = [ubyte(AC_Update_Delete_RSAprivateFile.get[0]), ubyte(AC_Update_Delete_RSApublicFile.get[0])];

            // check whether auth is required for updating private key file or public key file
            assert(scbs[0] != 0xFF); // FIXME to strict
            assert(scbs[1] != 0xFF); // FIXME to strict
            int[2]       tries_left;
            int[2]       pinLocal = 1;
            int[2]       pinReference = 1;
            char[32][2]  pin;
            pin[0] = "\0";
            pin[1] = "\0";
            ubyte*[2]    p_pinHex;
            p_pinHex[0] = cast(ubyte*)(pin[0].ptr);
            p_pinHex[1] = cast(ubyte*)(pin[1].ptr);

            if (scbs[0] != 0) { // updating private key file needs auth
                rv = IupGetParam(toStringz("Pin requested for authorization (SCB "~toHexString!(Order.increasing,LetterCase.upper)([ubyte(scbs[0])])~")"),
                    &param_action, null/* void* user_data*/, /*format*/
                    "&Pin local (User)? If local==No, then it's the Security Officer Pin:%b[No,Yes]\n" ~
                    "&Pin reference (1-31; selects the record# in pin file):%i\n" ~
                    "Pin (minLen: 4, maxLen: 8):%s\n", &pinLocal[0], &pinReference[0], pin[0].ptr, null);
                if (rv != 1)
                    return IUP_DEFAULT;
                assumeWontThrow(writeln("Value from IupGetParam [0]: ", pin[0]));
                assumeWontThrow(writefln("Value from IupGetParam hex [0]: %(%02X %)", p_pinHex[0][0..8]));
                assumeWontThrow(writefln("Return button pressed [0]: %s", rv));
            }
            if (scbs[1] && scbs[1] != scbs[0]) { // updating public key file needs auth different from the private
                rv = IupGetParam(toStringz("Pin requested for authorization (SCB "~toHexString!(Order.increasing,LetterCase.upper)([ubyte(scbs[1])])~")"),
                    &param_action, null/* void* user_data*/, /*format*/
                    "&Pin local (User)? If local==No, then it's the Security Officer Pin:%b[No,Yes]\n" ~
                    "&Pin reference (1-31; selects the record# in pin file):%i\n" ~
                    "Pin (minLen: 4, maxLen: 8):%s\n", &pinLocal[1], &pinReference[1], pin[1].ptr, null);
                if (rv != 1)
                    return IUP_DEFAULT;
                assumeWontThrow(writeln("Value from IupGetParam [1]: ", pin[1]));
                assumeWontThrow(writefln("Value from IupGetParam hex [1]: %(%02X %)", p_pinHex[1][0..8]));
                assumeWontThrow(writefln("Return button pressed [1]: %s", rv));
            }
            {
                ub2 fid = integral2ub!2(fidRSADir.get)[0..2];
                rv= acos5_64_short_select(card, null, fid, true);
                assert(rv==0);
            }
            if (scbs[0]) {
                rv = sc_verify(card, SC_AC.SC_AC_CHV, pinLocal[0]? 0x80 | pinReference[0] : pinReference[0], p_pinHex[0], 8, &tries_left[0]);
                if (rv != SC_SUCCESS)
                    return IUP_DEFAULT;
            }
            if (scbs[1] && scbs[1] != scbs[0]) {
                rv = sc_verify(card, SC_AC.SC_AC_CHV, pinLocal[1]? 0x80 | pinReference[1] : pinReference[1], p_pinHex[1], 8, &tries_left[1]);
                if (rv != SC_SUCCESS)
                    return IUP_DEFAULT;
            }
            {
                sc_security_env  env = { SC_SEC_ENV_FILE_REF_PRESENT, SC_SEC_OPERATION.SC_SEC_OPERATION_GENERATE_RSAPRIVATE };
                env.file_ref.len = 2;
                env.file_ref.value[0..2] = integral2ub!2((fidRSAprivate.get)[0])[0..2];
                if ((rv= sc_set_security_env(card, &env, 0)) < 0) {
                    mixin (log!(__FUNCTION__, "sc_set_security_env failed for SC_SEC_OPERATION_GENERATE_RSAPRIVATE"));
                    return rv;
                }
            }
            {
                sc_security_env  env = { SC_SEC_ENV_FILE_REF_PRESENT, SC_SEC_OPERATION.SC_SEC_OPERATION_GENERATE_RSAPUBLIC };
                env.file_ref.len = 2;
                env.file_ref.value[0..2] = integral2ub!2((fidRSApublic.get)[0])[0..2];
                if ((rv= sc_set_security_env(card, &env, 0)) < 0) {
                    mixin (log!(__FUNCTION__, "sc_set_security_env failed for SC_SEC_OPERATION_GENERATE_RSAPUBLIC"));
                    return rv;
                }
            }

            if ((rv= cry_____7_4_4___46_generate_keypair_RSA(card, lv_key_len_type_data)) != SC_SUCCESS) {
                assumeWontThrow(writeln("  ### FAILED: Something went wrong with generate_keypair_RSA"));
                hstat.SetString(IUP_TITLE, "FAILURE: Generate new RSA key pair content");
                return IUP_DEFAULT;
            }

            // almost done, except updating PRKDF and PUKDF
            ub2 ac =  AC_Update_PrKDF_PuKDF.get;
            assert(ac[0] == ac[1], "PrKDF and PuKDF shall have the same SCB: Either both always readable or protected by the same pin");
            assert(ac[0] != 0xFF); // PrKDF and PuKDF MUST BE updatable
            assert(ac[0] == 0 || ac[0].among(scbs[0], scbs[1]));
            long k = countUntil(scbs[], ac[0]);

            foreach (ub2 fid; chunks(prkdf.data[8..8+prkdf.data[1]], 2))
                rv= acos5_64_short_select(card, null, fid, true);
            assert(rv==0);
            if (ac[0]) {
                rv = sc_verify(card, SC_AC.SC_AC_CHV, pinLocal[k]? 0x80 | pinReference[k] : pinReference[k], p_pinHex[k], 8, &tries_left[k]);
                if (rv != SC_SUCCESS)
                    return IUP_DEFAULT;
            }
            rv = sc_update_binary(card, haystackPriv.front.posStart, bufPriv.ptr, bufPriv.length, 0);
            assert(rv==bufPriv.length);

            foreach (ub2 fid; chunks(pukdf.data[8..8+pukdf.data[1]], 2))
                rv= acos5_64_short_select(card, null, fid, true);
            assert(rv==0);
            if (ac[1]) {
                rv = sc_verify(card, SC_AC.SC_AC_CHV, pinLocal[k]? 0x80 | pinReference[k] : pinReference[k], p_pinHex[k], 8, &tries_left[k]);
                if (rv != SC_SUCCESS)
                    return IUP_DEFAULT;
            }
            rv = sc_update_binary(card, haystackPubl.front.posStart, bufPubl.ptr, bufPubl.length, 0);
            assert(rv==bufPubl.length);
`;
            mixin (connect_card!commands);
            hstat.SetString(IUP_TITLE, "SUCCESS: Generate new RSA key pair content");
            return IUP_DEFAULT; // case "toggle_RSA_key_pair_generate"

        default:
    }
    return IUP_DEFAULT;
} // btn_RSA_cb


int param_action(Ihandle* param_box, int param_index, void* user_data)
{ // from html/examples/tests/getparam.c
    printf("param_action(%d, %p)\n", param_index, user_data);
    switch (param_index)
    {
    case IUP_GETPARAM_MAP:
        printf("Map\n");
        break;
    case IUP_GETPARAM_CLOSE:
        printf("IupGetParam - Close\n");
        break;
    case IUP_GETPARAM_BUTTON1:
        printf("IupGetParam - Button1 (OK)\n");
        break;
    case IUP_GETPARAM_INIT:
        printf("Init\n");
        break;
    case IUP_GETPARAM_BUTTON2:
        printf("IupGetParam - Button2 (Cancel)\n");
        break;
    case IUP_GETPARAM_BUTTON3:
        printf("IupGetParam - Button3 (Help)\n");
        break;
    default:
        {
            Ihandle* param = cast(Ihandle*) IupGetAttributeId(param_box, "PARAM", param_index);
            printf("PARAM%d = %s\n", param_index, IupGetAttribute(param, "VALUE"));
            break;
        }
    }
    return 1;
}

/*
int btn_RSA_checkPRKDF_PUKDF_cb(Ihandle* ih)
{
    assumeWontThrow(writeln);
    foreach (i, elem; PRKDF)
        assumeWontThrow(writefln("PRKDF[%s]: %s", i, elem));
    assumeWontThrow(writeln);
    foreach (i, elem; PUKDF)
        assumeWontThrow(writefln("PUKDF[%s]: %s", i, elem));
    assumeWontThrow(writeln);
    return IUP_DEFAULT;
} // btn_RSA_checkPRKDF_PUKDF_cb
*/

} //extern(C) nothrow
