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
//import std.ascii : isHexDigit;
//import std.digest; // : toHexString;
import std.typecons : Tuple, tuple;
import std.string : /*chomp, */  toStringz, fromStringz, representation;

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

import util_opensc : lh, card, acos5_64_short_select, readFile, decompose, PKCS15Path_FileType, pkcs15_names,
    PKCS15_FILE_TYPE, fs, sitTypeFS, PRKDF, PUKDF, AODF, cry_____7_4_4___46_generate_keypair_RSA,
    util_connect_card, connect_card, PKCS15_ObjectTyp, errorDescription, PKCS15, iter_begin, appdf, prkdf, pukdf, tnTypePtr,
    /*populate_tree_fs,*/ itTypeFS, aid, cm_7_3_1_14_get_card_info, is_ACOSV3_opmodeV3_FIPS_140_2L3, is_ACOSV3_opmodeV3_FIPS_140_2L3_active,
    my_pkcs15init_callbacks, tlv_Range_mod, file_type;

//import asn1_pkcs15 : CIO_RSA_private, CIO_RSA_public, CIO_Auth_Pin, encodeEntry_PKCS15_PRKDF, encodeEntry_PKCS15_PUKDF;
import libtasn1;
import pkcs11;


// tag types
struct _modulusBitsRSA{}
struct _storeAsCRTRSAprivate{}    // modeCRTkeygenRSAprivate
struct _usageRSAprivateKeyACOS{}  // usageKeygenRSAprivate
struct _usageRSAprivateKeyPrKDF{} // usagePrKDF_RSAprivate
//Obs
struct _usageRSApublicKeyPuKDF{}  // usagePuKDF_RSApublic
struct _sizeNewRSAprivateFile{}
struct _sizeNewRSApublicFile{}

struct _keyPairId{}
struct _keyPairLabel{}
struct _keyPairModifiable{}
struct _fidRSADir{}
struct _fidRSAprivate{}
struct _fidRSApublic{}

struct _valuePublicExponent{}   // publicExponentRSA
struct _authIdRSAprivate{}

struct _AC_Update_PrKDF_PuKDF{}            //SCB
struct _AC_Update_Delete_RSAprivateFile{}
struct _AC_Update_Delete_RSApublicFile{}
struct _AC_Delete_Create_RSADir{}


bool isNewKeyPairId;


enum /* matrixRowName */ {
    r_keyPairId = 1,
      r_keyPairModifiable,
      r_usageRSAprivateKeyPrKDF,
//    r_usageRSApublicKeyPuKDF,    hidden
      r_keyPairLabel,
      r_authIdRSAprivate,

      r_modulusBitsRSA,
      r_valuePublicExponent,

    r_acos_internal,
    r_storeAsCRTRSAprivate,
    r_usageRSAprivateKeyACOS,

    r_fidRSAprivate,
    r_fidRSApublic,
    r_fidRSADir,

    r_change_calcPrKDF,
    r_change_calcPuKDF,

    r_sizeNewRSAprivateFile,
    r_sizeNewRSApublicFile,


    r_statusInput,
    r_AC_Update_PrKDF_PuKDF,

    r_AC_Update_Delete_RSAprivateFile,
    r_AC_Update_Delete_RSApublicFile,
    r_AC_Delete_Create_RSADir,
}

/*
"toggle_RSA_PrKDF_PuKDF_change"
"toggle_RSA_key_pair_delete"
"toggle_RSA_key_pair_regenerate"
"toggle_RSA_key_pair_create_and_generate"
"toggle_RSA_key_pair_try_sign"
*/

/* modulusBitsRSA : from 512 to 4096, step 256, except for FIPS: 2048 and 3072 only (not yet enforced !)
Modifying modulusBitsRSA depends on radio_RSA, comprising:
"toggle_RSA_PrKDF_PuKDF_change"
"toggle_RSA_key_pair_delete"
"toggle_RSA_key_pair_regenerate"
"toggle_RSA_key_pair_create_and_generate"
"toggle_RSA_key_pair_try_sign"

 */
Pub!_modulusBitsRSA          modulusBitsRSA;
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
Pub!_authIdRSAprivate        authIdRSAprivate;

Obs_statusInput              statusInput;

Pub!(_AC_Update_PrKDF_PuKDF,          ubyte[2])  AC_Update_PrKDF_PuKDF;
Pub!(_AC_Update_Delete_RSAprivateFile,ubyte[2])  AC_Update_Delete_RSAprivateFile;
Pub!(_AC_Update_Delete_RSApublicFile, ubyte[2])  AC_Update_Delete_RSApublicFile;
Pub!(_AC_Delete_Create_RSADir,        ubyte[2])  AC_Delete_Create_RSADir;

void initialize_PubObs_generateKeyPair_RSA() {
    /* initialze the publisher/observer system for GenerateKeyPair_RSA_tab */
    // some variables are declared as publisher though they don't need to be, currently just for consistency, but that's not the most efficient way
    keyPairLabel            = new Pub!(_keyPairLabel,string)  (r_keyPairLabel,            AA["matrixRsaAttributes"]);
    modulusBitsRSA          = new Pub!_modulusBitsRSA         (r_modulusBitsRSA,          AA["matrixRsaAttributes"]);
    storeAsCRTRSAprivate    = new Pub!_storeAsCRTRSAprivate   (r_storeAsCRTRSAprivate,    AA["matrixRsaAttributes"]);
    usageRSAprivateKeyACOS  = new Pub!_usageRSAprivateKeyACOS (r_usageRSAprivateKeyACOS,  AA["matrixRsaAttributes"]);
    usageRSAprivateKeyPrKDF = new Pub!_usageRSAprivateKeyPrKDF(r_usageRSAprivateKeyPrKDF, AA["matrixRsaAttributes"]);
    keyPairModifiable       = new Pub!_keyPairModifiable      (r_keyPairModifiable,       AA["matrixRsaAttributes"]);
    authIdRSAprivate        = new Pub!_authIdRSAprivate       (r_authIdRSAprivate,    AA["matrixRsaAttributes"], true);
    keyPairId               = new Pub!_keyPairId              (r_keyPairId,               AA["matrixRsaAttributes"], true);
    fidRSADir               = new Pub!_fidRSADir              (r_fidRSADir,               AA["matrixRsaAttributes"], true);
    fidRSAprivate           = new PubA2!_fidRSAprivate        (r_fidRSAprivate,           AA["matrixRsaAttributes"]);
    fidRSApublic            = new PubA2!_fidRSApublic         (r_fidRSApublic,            AA["matrixRsaAttributes"]);
    valuePublicExponent     = new PubA16!_valuePublicExponent (r_valuePublicExponent,     AA["matrixRsaAttributes"]);
    AC_Update_PrKDF_PuKDF           = new Pub!(_AC_Update_PrKDF_PuKDF,ubyte[2])           (r_AC_Update_PrKDF_PuKDF,           AA["matrixRsaAttributes"]);
    AC_Update_Delete_RSAprivateFile = new Pub!(_AC_Update_Delete_RSAprivateFile,ubyte[2]) (r_AC_Update_Delete_RSAprivateFile, AA["matrixRsaAttributes"]);
    AC_Update_Delete_RSApublicFile  = new Pub!(_AC_Update_Delete_RSApublicFile, ubyte[2]) (r_AC_Update_Delete_RSApublicFile,  AA["matrixRsaAttributes"]);
    AC_Delete_Create_RSADir         = new Pub!(_AC_Delete_Create_RSADir,        ubyte[2]) (r_AC_Delete_Create_RSADir,         AA["matrixRsaAttributes"]);

    usageRSApublicKeyPuKDF  = new Obs_usageRSApublicKeyPuKDF  (0/*r_usageRSApublicKeyPuKDF,  AA["matrixRsaAttributes"]*/); // visual representation removed
    sizeNewRSAprivateFile   = new Obs_sizeNewRSAprivateFile   (r_sizeNewRSAprivateFile,   AA["matrixRsaAttributes"]);
    sizeNewRSApublicFile    = new Obs_sizeNewRSApublicFile    (r_sizeNewRSApublicFile,    AA["matrixRsaAttributes"]);
    statusInput             = new Obs_statusInput             (r_statusInput,             AA["matrixRsaAttributes"]);
    change_calcPrKDF        = new Obs_change_calcPrKDF        (r_change_calcPrKDF,        AA["matrixRsaAttributes"]);
    change_calcPuKDF        = new Obs_change_calcPuKDF        (r_change_calcPuKDF,        AA["matrixRsaAttributes"]);
//// dependencies
    fidRSAprivate          .connect(&sizeNewRSAprivateFile.watch); // just for show (sizeCurrentRSAprivateFile) reason
    modulusBitsRSA         .connect(&sizeNewRSAprivateFile.watch);
    storeAsCRTRSAprivate   .connect(&sizeNewRSAprivateFile.watch);

    fidRSApublic           .connect(&sizeNewRSApublicFile.watch);  // just for show (sizeCurrentRSApublicFile) reason
    modulusBitsRSA         .connect(&sizeNewRSApublicFile.watch);

    usageRSAprivateKeyPrKDF.connect(&usageRSApublicKeyPuKDF.watch);

    keyPairId              .connect(&change_calcPrKDF.watch); // THIS MUST BE the first entry for change_calcPrKDF ! If no keyPairId is selected, this MUST be the only one accessible
    keyPairLabel           .connect(&change_calcPrKDF.watch);
    authIdRSAprivate       .connect(&change_calcPrKDF.watch);
    keyPairModifiable      .connect(&change_calcPrKDF.watch);
    modulusBitsRSA         .connect(&change_calcPrKDF.watch);
    usageRSAprivateKeyPrKDF.connect(&change_calcPrKDF.watch);
//  fidRSAprivate          .connect(&change_calcPrKDF.watch);

    keyPairId              .connect(&change_calcPuKDF.watch); // THIS MUST BE the first entry for change_calcPuKDF ! If no keyPairId is selected, this MUST be the only one accessible
    keyPairLabel           .connect(&change_calcPuKDF.watch);
//  authIdRSApublicFile    .connect(&change_calcPuKDF.watch);
    keyPairModifiable      .connect(&change_calcPuKDF.watch);
    modulusBitsRSA         .connect(&change_calcPuKDF.watch);
    usageRSApublicKeyPuKDF .connect(&change_calcPuKDF.watch);
//  fidRSApublic           .connect(&change_calcPuKDF.watch);

    fidRSADir              .connect(&statusInput.watch);
    fidRSAprivate          .connect(&statusInput.watch);
    fidRSApublic           .connect(&statusInput.watch);
    valuePublicExponent    .connect(&statusInput.watch);
    usageRSAprivateKeyPrKDF.connect(&statusInput.watch);
    usageRSAprivateKeyACOS .connect(&statusInput.watch);
    sizeNewRSAprivateFile  .connect(&statusInput.watch);
    sizeNewRSApublicFile   .connect(&statusInput.watch);

//// values to start with
    fidRSADir              .set(appdf is null? 0 : ub22integral(appdf.data[2..4]), true);
    storeAsCRTRSAprivate   .set(true, true);
    usageRSAprivateKeyACOS .set(4,   true); // this is only for acos-generation; no variable depends on this
    AC_Update_PrKDF_PuKDF  .set([prkdf is null? 0xFF : prkdf.data[25], pukdf is null? 0xFF : pukdf.data[25]], true); // no variable depends on this
    AC_Delete_Create_RSADir.set([appdf is null? 0xFF : appdf.data[24], appdf is null? 0xFF : appdf.data[25]], true); // no variable depends on this
    toggle_RSA_cb(AA["toggle_RSA_PrKDF_PuKDF_change"].GetHandle, 1); // was set to active already
//    AA["radio_RSA"].SetAttribute("VALUE_HANDLE", "toggle_RSA_PrKDF_PuKDF_change"); // doesn't work: "Changes the active toggle"
//    AA["toggle_RSA_PrKDF_PuKDF_change"].SetIntegerVALUE(1); // Doesn't invoke toggle_RSA_cb
}

enum string commonConstructor =`
    this(int lin/*, int col*/, Handle control = null) {
        _lin = lin;
        _col = 1;
        _h   = control;
    }
`;

mixin template Pub_boilerplate(T,V)
{
    @property V get() const @nogc nothrow /*pure*/ @safe { return _value; }

    void emit_self() nothrow {
        try
            emit(T.stringof, _value);
        catch (Exception e) { printf("### Exception in emit_self()"); /* todo: handle exception */ }
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
    this(int lin/*, int col*/, Handle control = null, bool hexRep = false) {
        _lin = lin;
        _col = 1;
        _h   = control;
        _hexRep = hexRep;
/*
Store    the class object reference to   an attribure (in the constructor)
                if (_h !is null)
                    _h.SetAttributeStr(T.stringof, cast(char*)this);

Retrieve the class object reference from an attribure (where it will be used)  What was the benefit of that? Look for the project where it was used
                Handle h = createHandle(ih / * Ihandle* interfaceElement * /);
                char* cptr;
                if ((cptr = h.GetAttributeStr("_fidRSADir")) != null) {
                    auto obj  = cast(Pub!_fidRSADir) cptr;
                    assert(obj !is null);
                    obj.set = cast(int) strtol(h.GetAttributeVALUE, null, 16);
                }
*/
    }

    @property V set(V v, bool programmatically=false)  nothrow {
        try {
            _value = v;
////assumeWontThrow(writefln(T.stringof~" object was set to value %s", _value));
            static if (is(T==_usageRSAprivateKeyACOS) || is(T==_usageRSAprivateKeyPrKDF) /*|| is(T==_usageRSApublicKeyPuKDF)*/) {
                if (_h !is null) {
//assumeWontThrow(writefln(T.stringof~" object was set to value %s and translate int", _value));
                    _h.SetStringId2 ("", _lin, _col, keyUsageFlagsInt2string(_value));
                }
            }
            else static if (is(T==_keyPairLabel)) {
                if (programmatically && _h !is null) {
//assumeWontThrow(writefln(T.stringof~" object was set to value %s and translate int", _value));
                    _h.SetStringId2 ("", _lin, _col, _value);
                }
            }
            else static if (is(T==_AC_Update_PrKDF_PuKDF) || is(T==_AC_Delete_Create_RSADir) ||
                is(T==_AC_Update_Delete_RSAprivateFile) || is(T==_AC_Update_Delete_RSApublicFile)) {
                if (programmatically && _h !is null) {
                    _h.SetStringId2 ("", _lin, _col, format!"%02X"(_value[0])  ~" / "~format!"%02X"(_value[1]));
                }
            }
            else {
                if (programmatically &&  _h !is null)
                    _h.SetStringId2 ("", _lin, _col, _hexRep? format!"%X"(_value) : _value.to!string);
            }
            emit(T.stringof, _value);
            /* this is critical for _keyPairId:
             * First change_calcPrKDF.watch and change_calcPuKDF.watch must run: They create/dup structure to structure_new
             * only then: set_more_for_keyPairId */
            static if (is (T == _keyPairId))
                set_more_for_keyPairId(_value);
        }
        catch (Exception e) { printf("### Exception in Pub.set()"); /* todo: handle exception */ }
        return _value;
    }

    mixin Pub_boilerplate!(T,V);
}

class PubA2(T, V=int)
{
    mixin(commonConstructor);

/*
V[2] mapping:
 0: fid
 1: fid_size

 if locate fid within appDF fails, set both to zero

 accepts a new fid from v[0] only, if acceptable
 and depending on that, retrieves the file's size into v[1];

 usable for both fidRSAprivate and fidRSApublic
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
                if (isNewKeyPairId)
                    _value = [v[0],0];
                else
                    _value = [0,0];
                programmatically = true;
                goto end;
            }

            size_or_MRL_NOR = privORpub.data[4..6];
            t = decompose(cast(EFDB) privORpub.data[0], size_or_MRL_NOR);
            v[1] = t[0];
            _value = v;
end:
////assumeWontThrow(writefln(T.stringof~" object was set to values %04X, %s", _value[0], _value[1]));
            if (programmatically &&  _h !is null)
                _h.SetStringId2 ("", _lin, _col, format!"%4X"(_value[0]));
            emit(T.stringof, _value);
            }
            return;
        }
        catch (Exception e) { printf("### Exception in PubA2.set()"); /* todo: handle exception */ }
assumeWontThrow(writefln(T.stringof~"### object was set (without emit) to values %04X, %s", _value[0], _value[1]));
    }

    mixin Pub_boilerplate!(T,V[2]);
}

class PubA16(T, V=ubyte)
{
    mixin(commonConstructor);

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
            if (programmatically &&  _h !is null) {
                // trim leading zero bytes
                ptrdiff_t  pos = clamp(_value[].countUntil!"a>0", -1,15);
                _h.SetStringId2 ("", _lin, _col, format!"%(%02X%)"(pos==-1? [ubyte(0)] : _value[pos..$]));
            }
            emit(T.stringof, _value);
        }
        catch (Exception e) { printf("### Exception in PubA16.set()"); /* todo: handle exception */ }
////assumeWontThrow(writefln(T.stringof~" object (was set to) values %(%02X %)", _value));
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

class Obs_usageRSApublicKeyPuKDF {
    mixin(commonConstructor);

    void watch(string msg, int v) {
        switch(msg) {
            case "_usageRSAprivateKeyPrKDF":
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
        emit("_usageRSApublicKeyPuKDF", _value);

        if (_h !is null) {
            _h.SetStringId2 ("", _lin, _col, keyUsageFlagsInt2string(_value));
            _h.Update;
        }
    }

    mixin Pub_boilerplate!(_usageRSApublicKeyPuKDF, int);
}

class Obs_sizeNewRSAprivateFile {
    mixin(commonConstructor);

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
            case "_modulusBitsRSA":
                _modulusBitsRSA = v;
                break;
            case "_storeAsCRTRSAprivate":
                _storeAsCRTRSAprivate = v;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        _value =  _modulusBitsRSA<=0? 0 : 5 + _modulusBitsRSA/16*(_storeAsCRTRSAprivate ? 5 : 2);
        present();
    }

    void present()
    {
        emit("_sizeNewRSAprivateFile", _value);
////assumeWontThrow(writefln(typeof(this).stringof~" object was set to _fidRSAprivate(%04X), _fidSizeRSAprivate(%s), _value(%s)", _fidRSAprivate, _fidSizeRSAprivate, _value));

        if (_h !is null) {
            _h.SetStringId2 ("", _lin, _col, _value.to!string ~" / "~ _fidSizeRSAprivate.to!string);
            _h.Update;
        }
    }

    mixin Pub_boilerplate!(_sizeNewRSAprivateFile, int);

    private :
        int  _fidRSAprivate;
        int  _fidSizeRSAprivate;
        int  _modulusBitsRSA;
        int  _storeAsCRTRSAprivate;
//      int  _value; // size of RSAprivate file required for the _modulusBitsRSA and _storeAsCRTRSAprivate settings
} // class Obs_sizeNewRSAprivateFile

class Obs_sizeNewRSApublicFile {
    mixin(commonConstructor);

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
            case "_modulusBitsRSA":
//                _modulusBitsRSA = v;
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
        emit("_sizeNewRSApublicFile", _value);
////assumeWontThrow(writefln(typeof(this).stringof~" object was set to _fidRSApublic(%04X), _fidSizeRSApublic(%s), _value(%s)", _fidRSApublic, _fidSizeRSApublic, _value));

        if (_h !is null) {
            _h.SetStringId2 ("", _lin, _col, _value.to!string ~" / "~ _fidSizeRSApublic.to!string);
            _h.Update;
        }
    }

    mixin Pub_boilerplate!(_sizeNewRSApublicFile, int);

    private :
        int  _fidRSApublic;
        int  _fidSizeRSApublic;
//      int   _value; // size of RSApublic file required for the _modulusBitsRSA setting
} // class Obs_sizeNewRSApublicFile


class Obs_change_calcPrKDF {
    mixin(commonConstructor);

    @property ref PKCS15_ObjectTyp  pkcs15_ObjectTyp() @nogc nothrow /*pure*/ @safe { return _PrKDFentry; }
    @property     const(int)        get()        const @nogc nothrow /*pure*/ @safe { return _value; }

    void watch(string msg, int v) {
        import core.bitop : bitswap;
        int asn1_result;
        int outLen;
        switch (msg) {
            case "_keyPairId":
                {
                    if (_PrKDFentry.structure_new !is null)
                        asn1_delete_structure(&_PrKDFentry.structure_new);
                    if (isNewKeyPairId) {
                        _PrKDFentry = PKCS15_ObjectTyp.init;
//30 2F 30 0A 0C 01 3F 03 02 06   C0 04 01 01 30 0F 04 01 FF 03   03 06 20 00 03 02 03 B8 02 01   FF A1 10 30 0E 30 08 04 06 3F   00 41 00 41 FF 02 02 10 00
                        _PrKDFentry.der = (cast(immutable(ubyte)[])hexString!"30 2F 30 0A 0C 01 3F 03 02 06 C0 04 01 01 30 0F 04 01 FF 03 03 06 20 00 03 02 03 B8 02 01 FF A1 10 30 0E 30 08 04 06 3F 00 41 00 41 FF 02 02 10 00").dup;
                        _PrKDFentry.der[18] = cast(ubyte)v;
                        _PrKDFentry.der[30] = cast(ubyte)v;
                        _PrKDFentry.der[44] = 0xF0 | cast(ubyte)v;
                        asn1_result = asn1_create_element(PKCS15, pkcs15_names[PKCS15_FILE_TYPE.PKCS15_PRKDF][1], &_PrKDFentry.structure); // "PKCS15.PrivateKeyType"
                        if (asn1_result != ASN1_SUCCESS) {
                            assumeWontThrow(writeln("### Structure creation: ", asn1_strerror2(asn1_result)));
                            exit(1);
                        }
                        asn1_result = asn1_der_decoding(&_PrKDFentry.structure, _PrKDFentry.der, errorDescription);
                        if (asn1_result != ASN1_SUCCESS) {
                            assumeWontThrow(writeln("### asn1Decoding: ", errorDescription));
                            exit(1);
                        }
                        ubyte[16]  str; // verify, that a value for "privateRSAKey.privateRSAKeyAttributes.value.indirect.path.path" does exist for this keyPairId
                        if ((asn1_result= asn1_read_value(_PrKDFentry.structure, pkcs15_names[PKCS15_FILE_TYPE.PKCS15_RSAPrivateKey][2], str, outLen)) != ASN1_SUCCESS) {
                            assumeWontThrow(writefln("### asn1_read_value: %(%02X %)", _PrKDFentry.der));
                            exit(1);
                        }
                        assert(v == getIdentifier(_PrKDFentry, "privateRSAKey.commonKeyAttributes.iD"));
                    }
                    else {
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

            case "_authIdRSAprivate":
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
//                assert(outLen==2); // bits
                flags[0] = util_general.bitswap(flags[0]);

                ubyte[1] tmp = util_general.bitswap( cast(ubyte) ((flags[0]&0xFD) | (v!=0)*2) );
                asn1_write_value(_PrKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.flags", tmp.ptr, 2); // 2 bits
                break;

            case "_modulusBitsRSA":
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
//        assert(_PrKDFentry.posEnd); // it has been set
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
////assumeWontThrow(writefln(typeof(this).stringof~" object was set"));
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
    mixin(commonConstructor);

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
                    if (_PuKDFentry.structure_new !is null)
                        asn1_delete_structure(&_PuKDFentry.structure_new);
                    if (isNewKeyPairId) {
                        _PuKDFentry = PKCS15_ObjectTyp.init;
//30 2F 30 0A 0C 01 3F 03 02 06   C0 04 01 01 30 0F 04 01 FF 03   03 06 20 00 03 02 03 B8 02 01   FF A1 10 30 0E 30 08 04 06 3F   00 41 00 41 FF 02 02 10 00
//30 2C 30 07 0C 01 3F 03 02 06   40          30 0F 04 01 FF 03   03 06 02 00 03 02 03 48 02 01   FF A1 10 30 0E 30 08 04 06 3F   00 41 00 41 FF 02 02 10 00
                        _PuKDFentry.der = (cast(immutable(ubyte)[])hexString!"30 2C 30 07 0C 01 3F 03 02 06 40 30 0F 04 01 FF 03 03 06 02 00 03 02 03 48 02 01 FF A1 10 30 0E 30 08 04 06 3F 00 41 00 41 FF 02 02 10 00").dup;
                        _PuKDFentry.der[15] = cast(ubyte)v;
                        _PuKDFentry.der[27] = cast(ubyte)v;
                        _PuKDFentry.der[41] = 0x30 | cast(ubyte)v;
                        asn1_result = asn1_create_element(PKCS15, pkcs15_names[PKCS15_FILE_TYPE.PKCS15_PUKDF][1], &_PuKDFentry.structure); // "PKCS15.PublicKeyType"
                        if (asn1_result != ASN1_SUCCESS) {
                            assumeWontThrow(writeln("### Structure creation: ", asn1_strerror2(asn1_result)));
                            exit(1);
                        }
                        asn1_result = asn1_der_decoding(&_PuKDFentry.structure, _PuKDFentry.der, errorDescription);
                        if (asn1_result != ASN1_SUCCESS) {
                            assumeWontThrow(writeln("### asn1Decoding: ", errorDescription));
                            exit(1);
                        }
                        ubyte[16]  str; // verify, that a value for "publicRSAKey.publicRSAKeyAttributes.value.indirect.path.path" does exist for this keyPairId
                        if ((asn1_result= asn1_read_value(_PuKDFentry.structure, pkcs15_names[PKCS15_FILE_TYPE.PKCS15_RSAPublicKey][2], str, outLen)) != ASN1_SUCCESS) {
                            assumeWontThrow(writefln("### asn1_read_value: %(%02X %)", _PuKDFentry.der));
                            exit(1);
                        }
                        assert(v == getIdentifier(_PuKDFentry, "publicRSAKey.commonKeyAttributes.iD"));
                    }
                    else {
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

            case "_modulusBitsRSA":
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
//        assert(_PuKDFentry.posEnd); // it has been set
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
////assumeWontThrow(writefln(typeof(this).stringof~" object was set"));
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
    mixin(commonConstructor);

  @property bool[9] get() const /*@nogc*/ nothrow /*pure*/ /*@safe*/ { return _value; }

//    @property bool[4] val() const @nogc nothrow /*pure*/ @safe { return _value; }

    void watch(string msg, int[2] v) {
        switch(msg) {
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
    void watch(string msg, int v) {
        switch(msg) {
            case "_fidRSADir":
                _value[1] = v>0;
                break;
            case "_usageRSAprivateKeyPrKDF":
                _usageRSAprivateKeyPrKDF = v;
                _value[6] = (v&2 && !(_usageRSAprivateKeyACOS&2))  || (v&4 && !(_usageRSAprivateKeyACOS&4))?  false : true;
                break;
            case "_usageRSAprivateKeyACOS":
                _usageRSAprivateKeyACOS = v;
                _value[6] = (_usageRSAprivateKeyPrKDF&2 && !(v&2)) || (_usageRSAprivateKeyPrKDF&4 && !(v&4))? false : true;
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
    void watch(string msg, ubyte[16] v) {
        switch(msg) {
            case "_valuePublicExponent":
                _value[5] = ub82integral(v[0..8])>0 || ub82integral(v[8..16])>0;
                break;
            default:
                writeln(msg); stdout.flush();
                assert(0, "Unknown observation");
        }
        calculate();
    }

    void calculate() {
        string activeToggle = AA["radio_RSA"].GetStringVALUE();
        _value[0] = all( indexed(_value[],
                        activeToggle.among("toggle_RSA_PrKDF_PuKDF_change", "toggle_RSA_key_pair_delete")?  [1,2,3,4]     :
                        activeToggle.among("toggle_RSA_key_pair_regenerate")?                               [1,2,3,4,5,6,7,8] :
                        activeToggle.among("toggle_RSA_key_pair_create_and_generate")?                      [1,    4,5,6] :
                                                                                                            [1,2,3,4,5] ));
//        emit("_statusInput", _value);
////assumeWontThrow(writefln(typeof(this).stringof~" object was set to values %(%s %)", _value));

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

//    mixin Signal!(string, bool[6]);

    private :
        int  _fidSizeRSAprivate;
        int  _fidSizeRSApublic;
        int  _sizeNewRSAprivateFile;
        int  _sizeNewRSApublicFile;
        int  _usageRSAprivateKeyPrKDF;
        int  _usageRSAprivateKeyACOS;

/*
    sizeNewRSAprivateFile  .connect(&statusInput.watch);
    sizeNewRSApublicFile   .connect(&statusInput.watch);
bool[ ] mapping:
 0==true: overall okay;
 1==true: appdf !is null, i.e. appDir exists
 2==true: fidRSAprivate exists and is below appDir in same directory as fidRSApublic
 3==true: fidRSApublic  exists and is below appDir in same directory as fidRSAprivate
 4==true: fidRSAprivate and fidRSApublic are a key pair with common key id; may also read priv file from pub in order to verify
 5==true: valuePublicExponent is a prime
 6==true: usageRSAprivateKeyPrKDF and usageRSAprivateKeyACOS don't conflict (only for "toggle_RSA_key_pair_regenerate"/"toggle_RSA_key_pair_create_and_generate")
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

int getIdentifier(const ref PKCS15_ObjectTyp ot, string nodeName, bool new_=false) nothrow {
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


/* ATTENTION: this must be synchronous how opensc generates new ones from profile acos5_64.profile
currently the template defines for
EF public-key:  starting from file-id = 4131
EF private-key: starting from file-id = 41F1
The last nibble is common for a keypair and taken as keyPairId (1 byte)
Operating with a 1 byte is NOT CONFORMANT to the standard, that's just how it is currently

The topic RSA Keypair file id must be reviewed as well: There are some hardcoded restrictions/conventions/rules, in the driver as well

*/
int nextUniqueKeyPairId() nothrow {
    int[] keyPairIdAllowedRange = iota(1,16).array;
    foreach (ref elem; PRKDF) {
        int id = getIdentifier(elem, "privateRSAKey.commonKeyAttributes.iD");
        keyPairIdAllowedRange = find!((a,b) => a == b)(keyPairIdAllowedRange, id); // remove any id smaller than id found
        if (keyPairIdAllowedRange.length)
            keyPairIdAllowedRange = keyPairIdAllowedRange[1..$]; // remove id found
    }
//    int result = keyPairIdAllowedRange.empty? -1 : keyPairIdAllowedRange.front;
//assumeWontThrow(writeln("nextUniqueKeyPairId: ", result));
    return keyPairIdAllowedRange.empty? -1 : keyPairIdAllowedRange.front;//result;
}

void populate_info_from_getResponse(ref ub32 info, /*const*/ ubyte[MAX_FCI_GET_RESPONSE_LEN] rbuf)  nothrow {
//    assumeWontThrow(writefln("%(%02X %)     %(%02X %)", info, rbuf));
    ubyte len = rbuf[1];
    foreach (d,T,L,V; tlv_Range_mod(rbuf[2..2+len])) {
        if      (T == ISO7816_TAG_FCP_.ISO7816_TAG_FCP_SIZE)
            info[4..6]/*fileSize*/ = V[0..2];
        else if (T == ISO7816_TAG_FCP_.ISO7816_TAG_FCP_TYPE) {
            info[0]/*FDB*/ = V[0];
            if (iEF_FDB_to_structure(cast(EFDB)V[0])&6  &&  L.among(5,6)) { // then it's a record-based fdb
                info[4]/*MRL*/ = V[3];
                info[5]/*NOR*/ = V[L-1];
            }
        }
        else if (T == ISO7816_TAG_FCP_.ISO7816_TAG_FCP_FID)
            info[2..4]/*fid*/ = V[0..2];
        else if (T == ISO7816_TAG_FCP_.ISO7816_TAG_FCP_LCS)
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
}


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

    string activeToggle = AA["radio_RSA"].GetStringVALUE();
//assumeWontThrow(writefln("activeToggle: %s", activeToggle));
////    printf("set_more_for_keyPairId (%d)\n", keyPairId);

    int  asn1_result;
    int  outLen;
    PKCS15_ObjectTyp  PrKDFentry, PuKDFentry;

    assert(keyPairId > 0);

    PrKDFentry = change_calcPrKDF.pkcs15_ObjectTyp;
    PuKDFentry = change_calcPuKDF.pkcs15_ObjectTyp;

    ubyte[1] flags; // optional
    asn1_result = asn1_read_value(PrKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.flags", flags, outLen);
    if (asn1_result != ASN1_SUCCESS)
        assumeWontThrow(writeln("### asn1_read_value privateRSAKey.commonObjectAttributes.flags: ", asn1_strerror2(asn1_result)));
    else {
//        assert(outLen==2); // bits
        flags[0] = util_general.bitswap(flags[0]);

        keyPairModifiable.set((flags[0]&2)/2, true);

        if (!keyPairModifiable.get &&  activeToggle.among("toggle_RSA_key_pair_delete", "toggle_RSA_key_pair_regenerate") ) {
            IupMessage("Feedback upon setting keyPairId",
"The PrKDF entry for the selected keyPairId disallows modifying the RSA private key !\nThe toggle will be changed to toggle_RSA_PrKDF_PuKDF_change toggled");
            AA["toggle_RSA_PrKDF_PuKDF_change"].SetIntegerVALUE(1);
            toggle_RSA_cb(AA["toggle_RSA_PrKDF_PuKDF_change"].GetHandle, 1);
        }
    }
    ubyte[1] authId; // optional
    asn1_result = asn1_read_value(PrKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.authId", authId, outLen);
    if (asn1_result != ASN1_SUCCESS) {
        assumeWontThrow(writeln("### asn1_read_value privateRSAKey.commonObjectAttributes.authId: ", asn1_strerror2(asn1_result)));
    }
    else {
        assert(outLen==1);
        if (authId[0])
            assert(flags[0]&1); // may run into a problem if asn1_read_value for flags failed
        authIdRSAprivate.set(authId[0], true);
    }


    { // make label inaccessible when leaving the scope
        char[] label = new char[65]; // optional
        label[0..65] = '\0';
        asn1_result = asn1_read_value(PrKDFentry.structure_new, "privateRSAKey.commonObjectAttributes.label", label, outLen);
        if (asn1_result != ASN1_SUCCESS) {
            assumeWontThrow(writeln("### asn1_read_value privateRSAKey.commonObjectAttributes.label: ", asn1_strerror2(asn1_result)));
        }
        else
            keyPairLabel.set(assumeUnique(label[0..outLen]), true);
    }

    ubyte[2] keyUsageFlags; // non-optional
    asn1_result = asn1_read_value(PrKDFentry.structure_new, "privateRSAKey.commonKeyAttributes.usage", keyUsageFlags, outLen);
    if (asn1_result != ASN1_SUCCESS)
        assumeWontThrow(writeln("### asn1_read_value privateRSAKey.commonKeyAttributes.usage: ", asn1_strerror2(asn1_result)));
    else {
//        assert(outLen==10); // bits
//assumeWontThrow(writefln("keyUsageFlags: %(%02X %)", keyUsageFlags));
        usageRSAprivateKeyPrKDF.set( bitswap(ub22integral(keyUsageFlags)<<16), true);
    }

//        with (PrKDFentry.privateRSAKeyAttributes) {

    ubyte[2] modulusLength; // non-optional
    asn1_result = asn1_read_value(PrKDFentry.structure_new, "privateRSAKey.privateRSAKeyAttributes.modulusLength", modulusLength, outLen);
    if (asn1_result == ASN1_ELEMENT_NOT_FOUND)
        assumeWontThrow(writeln("### asn1_read_value privateRSAKey.privateRSAKeyAttributes.modulusLength: ", asn1_strerror2(asn1_result)));
    assert(outLen==2);
//assumeWontThrow(writefln("modulusLength set by set_more_for_keyPairId: %(%02X %)", modulusLength));
    modulusBitsRSA.set(ub22integral(modulusLength), true);

    ubyte[16]  str;
    asn1_result = asn1_read_value(PrKDFentry.structure_new, "privateRSAKey.privateRSAKeyAttributes.value.indirect.path.path", str, outLen);
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

    asn1_result = asn1_read_value(PuKDFentry.structure_new, "publicRSAKey.publicRSAKeyAttributes.value.indirect.path.path", str, outLen);
    if (asn1_result == ASN1_ELEMENT_NOT_FOUND) {
        assumeWontThrow(writeln("### asn1_read_value publicRSAKey.publicRSAKeyAttributes.value.indirect.path.path: ", asn1_strerror2(asn1_result)));
        exit(1);
    }
    assert(outLen>=2);
    fidRSApublic.set( [ub22integral(str[outLen-2..outLen]), 0], true );

    tnTypePtr rsaPriv, rsaPub;
    with (AA["matrixRsaAttributes"])
    try {
        ub2 ub2fidRSAPriv = integral2ub!2(fidRSAprivate.get[0])[0..2];
        rsaPriv = fs.preOrderRange(iter_begin, fs.end()).locate!"equal(a[2..4], b[])"(ub2fidRSAPriv);
//        SetStringId2("", r_AC_Update_Delete_RSAprivateFile, 1, rsaPriv is null? "unknown / unknown" : format!"%02X"(rsaPriv.data[25])~" / "~format!"%02X"(rsaPriv.data[30]));
        AC_Update_Delete_RSAprivateFile.set(rsaPriv is null? [ubyte(0xFF), ubyte(0xFF)] : [rsaPriv.data[25], rsaPriv.data[30]], true);

        ub2 ub2fidRSAPub  = integral2ub!2(fidRSApublic.get[0])[0..2];
        rsaPub  = fs.preOrderRange(iter_begin, fs.end()).locate!"equal(a[2..4], b[])"(ub2fidRSAPub);
//        SetStringId2("", r_AC_Update_Delete_RSApublicFile,  1, rsaPub is null?  "unknown / unknown" : format!"%02X"(rsaPub.data[25]) ~" / "~format!"%02X"(rsaPub.data[30]));
        AC_Update_Delete_RSApublicFile.set(rsaPub is null? [ubyte(0xFF), ubyte(0xFF)]   : [rsaPub.data[25],  rsaPub.data[30]], true);
    }
    catch (Exception e) { printf("### Exception in set_more_for_keyPairId()"); /* todo: handle exception */ }
////
    if (isNewKeyPairId) {
ub16 buf = [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,1,0,1];
valuePublicExponent.set(buf, true);
        isNewKeyPairId = false;
    }
    else {

        enum string commands = `
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
    }
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

//        rc = sc_update_binary(card, posStartPriv, const(ubyte)* buf, posEnd1Priv-posStartPriv, 0);
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

int matrixRsaAttributes_dropcheck_cb(Ihandle* /*self*/, int lin, int col) {
    if (col!=1 || lin>r_storeAsCRTRSAprivate)
        return IUP_IGNORE; // draw nothing
//    printf("matrixRsaAttributes_dropcheck_cb(%d, %d)\n", lin, col);
//    printf("matrixRsaAttributes_dropcheck_cb  %s\n", AA["radio_RSA"].GetAttributeVALUE());
    string activeToggle = AA["radio_RSA"].GetStringVALUE();
    bool isSelectedKeyPairId = AA["matrixRsaAttributes"].GetIntegerId2("", r_keyPairId, 1) != 0;
    switch (lin) {
    /* dropdown */
        case r_keyPairId:
            if (activeToggle != "toggle_RSA_key_pair_create_and_generate")
                return IUP_DEFAULT; // show the dropdown/popup menu
            return     IUP_IGNORE; // draw nothing

        case r_authIdRSAprivate:
            if (!activeToggle.among("toggle_RSA_key_pair_delete", "toggle_RSA_key_pair_try_sign")  &&  isSelectedKeyPairId)
                return IUP_DEFAULT; // show the dropdown/popup menu
            return     IUP_IGNORE; // draw nothing

        case r_modulusBitsRSA:
            if ( !activeToggle.among("toggle_RSA_PrKDF_PuKDF_change", "toggle_RSA_key_pair_delete", "toggle_RSA_key_pair_try_sign")  &&  isSelectedKeyPairId)
                return IUP_DEFAULT; // show the dropdown/popup menu
            return     IUP_IGNORE; // draw nothing

    /* toggle */
        case r_storeAsCRTRSAprivate:
            if ( !activeToggle.among("toggle_RSA_PrKDF_PuKDF_change", "toggle_RSA_key_pair_delete", "toggle_RSA_key_pair_try_sign"))
                return IUP_CONTINUE; // show and enable the toggle button ; this short version works with TOGGLECENTERED only !
            return     IUP_IGNORE; // draw nothing

        case r_keyPairModifiable:
            if (!activeToggle.among("toggle_RSA_key_pair_delete", "toggle_RSA_key_pair_try_sign")  &&  isSelectedKeyPairId)
                return IUP_CONTINUE; // show and enable the toggle button ; this short version works with TOGGLECENTERED only !
            return     IUP_IGNORE; // draw nothing

        default:  return IUP_IGNORE; // draw nothing
    }
} // matrixRsaAttributes_dropcheck_cb

int matrixRsaAttributes_drop_cb(Ihandle* /*self*/, Ihandle* drop, int lin, int col) {
    if (col!=1 || lin>r_storeAsCRTRSAprivate)
        return IUP_IGNORE; // draw nothing
//    printf("matrixRsaAttributes_drop_cb(%d, %d)\n", lin, col);
    string activeToggle = AA["radio_RSA"].GetStringVALUE();
    ubyte[2]  str;
    int outLen;
    int asn1_result, rv;
    with (createHandle(drop))
    switch (lin) {
        case r_keyPairId:
            if (activeToggle != "toggle_RSA_key_pair_create_and_generate") {
                int i = 1;
                foreach (const ref elem; PRKDF) {
                    if ((rv= getIdentifier(elem, "privateRSAKey.commonKeyAttributes.iD")) < 0)
                        continue;
                    SetIntegerId("", i++, rv);
                }
                SetAttributeId("", i, null);
                SetAttributeStr(IUP_VALUE, null);
                return IUP_DEFAULT; // show a dropdown field
            }
            return     IUP_IGNORE;  // show a text-edition field

        case r_authIdRSAprivate:
            if (activeToggle != "toggle_RSA_key_pair_delete") {
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

        case r_modulusBitsRSA:
            foreach (i; 1..16)
                SetIntegerId("", i, 4096-(i-1)*256);
            SetAttributeId("", 16, null);
            SetAttributeStr(IUP_VALUE, null);
            return IUP_DEFAULT;

        default:
            return IUP_IGNORE;
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
    assert(t);
    int val;
    try
        val = fromStringz(t).to!int;
    catch(Exception e) { printf("### Exception in matrixRsaAttributes_dropselect_cb"); return IUP_CONTINUE; }
////    printf("matrixRsaAttributes_dropselect_cb(lin: %d, col: %d, text (t) of the item whose state was changed: %s, mumber (i) of the item whose state was changed: %d, selected (v): %d)\n", lin, col, t, i, v);
    if (v/*selected*/ && col==1) {
        Handle h = createHandle(self);

        switch (lin) {
            case r_modulusBitsRSA:
                modulusBitsRSA.set =  (17-i)*256;
                break;

            case r_keyPairId:
                keyPairId.set = val; //h.GetIntegerVALUE;
                break;

            case r_authIdRSAprivate:
                authIdRSAprivate.set = val; //h.GetIntegerVALUE;
                break;

            default:
                assert(0);//break;
        }
    }
    return IUP_CONTINUE; // return IUP_DEFAULT;
}

int matrixRsaAttributes_edition_cb(Ihandle* ih, int lin, int col, int mode, int update)
{
//mode: 1 if the cell has entered the edition mode, or 0 if the cell has left the edition mode
//update: used when mode=0 to identify if the value will be updated when the callback returns with IUP_DEFAULT. (since 3.0)
//matrixRsaAttributes_edition_cb(1, 1) mode: 1, update: 0
//matrixRsaAttributes_edition_cb(1, 1) mode: 0, update: 1
////    printf("matrixRsaAttributes_edition_cb(%d, %d) mode: %d, update: %d\n", lin, col, mode, update);
    string activeToggle = AA["radio_RSA"].GetStringVALUE();
    bool isSelectedKeyPairId = AA["matrixRsaAttributes"].GetIntegerId2("", r_keyPairId, 1) != 0;
    if (mode==1) {
        AA["statusbar"].SetString(IUP_TITLE, "statusbar");
        if (!isSelectedKeyPairId) {
            if (lin.among(r_keyPairModifiable,
                          r_usageRSAprivateKeyPrKDF,
                          r_keyPairLabel,
                          r_modulusBitsRSA))
                return IUP_IGNORE;
            if (lin==r_authIdRSAprivate && activeToggle != "toggle_RSA_key_pair_delete")
                return IUP_IGNORE;
        }
        switch (activeToggle) {
            case "toggle_RSA_PrKDF_PuKDF_change":
                if (col==2 || lin.among(r_acos_internal,
//                                     r_keyPairId,
                                       r_modulusBitsRSA,
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
//                                     r_authIdRSAprivate,
                                       r_valuePublicExponent,
                                       r_statusInput
//                                     r_usageRSAprivateKeyPrKDF,
//                                       r_usageRSApublicKeyPuKDF,  hidden
//                                     r_keyPairModifiable
                )) // read_only
                    return IUP_IGNORE;
                else
                    return IUP_DEFAULT;
            case "toggle_RSA_key_pair_delete",
                 "toggle_RSA_key_pair_try_sign":
                if (col==2 || lin.among(r_acos_internal,
//                                     r_keyPairId,
                                       r_modulusBitsRSA,
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
                                       r_authIdRSAprivate,
                                       r_valuePublicExponent,
                                       r_statusInput,
                                       r_usageRSAprivateKeyPrKDF,
//                                       r_usageRSApublicKeyPuKDF,  hidden
                                       r_keyPairModifiable
                )) // read_only
                    return IUP_IGNORE;
                else
                    return IUP_DEFAULT;

            case "toggle_RSA_key_pair_regenerate",
                 "toggle_RSA_key_pair_create_and_generate":
                if (col==2 || lin.among(r_acos_internal,
//                                     r_keyPairId,
//                                       r_modulusBitsRSA,
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
//                                       r_authIdRSAprivate,
//                                       r_valuePublicExponent,
                                       r_statusInput
//                                       r_usageRSAprivateKeyPrKDF,
//                                       r_usageRSApublicKeyPuKDF,  hidden
//                                       r_keyPairModifiable
                )) // read_only
                    return IUP_IGNORE;
                else
                    return IUP_DEFAULT;

            default:  assert(0);
        }
    }
    //mode==0
    if (lin.among(r_modulusBitsRSA,        // obj.val set.method in matrixRsaAttributes_dropselect_cb
                  r_keyPairId,             // obj.val set.method in matrixRsaAttributes_dropselect_cb
                  r_authIdRSAprivate,      // obj.val set.method in matrixRsaAttributes_dropselect_cb
                  r_storeAsCRTRSAprivate,  // obj.val set.method in matrixRsaAttributes_togglevalue_cb
                  r_keyPairModifiable,     // obj.val set.method in matrixRsaAttributes_togglevalue_cb
    ))
        return IUP_DEFAULT;

    Handle h = createHandle(ih);

    switch (lin) {
        case r_fidRSADir:
            fidRSADir.set = cast(int) strtol(h.GetAttributeVALUE, null, 16);
            break;

        case r_usageRSAprivateKeyPrKDF:
            {
                if (activeToggle != "toggle_RSA_key_pair_create_and_generate")
                    IupMessage("Feedback upon setting usageRSAprivateKeyPrKDF",
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
                // checking against usageRSAprivateKeyACOS done in status
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

        case r_authIdRSAprivate:
            authIdRSAprivate.set = cast(int) strtol(h.GetAttributeVALUE, null, 16);
            break;

        default:
            break;
    }
    return IUP_DEFAULT;
}

int matrixRsaAttributes_togglevalue_cb(Ihandle* /*self*/, int lin, int col, int status)
{
    assert(col==1 && lin.among(r_keyPairModifiable, r_storeAsCRTRSAprivate));
////    printf("matrixRsaAttributes_togglevalue_cb(%d, %d) status: %d\n", lin, col, status);
    switch (lin) {
        case r_keyPairModifiable:
            bool isSelectedKeyPairId = AA["matrixRsaAttributes"].GetIntegerId2("", r_keyPairId, 1) != 0;
            if (isSelectedKeyPairId)
                keyPairModifiable.set = status;
            else
                assert(0);
            break;

        case r_storeAsCRTRSAprivate:
            storeAsCRTRSAprivate.set = status;
            break;

        default: break;
    }
    return IUP_DEFAULT;
}

int toggle_RSA_cb(Ihandle* ih, int state)
{
//    printf("toggle_RSA_cb (%d) %s\n", state, IupGetName(ih));
    if (state==0) { // for the toggle, that lost activated state
        /* if the keyPairId is not valid (e.g. prior selected was "toggle_RSA_key_pair_create_and_generate" but no creation was invoked)
           then select a valid one */
        int Id;
        Handle h = AA["matrixRsaAttributes"];
        string inactivatedToggle = IupGetName(ih).fromStringz.idup;
        if (inactivatedToggle == "toggle_RSA_key_pair_create_and_generate" &&
            empty(find!((a,b) => b == getIdentifier(a, "privateRSAKey.commonKeyAttributes.iD"))(PRKDF, keyPairId.get)))
            foreach (int i, const ref elem; PRKDF) {
                if ((Id= getIdentifier(elem, "privateRSAKey.commonKeyAttributes.iD")) < 0)
                    continue;
                h.SetIntegerId2("", r_keyPairId, 1, Id);
                matrixRsaAttributes_dropselect_cb(h.GetHandle, r_keyPairId, 1, null, Id.to!string.toStringz, i+1, 1);
                break;
            }
        AA["statusbar"].SetString(IUP_TITLE, "statusbar");
        return IUP_DEFAULT;
    }
    string activeToggle = AA["radio_RSA"].GetStringVALUE();

    if (!keyPairModifiable.get && activeToggle.among("toggle_RSA_key_pair_delete", "toggle_RSA_key_pair_regenerate") ) {
        IupMessage("Feedback upon setting keyPairId",
"The PrKDF entry for the selected keyPairId disallows modifying the RSA private key !\nThe toggle will be changed to toggle_RSA_PrKDF_PuKDF_change toggled");
        AA["toggle_RSA_PrKDF_PuKDF_change"].SetIntegerVALUE(1);
        toggle_RSA_cb(AA["toggle_RSA_PrKDF_PuKDF_change"].GetHandle, 1);
        return IUP_DEFAULT;
    }

    Handle hButton = AA["btn_RSA"];
////    printf("toggle_RSA_cb (%d) %s\n", state, activeToggle.toStringz);

    with (AA["matrixRsaAttributes"])
    switch (activeToggle) {
        case "toggle_RSA_PrKDF_PuKDF_change":            hButton.SetString(IUP_TITLE, "PrKDF/PuKDF only: Change some administrative (PKCS#15) data");
            SetRGBId2(IUP_BGCOLOR, r_keyPairModifiable,       1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_usageRSAprivateKeyPrKDF, 1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyPairLabel,            1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_authIdRSAprivate,        1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_modulusBitsRSA,          1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_valuePublicExponent,     1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_storeAsCRTRSAprivate,    1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_usageRSAprivateKeyACOS,  1,  255,255,255);
            break;
        case "toggle_RSA_key_pair_delete":               hButton.SetString(IUP_TITLE, "RSA key pair: Delete key pair files (Currently not capable to delete the last existing key pair, i.e. one must remain to be selectable)");
            SetRGBId2(IUP_BGCOLOR, r_keyPairModifiable,       1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_usageRSAprivateKeyPrKDF, 1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keyPairLabel,            1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_authIdRSAprivate,        1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_modulusBitsRSA,          1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_valuePublicExponent,     1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_storeAsCRTRSAprivate,    1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_usageRSAprivateKeyACOS,  1,  255,255,255);
            break;
        case "toggle_RSA_key_pair_regenerate":           hButton.SetString(IUP_TITLE, "RSA key pair: Regenerate RSA key pair content in existing files (Takes some time: Up to 3-5 minutes for 4096 bit)");
            SetRGBId2(IUP_BGCOLOR, r_keyPairModifiable,       1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_usageRSAprivateKeyPrKDF, 1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyPairLabel,            1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_authIdRSAprivate,        1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_modulusBitsRSA,          1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_valuePublicExponent,     1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_storeAsCRTRSAprivate,    1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_usageRSAprivateKeyACOS,  1,  152,251,152);
            break;
        case "toggle_RSA_key_pair_create_and_generate":  hButton.SetString(IUP_TITLE, "RSA key pair: Create new RSA key pair files and generate RSA key pair content");
            SetRGBId2(IUP_BGCOLOR, r_keyPairModifiable,       1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_usageRSAprivateKeyPrKDF, 1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_keyPairLabel,            1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_authIdRSAprivate,        1,  152,251,152);

            SetRGBId2(IUP_BGCOLOR, r_modulusBitsRSA,          1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_valuePublicExponent,     1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_storeAsCRTRSAprivate,    1,  152,251,152);
            SetRGBId2(IUP_BGCOLOR, r_usageRSAprivateKeyACOS,  1,  152,251,152);

            isNewKeyPairId = true;
            int nextUniqueId = nextUniqueKeyPairId();
            assert(nextUniqueId>=0);
            keyPairId.set(nextUniqueId, true);
            break;
        case "toggle_RSA_key_pair_try_sign":  hButton.SetString(IUP_TITLE, "RSA key pair: Sign SHA1/SHA256 hash");
            SetRGBId2(IUP_BGCOLOR, r_keyPairModifiable,       1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_usageRSAprivateKeyPrKDF, 1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_keyPairLabel,            1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_authIdRSAprivate,        1,  255,255,255);

            SetRGBId2(IUP_BGCOLOR, r_modulusBitsRSA,          1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_valuePublicExponent,     1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_storeAsCRTRSAprivate,    1,  255,255,255);
            SetRGBId2(IUP_BGCOLOR, r_usageRSAprivateKeyACOS,  1,  255,255,255);
            break;
        default:  assert(0);
    } // switch (activeToggle)
//    printf("invoke recalculation of statusInput\n");
    valuePublicExponent.emit_self(); // invokes updating statusInput for am activated toggle; (valuePublicExponent is arbitrary here, just one, that statusInput depends on)
    // a 'clean' alternative would be, to introduce a Publisher toggle, that statusInput depends on
    return IUP_DEFAULT;
}

const char[] btn_RSA_cb_common1 =`
            int diff;
            diff = doDelete? change_calcPrKDF.pkcs15_ObjectTyp.posStart - change_calcPrKDF.pkcs15_ObjectTyp.posEnd : change_calcPrKDF.get;

            ubyte[] zeroAdd = new ubyte[ diff>=0? 0 : abs(diff) ];
            auto haystackPriv = find!((a,b) => b == getIdentifier(a, "privateRSAKey.commonKeyAttributes.iD"))(PRKDF, keyPairId.get);
            assert(!haystackPriv.empty);
            // change_calcPrKDF.pkcs15_ObjectTyp shall be identical to resulting haystackPriv.front (except the _new components)!) !

            with (change_calcPrKDF.pkcs15_ObjectTyp)
            if (!doDelete && der_new !is null) {
                haystackPriv.front.der = der = der_new.dup;

                asn1_node  structurePriv, tmp = haystackPriv.front.structure;
                int asn1_result = asn1_create_element(PKCS15, pkcs15_names[PKCS15_FILE_TYPE.PKCS15_PRKDF][3], &structurePriv);
                if (asn1_result != ASN1_SUCCESS) {
                    assumeWontThrow(writeln("### Structure creation: ", asn1_strerror2(asn1_result)));
                    return IUP_DEFAULT;
                }
                if (asn1_der_decoding(&structurePriv, haystackPriv.front.der, errorDescription) != ASN1_SUCCESS) {
                    assumeWontThrow(writeln("### asn1Decoding: ", errorDescription));
                    return IUP_DEFAULT;
                }
                haystackPriv.front.structure = structurePriv;
                structure                    = structurePriv;
                asn1_delete_structure(&tmp);
            }

            ubyte[] bufPriv;
            change_calcPrKDF.pkcs15_ObjectTyp.posEnd +=  diff;
            foreach (i, ref elem; haystackPriv) {
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
            auto haystackPubl = find!((a,b) => b == getIdentifier(a, "publicRSAKey.commonKeyAttributes.iD"))(PUKDF, keyPairId.get);
            assert(!haystackPubl.empty);
            // change_calcPuKDF.pkcs15_ObjectTyp shall be identical to resulting haystackPubl.front (except the _new components)!) !

            with (change_calcPuKDF.pkcs15_ObjectTyp)
            if (!doDelete && der_new !is null) {
                haystackPubl.front.der = der = der_new.dup;

                asn1_node  structurePubl, tmp = haystackPubl.front.structure;
                int asn1_result = asn1_create_element(PKCS15, pkcs15_names[PKCS15_FILE_TYPE.PKCS15_PUKDF][3], &structurePubl);
                if (asn1_result != ASN1_SUCCESS) {
                    assumeWontThrow(writeln("### Structure creation: ", asn1_strerror2(asn1_result)));
                    return IUP_DEFAULT;
                }
                if (asn1_der_decoding(&structurePubl, haystackPubl.front.der, errorDescription) != ASN1_SUCCESS) {
                    assumeWontThrow(writeln("### asn1Decoding: ", errorDescription));
                    return IUP_DEFAULT;
                }
                haystackPubl.front.structure = structurePubl;
                structure                    = structurePubl;
                asn1_delete_structure(&tmp);
            }

            ubyte[] bufPubl;
            change_calcPuKDF.pkcs15_ObjectTyp.posEnd +=  diff;
            foreach (i, ref elem; haystackPubl) {
                if (i>0 || !doDelete)
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

    if (!statusInput.get[0]) {
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
    string activeToggle = AA["radio_RSA"].GetStringVALUE();

    switch (activeToggle) {
        case "toggle_RSA_PrKDF_PuKDF_change":
            if (equal(change_calcPrKDF.pkcs15_ObjectTyp.der, change_calcPrKDF.pkcs15_ObjectTyp.der_new) &&
                equal(change_calcPuKDF.pkcs15_ObjectTyp.der, change_calcPuKDF.pkcs15_ObjectTyp.der_new) ) {
                IupMessage("Feedback", "Nothing changed! Won't write anything to files");
                return IUP_DEFAULT;
            }

            //Does statusInput check, that the bytes to be written to PrKDF and PuKDF are there in "free space"
            bool doDelete = false;
            mixin(btn_RSA_cb_common1);

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
            bool doDelete = false;
            mixin(btn_RSA_cb_common1);

            auto       pos_parent = new sitTypeFS(appdf);
            tnTypePtr  prFile, puFile;
            try {
                prFile = fs.siblingRange(fs.begin(pos_parent), fs.end(pos_parent)).locate!"equal(a[2..4], b[])"(integral2ub!2(fidRSAprivate.get[0])[0..2]);
                pos_parent = new sitTypeFS(appdf);
                puFile = fs.siblingRange(fs.begin(pos_parent), fs.end(pos_parent)).locate!"equal(a[2..4], b[])"(integral2ub!2(fidRSApublic.get[0])[0..2]);
            }
            catch (Exception e) { printf("### Exception in btn_RSA_cb() for toggle_RSA_key_pair_regenerate"); return IUP_DEFAULT; /* todo: handle exception */ }
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

            uba  lv_key_len_type_data = [0x02, cast(ubyte)(modulusBitsRSA.get/128), code(storeAsCRTRSAprivate.get, usageRSAprivateKeyACOS.get)];
            if (any(valuePublicExponent.get[0..8]) || ub82integral(valuePublicExponent.get[8..16])!=0x10001) {
                lv_key_len_type_data[0] = 0x12;
                lv_key_len_type_data ~= valuePublicExponent.get;
            }


//            // select app dir
//            {
//                ub2 fid = integral2ub!2(fidRSADir.get)[0..2];
//                rv= acos5_64_short_select(card, null, fid, true);
//                assert(rv==0);
//            }
            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &prFile.data[8], prFile.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);
            if (rv < 0)
                return IUP_DEFAULT;
            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &puFile.data[8], puFile.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_UPDATE);
            if (rv < 0)
                return IUP_DEFAULT;

            {
                sc_security_env  env = { SC_SEC_ENV_FILE_REF_PRESENT, SC_SEC_OPERATION.SC_SEC_OPERATION_GENERATE_RSAPRIVATE };
                env.file_ref.len = 2;
                env.file_ref.value[0..2] = integral2ub!2((fidRSAprivate.get)[0])[0..2];
                if ((rv= sc_set_security_env(card, &env, 0)) < 0) {
                    mixin (log!(__FUNCTION__,  "sc_set_security_env failed for SC_SEC_OPERATION_GENERATE_RSAPRIVATE"));
                    hstat.SetString(IUP_TITLE, "sc_set_security_env failed for SC_SEC_OPERATION_GENERATE_RSAPRIVATE");
                    return IUP_DEFAULT;
                }
            }
            {
                sc_security_env  env = { SC_SEC_ENV_FILE_REF_PRESENT, SC_SEC_OPERATION.SC_SEC_OPERATION_GENERATE_RSAPUBLIC };
                env.file_ref.len = 2;
                env.file_ref.value[0..2] = integral2ub!2((fidRSApublic.get)[0])[0..2];
                if ((rv= sc_set_security_env(card, &env, 0)) < 0) {
                    mixin (log!(__FUNCTION__,  "sc_set_security_env failed for SC_SEC_OPERATION_GENERATE_RSAPUBLIC"));
                    hstat.SetString(IUP_TITLE, "sc_set_security_env failed for SC_SEC_OPERATION_GENERATE_RSAPUBLIC");
                    return IUP_DEFAULT;
                }
            }

            if ((rv= cry_____7_4_4___46_generate_keypair_RSA(card, lv_key_len_type_data)) != SC_SUCCESS) {
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
            return IUP_DEFAULT; // case "toggle_RSA_key_pair_regenerate"

        case "toggle_RSA_key_pair_delete":
        /*
           A   key pair id must be selected, and be >0
           The key pair must be modifiable; flags bit modifiable
           Ask for permission, if the key pair id is associated with a certificate, because it will render the certificate useless
        */
            bool doDelete = true;
            int keyPairId_old = keyPairId.get;
            mixin(btn_RSA_cb_common1);

            auto       pos_parent = new sitTypeFS(appdf);
            tnTypePtr  prFile, puFile;
            try {
                prFile = fs.siblingRange(fs.begin(pos_parent), fs.end(pos_parent)).locate!"equal(a[2..4], b[])"(integral2ub!2(fidRSAprivate.get[0])[0..2]);
                pos_parent = new sitTypeFS(appdf);
                puFile = fs.siblingRange(fs.begin(pos_parent), fs.end(pos_parent)).locate!"equal(a[2..4], b[])"(integral2ub!2(fidRSApublic.get[0])[0..2]);
            }
            catch (Exception e) { printf("### Exception in btn_RSA_cb() for toggle_RSA_key_pair_delete"); return IUP_DEFAULT; /* todo: handle exception */ }
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
            mixin (connect_card!commands); // x-1930 -56
            hstat.SetString(IUP_TITLE, "SUCCESS: Delete key pair files");

            // the files are deleted, but still part of fs and tree view; now remove those too
            ub2[] searched;
            searched ~= integral2ub!2(fidRSAprivate.get[0])[0..2];
            searched ~= integral2ub!2(fidRSApublic. get[0])[0..2];
            sitTypeFS parent = new sitTypeFS(appdf);
            try
            foreach (tnTypePtr nodeFS, unUsed; fs.siblingRange(parent.begin(), parent.end())) {
                assert(nodeFS);
                if (nodeFS.data[0] != EFDB.RSA_Key_EF)
                    continue;
                ubyte len = nodeFS.data[1];
                if (countUntil!((a,b) => equal(a[], b))(searched, nodeFS.data[8+len-2..8+len]) >= 0) {
                    auto  tr = cast(iup.iup_plusD.Tree) AA["tree_fs"];
                    int id = tr.GetId(nodeFS);
//assumeWontThrow(writeln("id: ", id));
//assumeWontThrow(writeln("TITLE: ", tr.GetStringId ("TITLE", id)));
                    if (id>0) {
                        tr.SetStringVALUE(tr.GetStringId ("TITLE", id)); // this seems to select as required
                        tr.SetStringId("DELNODE", id, "SELECTED");
                        fs.erase(new itTypeFS(nodeFS));
                    }
                }
            }
            catch (Exception e) { printf("### Exception in btn_RSA_cb() for toggle_RSA_key_pair_delete"); return IUP_DEFAULT; /* todo: handle exception */}

            int rv;
            Handle h = AA["matrixRsaAttributes"];
            // set to another keyPairId, the first found
            foreach (int i, const ref elem; PRKDF) {
                if ((rv= getIdentifier(elem, "privateRSAKey.commonKeyAttributes.iD")) < 0)
                    continue;
                h.SetIntegerId2("", r_keyPairId, 1, rv);
                matrixRsaAttributes_dropselect_cb(h.GetHandle, r_keyPairId, 1, null, rv.to!string.toStringz, i+1, 1);
                break;
            }
            // TODO remove will leak memory of structure
            PRKDF = PRKDF.remove!((a) => getIdentifier(a, "privateRSAKey.commonKeyAttributes.iD") == keyPairId_old);
            PUKDF = PUKDF.remove!((a) => getIdentifier(a, "publicRSAKey.commonKeyAttributes.iD")  == keyPairId_old);

            GC.collect(); // just a check
            return IUP_DEFAULT; // case "toggle_RSA_key_pair_delete"

        case "toggle_RSA_key_pair_create_and_generate":
            ubyte keyPairIdCurrent = cast(ubyte)keyPairId.get;
            { // scope for the Cryptoki session; upon leaving, everything related get's closed/released
                import core.sys.posix.dlfcn;
                import util_pkcs11;

                CK_RV              rv;
                CK_BYTE[8]         userPin =  0;//[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
                int       pinLocal     = 1;//(info.attrs.pin.reference&0x80)==0x80;
                int       pinReference = 1;//info.attrs.pin.reference&0x7F; // strip the local flag

                int rc = IupGetParam(toStringz("Pin requested for authorization (SCB "/*~toHexString!(Order.increasing,LetterCase.upper)([ubyte(scbs[0])])*/~")"),
                    null/* &param_action*/, null/* void* user_data*/, /*format*/
                    "&Pin local (User)? If local==No, then it's the Security Officer Pin:%b[No,Yes]\n" ~
                    "&Pin reference (1-31; selects the record# in pin file):%i\n" ~
                    "Pin (minLen: 4, maxLen: 8):%s\n", &pinLocal, &pinReference, userPin.ptr, null);
                if (rc != 1)
                    return IUP_DEFAULT;//return SC_ERROR_INVALID_PIN_LENGTH;

                assumeWontThrow(PKCS11.load("opensc-pkcs11.so"));
                scope(exit)  assumeWontThrow(PKCS11.unload());
                // libacos5_64.so is loaded already, but we need the library handle
                lh = assumeWontThrow(Runtime.loadLibrary("libacos5_64.so"));
                assert(lh);
                scope(exit)
                    if (!assumeWontThrow(Runtime.unloadLibrary(lh))) {
                        assumeWontThrow(writeln("Failed to do: Runtime.unloadLibrary(lh)"));
//                        return IUP_DEFAULT;
                    }

                auto control_generate_key = cast(ft_control_generate_key) dlsym(lh, "control_generate_key");
                char* error = dlerror();
                if (error) {
                    printf("dlsym error control_generate_key: %s\n", error);
                    return IUP_DEFAULT;
                }
                /* This will switch off updating PrKDF and PuKDF by opensc, thus we'll have to do it here later !
                  Multiple reasons:
                  1. It's currently impossible to convince opensc to encode the publicRSAKeyAttributes.value CHOICE as indirect. i.e. it would store the publicRSAKey within PuKDF,
                     consuming a lot of memory for many/long keys unnecessarily: acos stores the pub key as file anyway, and it's accessible
                  2. opensc always adds signRecover/verifyRecover when sign/verify is selected
                  3. PuKDF contains wrong entry commonKeyAttributes.native=false
//                  4. opensc changes the id setting, see id-style in profile; currently I prefer 1-byte ids, same as the last nibble of fileid, i.e. keypair 41F5/4135 gets id 0x05
                  5. opensc erases CommonObjectAttributes.flags for pubkey occasionally
                  6. opensc stores less bits for  occasionally
                  7  opensc stores incorect modulusLength occasionally
                 */
                // also this provides more control of keygen, than possible with opensc (tools etc.)
                control_generate_key(true, !!(usageRSAprivateKeyACOS.get&2), !!storeAsCRTRSAprivate.get);

                rv= C_Initialize(null);
                pkcs11_check_return_value(rv, "Failed to initialze Cryptoki");
                if (rv != CKR_OK)
                    return IUP_DEFAULT;
                scope(exit)
                    C_Finalize(NULL_PTR);

                CK_SLOT_ID  slot = pkcs11_get_slot();
                CK_SESSION_HANDLE  session = pkcs11_start_session(slot);
                pkcs11_login(session, userPin); // CKR_USER_PIN_NOT_INITIALIZED

                CK_OBJECT_HANDLE  publicKey, privateKey;
                CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
                CK_ULONG modulusBits = modulusBitsRSA.get;
                CK_BYTE[] publicExponent = valuePublicExponent.get[0..16].dup;  // check whether the key_gen command respects this ; check  publicExponent handling in general in opensc (e.g. _sc_card_add_rsa_alg)
                CK_BYTE[] subject = cast(ubyte[])representation(keyPairLabel.get);
                CK_BYTE[] id      = [keyPairIdCurrent];
                CK_BBOOL yes = CK_TRUE;
                CK_BBOOL no  = CK_FALSE;
                CK_ATTRIBUTE[] publicKeyTemplate = [
                    {CKA_ID, id.ptr, id.length},
                    {CKA_LABEL, subject.ptr, subject.length},
                    {CKA_TOKEN, &yes, CK_BBOOL.sizeof}, // CKA_TOKEN=true to create a token object, opposed to session object
//                    {CKA_LOCAL, &yes, CK_BBOOL.sizeof}, // not becessary
                    {CKA_ENCRYPT, usageRSAprivateKeyPrKDF.get&2? &yes : &no, CK_BBOOL.sizeof},
                    {CKA_VERIFY,  usageRSAprivateKeyPrKDF.get&4? &yes : &no, CK_BBOOL.sizeof},

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
                    {CKA_DECRYPT, usageRSAprivateKeyPrKDF.get&2? &yes : &no, CK_BBOOL.sizeof},
                    {CKA_SIGN,    usageRSAprivateKeyPrKDF.get&4? &yes : &no, CK_BBOOL.sizeof},
                ];

                rv = C_GenerateKeyPair(session,
                    &mechanism,
                    publicKeyTemplate.ptr,  publicKeyTemplate.length,
                    privateKeyTemplate.ptr, privateKeyTemplate.length,
                    &publicKey,
                    &privateKey);
                pkcs11_check_return_value(rv, "generate key pair");
                if (rv != SC_SUCCESS)
                    hstat.SetString(IUP_TITLE, "FAILURE: Generate new RSA key pair. This isn't abnormal with acos. Just try again");

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

            fci_se_info  info2;
            rv= acos5_64_short_select(card, &info2, integral2ub!2(fidRSAprivate.get[0])[0..2], true, rbuf_priv);
            assert(rv == SC_SUCCESS); // the file should exist now: it was created by the C_GenerateKeyPair call
            info_priv[24..32] = info2.sac[];
            info2 = fci_se_info.init;
            rv= acos5_64_short_select(card, &info2, integral2ub!2(fidRSApublic.get[0])[0..2], true, rbuf_publ);
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
            auto iter = new itTypeFS(appdf);
            auto iter_priv = fs.append_child(iter, info_priv);
            auto iter_publ = fs.append_child(iter, info_publ);
            auto tr = cast(iup.iup_plusD.Tree) AA["tree_fs"];
            int id_appdf, rv;
            with (tr) {
                id_appdf = GetId(appdf);
                SetStringId(IUP_ADDLEAF, id_appdf, assumeWontThrow(format!" %04X  %s"(ub22integral(info_publ[2..4]),
                  file_type(2, cast(EFDB)info_publ[0], ub22integral(info_publ[2..4]), info_publ[4..6]))) ~"    "~pkcs15_names[info_publ[6]][0]);
                rv = SetUserId(id_appdf+1, iter_publ.node);
                assert(rv);
                SetAttributeId("TOGGLEVALUE", id_appdf+1, info_publ[7]==5? IUP_ON : IUP_OFF);
//                SetAttributeId(IUP_IMAGE,     id_appdf+1, "IUP_IMGBLANK");
                SetAttributeId(IUP_IMAGE,     id_appdf+1, IUP_IMGBLANK);

                SetStringId(IUP_ADDLEAF, id_appdf, assumeWontThrow(format!" %04X  %s"(ub22integral(info_priv[2..4]),
                  file_type(2, cast(EFDB)info_priv[0], ub22integral(info_priv[2..4]), info_priv[4..6]))) ~"    "~pkcs15_names[info_priv[6]][0]);
                rv = SetUserId(id_appdf+1, iter_priv.node);
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
            AA["toggle_RSA_PrKDF_PuKDF_change"].SetIntegerVALUE(1);
            toggle_RSA_cb(AA["toggle_RSA_PrKDF_PuKDF_change"].GetHandle, 1);
            keyPairId.set(keyPairIdCurrent, true);
            hstat.SetString(IUP_TITLE, "SUCCESS: RSA_key_pair_create_and_generate");
            GC.collect(); // just a check
            return IUP_DEFAULT; // case "toggle_RSA_key_pair_create_and_generate"

        case "toggle_RSA_key_pair_try_sign":
            /* convert the 'textual' hex to an ubyte[] hex (first 64 chars = 32 byte) ; sadly std.conv.hexString works for literals only */
            string tmp_str = AA["hash_to_be_signed"].GetStringVALUE();
            tmp_str.length = 64;
            string tmp_str2 = tmp_str[ 0..16] ~ '\0' ~ tmp_str[16..32] ~ '\0' ~ tmp_str[32..48] ~ '\0' ~ tmp_str[48..64] ~ '\0';
            ub32 hash;
            hash[ 0.. 8] = integral2ub!8(strtoull(tmp_str2.ptr,    null, 16))[0..8];
            hash[ 8..16] = integral2ub!8(strtoull(tmp_str2.ptr+17, null, 16))[0..8];
            hash[16..24] = integral2ub!8(strtoull(tmp_str2.ptr+34, null, 16))[0..8];
            hash[24..32] = integral2ub!8(strtoull(tmp_str2.ptr+51, null, 16))[0..8];
            assumeWontThrow(writefln("### hash_to_be_signed: %(%02X %)", hash));

            auto       pos_parent = new sitTypeFS(appdf);
            tnTypePtr  prFile;
            try
                prFile = fs.siblingRange(fs.begin(pos_parent), fs.end(pos_parent)).locate!"equal(a[2..4], b[])"(integral2ub!2(fidRSAprivate.get[0])[0..2]);
            catch (Exception e) { printf("### Exception in btn_RSA_cb() for toggle_RSA_key_pair_try_sign"); return IUP_DEFAULT; /* todo: handle exception */ }
            assert(prFile);
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

//            // select app dir
//            {
//                ub2 fid = integral2ub!2(fidRSADir.get)[0..2];
//                rv= acos5_64_short_select(card, null, fid, true);
//                assert(rv==0);
//            }
            sc_path_set(&file.path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, &prFile.data[8], prFile.data[1], 0, -1);
            rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_GENERATE);
            if (rv < 0)
                return IUP_DEFAULT;

            {
                sc_security_env  env = { SC_SEC_ENV_FILE_REF_PRESENT | SC_SEC_ENV_ALG_PRESENT, SC_SEC_OPERATION.SC_SEC_OPERATION_SIGN, SC_ALGORITHM_RSA };
                env.file_ref.len = 2;
                env.file_ref.value[0..2] = integral2ub!2((fidRSAprivate.get)[0])[0..2];
                if ((rv= sc_set_security_env(card, &env, 0)) < 0) {
                    mixin (log!(__FUNCTION__,  "sc_set_security_env failed for SC_SEC_OPERATION_SIGN"));
                    hstat.SetString(IUP_TITLE, "sc_set_security_env failed for SC_SEC_OPERATION_SIGN");
                    return IUP_DEFAULT;
                }
            }
            size_t sigLen = modulusBitsRSA.get/8;
            ubyte[] signature = new ubyte[sigLen];
//            ubyte[32] data = iota(ubyte(1), ubyte(33), ubyte(1)).array[]; // simulates a SHA256 hash
            if ((rv= sc_compute_signature(card, hash.ptr, hash.length, signature.ptr, signature.length)) != sigLen) {
                    mixin (log!(__FUNCTION__,  "sc_compute_signature failed"));
                    hstat.SetString(IUP_TITLE, "sc_compute_signature failed");
                    return IUP_DEFAULT;
            }
            assumeWontThrow(writefln("### signature: %(%02X %)", signature));
`;
            mixin (connect_card!commands);
            return IUP_DEFAULT; // case "toggle_RSA_key_pair_try_sign"

        default:  assert(0);
    } // switch (activeToggle)
} // btn_RSA_cb


} //extern(C) nothrow
