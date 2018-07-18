module pub;

import core.stdc.stdio : printf;
import std.signals;// : Signal;
import std.format : format;
import std.conv: to;
import std.exception : assumeWontThrow, assumeUnique;
import std.stdio;

import iup.iup_plusD : Handle;

import keyAsym : set_more_for_keyAsym_Id;
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
struct _AC_Update_Delete_RSAprivateFile{}
struct _AC_Update_Delete_RSApublicFile{}
struct _AC_Delete_Create_RSADir{}
//Obs
//struct _keyAsym_usagePuKDF{}

import keySym : set_more_for_keySym_Id;
// tag types
struct _keySym_algoType{}
struct _keySym_keyLenBits{}
struct _keySym_usageSKDF{}

struct _keySym_ExtAutStore{}
struct _keySym_ExtAut_ErrorCounterYN{}
struct _keySym_IntAutStore{}
struct _keySym_IntAut_UsageCounterYN{}

struct _keySym_Id{}
//struct _keySym_keyRef{}
struct _keySym_Label{}
struct _keySym_Modifiable{}
struct _keySym_authId{}
struct _keySym_fidAppDir{}
struct _keySym_fid{}
struct _keySym_global_local{}

struct _AC_Update_SKDF{}       //SCB
struct _AC_Update_keyFile{}    //SCB


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
                if ((cptr = h.GetAttributeStr("_keyAsym_fidAppDir")) != null) {
                    auto obj  = cast(Pub!_keyAsym_fidAppDir) cptr;
                    assert(obj !is null);
                    obj.set = cast(int) strtol(h.GetAttributeVALUE, null, 16);
                }
*/
    }

    @property V set(V v, bool programmatically=false)  nothrow {
        try {
            _value = v;
assumeWontThrow(writefln(T.stringof~" object was set to value %s", _value));

            static if (is(T==_keyAsym_usageGenerate) || is(T==_keyAsym_usagePrKDF) || is(T==_keySym_usageSKDF) /*|| is(T==_keyAsym_usagePuKDF)*/) {
                if (_h !is null) {
//assumeWontThrow(writefln(T.stringof~" object was set to value %s and translate int", _value));
                    _h.SetStringId2 ("", _lin, _col, keyUsageFlagsInt2string(_value));
                }
            }
            else static if (is(T==_keyAsym_Label) || is(T==_keySym_Label) || is(T==_keySym_algoType)) {
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
            else static if (is(T==_keySym_fidAppDir) || is(T==_keySym_fid)) {
                if (programmatically &&  _h !is null)
                    _h.SetStringId2 ("", _lin, _col, _hexRep? format!"%04X"(_value) : _value.to!string);
            }
            else {
                if (programmatically &&  _h !is null)
                    _h.SetStringId2 ("", _lin, _col, _hexRep? format!"%X"(_value) : _value.to!string);
            }
            emit(T.stringof, _value);
            /* this is critical for _keyAsym_Id:
             * First change_calcPrKDF.watch and change_calcPuKDF.watch must run: They create/dup structure to structure_new
             * only then: set_more_for_keyAsym_Id */
            static if (is (T == _keyAsym_Id))
                set_more_for_keyAsym_Id(_value);
            static if (is (T == _keySym_Id))
                set_more_for_keySym_Id(_value);
        }
        catch (Exception e) { printf("### Exception in Pub.set()\n"); /* todo: handle exception */ }
        return _value;
    }

    mixin Pub_boilerplate!(T,V);
}

