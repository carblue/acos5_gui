/*
 * Written in the D programming language, part of package acos5_64/acos5_64_gui.
 * util_general.d: Shared general utilities.
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
  Code that is in no way specific for opensc or any driver like acos5_64
*/

module util_general;

//---- above only imports from phobos, druntime: std, core ...
//---- imports from package:  opensc
//---- imports from package:  deimos.openssl
//---- imports from package:  other (external (dub) or local)      BUT NOTHING related to acos5_64 implementation files
/** ---- above only imports from phobos, druntime, deimos.openssl, opensc or 'other', below acos5_64 implementation files */

/** This file shall not depend on any of the acos5_64 implementation files !! */


pragma(inline, true)
ubyte bitswap ( ubyte x ) pure nothrow @nogc @safe
{
	static import core.bitop;
	return core.bitop.bitswap(cast(uint)x) >>> 24;
}

ubyte[] /* <-OctetStringBigEndian*/ integral2ub(uint storage_bytes)(size_t integral) // pure nothrow /*@nogc*/ @safe
	if (storage_bytes && storage_bytes<=size_t.sizeof)
{
	ubyte[] result;
	foreach (i; 0..storage_bytes)
		result ~= cast(ubyte)(integral >>> 8*(storage_bytes-1-i) & 0xFF); // precedence: () *  >>>  &
	return result;
}

/** Take a byte stream as coming form the token and convert to an integral value
Most often, the byte stream has to be interpreted as big-endian (The most significant byte (MSB) value, is at the lowest address (position in stream). The other bytes follow in decreasing order of significance)
currently used in new_file and unittest only
*/
ushort ub22integral(scope const ubyte[] ubtwo) pure nothrow @nogc @safe { // formerly ub22integralLastTwo
/* TODO make this general :
ushort ubyte_arr2ushort
uint   ubyte_arr2uint
ulong  ubyte_arr2ulong
ucent  ubyte_arr2ucent
auto ubyte_arr2integral(ubyte size)(ubyte[size] ubyte_arr) // allowed sizes: 2,4,8

Endianess is not relevant here !
*/
	assert(ubtwo.length==2);
	return  (ubtwo[0] << 8) | ubtwo[1];
}

ulong ub82integral(scope const ubyte[] ubeight) pure nothrow @nogc @safe { // formerly ub22integralLastTwo
// the representation in ubeight is bigEndian
    import std.math : pow;
	ulong result;
	assert(ubeight.length && ubeight.length<=8);
	foreach_reverse (i, b; ubeight)
/*
//    import std.exception : assumeWontThrow;
//    import std.stdio : writeln;
	    assumeWontThrow(writeln(i, " ", b));
3 0
2 65  0x41
1 0
0 63  0x3F
*/
		result += b* pow(256, ubeight.length-1-i); // 0x 3F 00 41 00  == 1.056.981.248

	return  result;
}

/* arr represents an integer with least significant bits stored at the end/back of arr */
ulong bits_used(ubyte[] arr) @nogc nothrow pure @safe
{
    import std.algorithm.searching : any, countUntil;
    import std.math : ilogb;

    if (!any(arr))
        return 0;
    ulong pos = countUntil!"a>0"(arr);
    return  1+ilogb(arr[pos]) + 8*(arr.length-pos-1);
}



import std.stdio : writeln;

version(GNU) { // gdc compiler
	import std.algorithm : equal /*, min, max, clamp, find, canFind, countUntil, any, mismatch, commonPrefix*/;
//import gcc.attribute;
}
else { // DigitalMars or LDC compiler
//	import std.algorithm.iteration : fold;
	import std.algorithm.comparison : equal/*, min, max, clamp, mismatch*/;
//	import std.algorithm.searching : /*count,*/ find, canFind, countUntil/*, any ,all, commonPrefix*/;
//	import std.algorithm.mutation: reverse;
}


pure nothrow @nogc @safe
unittest {
	assert(bitswap(ubyte(25)) == 152);
	ubyte[2] ub2 = [0x41, 0x03];
	assert(ub22integral(ub2) == 0x4103);
	ubyte[4] ub4 = [0x3F, 0x00, 0x41, 0x00];
	assert(ub82integral(ub4) == 0x3F004100);
	ubyte[] ub8 = [0,0,0,0,0, 1, 0, 1];
	assert(bits_used(ub8)==17);
}

pure nothrow /*@nogc*/ @safe
unittest {
version(X86_64) {
	const integralVal = 0xFFEEDDCCBBAA9988UL;
	assert(equal(integral2ub!8(integralVal), [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88][]));
version(LittleEndian)
	assert(equal(integral2ub!4(integralVal),                         [0xBB, 0xAA, 0x99, 0x88][]));

	ubyte[2] P1P2_or_P2 = [0, 255];
	ubyte[2] res = integral2ub!2(ub22integral(P1P2_or_P2) + 112)[];
	assert(equal(res[], [1,111]));
}
else version(X86) {
	const integralVal = 0xFFEEDDCCUL;
	assert(equal(integral2ub!4(integralVal), [0xFF, 0xEE, 0xDD, 0xCC][]));
}
else
	static assert(0);
}

@safe unittest {
	writeln("PASSED: bitswap");
	writeln("PASSED: ub22integral");
	writeln("PASSED: ub22integral");
version(X86_64) {
	writeln("PASSED: integral2ub!8");
	version(LittleEndian)
		writeln("PASSED: integral2ub!4");
	writeln("PASSED: integral2ub!2(ub22integral(x) + y)");
}
else
	version(X86)
		writeln("PASSED: integral2ub!4");
}

struct TriBool { //similar to std.typecons : Ternary; but no algebra required, just the states
	@safe @nogc nothrow pure:

	private ubyte m_value = 2; // yes
	private static TriBool make(ubyte b) {
		TriBool r = void;
		r.m_value = b;
		return r;
	}

	@property ubyte value() const {
		return m_value;
	}

	alias value this; // different from std.typecons.Ternary  // gdc seems to ignore it

	/** The possible states of the 'TriBool' */
	enum no      = make(0);
	enum yes     = make(2);
	enum unknown = make(6);
}
