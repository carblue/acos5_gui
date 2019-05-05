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


version(unittest) {
	import std.stdio : writeln, writefln;
	import std.exception : assumeWontThrow;

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
}

//---- above only imports from phobos, druntime: std, core ...
//---- imports from package:  opensc
//---- imports from package:  deimos.openssl
//---- imports from package:  other (external (dub) or local)      BUT NOTHING related to acos5_64 implementation files
/** ---- above only imports from phobos, druntime, deimos.openssl, opensc or 'other', below acos5_64 implementation files */

/** This file shall not depend on any of the acos5_64 implementation files !! */

size_t multipleGreaterEqual(size_t x, uint multiplier) pure nothrow @nogc @safe {
/*
Given any positive x, what is the nearest number n >= x that is a multiple of 'multiplier' ?
multipleGreaterEqual( 0,  8)  == 0
multipleGreaterEqual( 7,  8)  == 8
multipleGreaterEqual( 8,  8)  == 8
multipleGreaterEqual( 9,  8)  == 16

*/
    immutable rem = x%multiplier;
    return  x+ (rem==0? 0 : multiplier-rem);
}

string ubaIntegral2string(const(ubyte)[] arr, uint radix=16) nothrow {
	import std.conv : to, LetterCase;
	import std.digest : toHexString, Order;

	switch (radix) {
		case 16:  return toHexString!(Order.increasing,LetterCase.upper)(arr);
		case 10:
			if (arr.length<=8)
				return ub82integral(arr).to!string(radix);
			else
			{	assert(0); }
		default:  assert(0);
	}
}

ubyte[] string2ubaIntegral(string arr, uint radix=16) nothrow {
	import std.ascii : isHexDigit, isDigit, toUpper;
	import std.conv : to;
	import std.algorithm.searching : find;
	import std.exception : assumeWontThrow;
//	import std.math : pow;
	ubyte[]  result;
	switch (radix) {
		/* case 16 for literals :  std.conv.hexString does exactly that but with a string result, e.g.  auto indata = cast(immutable(ubyte)[])hexString!"A4 06 83 01 81 95 01 08"; */
		case 16:
			ubyte u;
			foreach (i, c; arr) {
				if (c.isHexDigit) {
					if ((i&1) == 0)
						u  =  cast(ubyte) ((c.isDigit? c - '0' : toUpper(c) - '7') << 4);
					else {
						u |=                c.isDigit? c - '0' : toUpper(c) - '7';
						result ~= u;
					}
				}
				else {
					result.length = 0;
					return result;
				}
			}
			return result;
		case 10:
			if (arr.length>19 || !arr.length)
					return result;
//			else {
				ulong ul_result;
/*
				ulong ul_digit;
				foreach (i, c; arr) {
				    if (!c.isDigit) {
					    result.length = 0;
					    return result;
				    }
				    ul_digit = c - '0';
				    assumeWontThrow(writefln("i(%s) c(%s), ul_digit(%s) pow %s", i, c, ul_digit, pow(10, arr.length -1 -i)));
					ul_result += pow(10UL, arr.length -1 -i) * (c.isDigit? c - '0' : toUpper(c) - '7');
				}
*/
				assumeWontThrow(ul_result = arr.to!ulong);
				result = integral2uba!8(ul_result);
				result = find!"a>0"(result);
				return result; // 0xFFFFFFFFFFFFFFFF == 1,84467440737e+19
//			}
		default:  return result;
	}
}

//	assert(equal(string2ubaIntegral("439041101", 10), [0x1A, 0x2B, 0x3c, 0x4d]));


pragma(inline, true)
ubyte bitswap ( ubyte x ) pure nothrow @nogc @safe
{
	static import core.bitop;
	return core.bitop.bitswap(cast(uint)x) >>> 24;
}

ubyte[] /* <-OctetStringBigEndian*/ integral2uba(uint storage_bytes)(size_t integral) // pure nothrow /*@nogc*/ @safe
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

/**
   converts a byte array, representing an unsigned integral number in network byte order (most significant byte first/big-endian) to an unsigned integral
   For 64-bit processors, the max. length of the byte array may be 8, denoted by the param name ub8
*/
ulong ub82integral(scope const ubyte[] ubMax8) pure nothrow @nogc @safe { // formerly ub22integralLastTwo
	import std.math : pow;
	ulong result;
	if (ubMax8.length == 0)
		return 0;
	immutable lenM1 = ubMax8.length - 1;
version(X86)
{	assert(lenM1<=3); }
else
	assert(lenM1<=7);
	foreach (i, b; ubMax8)
		result += b* pow(256, lenM1-i); // 0x 3F 00 41 00  == 1.056.981.248
	return  result;
}

/* arr represents an integer with least significant bits stored at the end/back of arr */
ulong bits_used(ubyte[] arr) @nogc nothrow pure @safe
{
	import std.algorithm.searching : any, countUntil;
	import std.math : ilogb;

	if (!any(arr))
		return 0;
	immutable pos = countUntil!"a>0"(arr);
	return  1+ilogb(arr[pos]) + 8*(arr.length-pos-1);
}



nothrow
unittest {
	assert(equal(ubaIntegral2string([0x1A, 0x2B, 0x3c, 0x4d], 16), "1A2B3C4D" ));
	assert(equal(ubaIntegral2string([0x1A, 0x2B, 0x3c, 0x4d], 10), "439041101"));
	assumeWontThrow(writeln("PASSED: ubaIntegral2string"));

	assert(equal(string2ubaIntegral("1a2b3C4D",  16), [0x1A, 0x2B, 0x3c, 0x4d]));
	assert(equal(string2ubaIntegral("439041101", 10), [0x1A, 0x2B, 0x3c, 0x4d]));
	assumeWontThrow(writeln("PASSED: string2ubaIntegral"));
}

pure nothrow @nogc @safe
unittest {
	assert(bitswap(ubyte(25)) == 152);
	ubyte[2] ub2 = [0x41, 0x03];
	assert(ub22integral(ub2) == 0x4103);
	ubyte[4] ub4 = [0x3F, 0x00, 0x41, 0x00];
	assert(ub82integral(ub4) == 0x3F004100);
version(X86_64) {
	ubyte[8] ub  = [0x3F, 0x00, 0x41, 0x00, 0x01, 0x02, 0xFE, 0xFF];
	assert(ub82integral(ub) == 0x3F0041000102FEFF);
//	assumeWontThrow(writeln("PASSED: ub82integral for ubyte[8]"));
}
	ubyte[8] ub8 = [0,0,0,0,0, 1, 0, 1];
	assert(bits_used(ub8)==17);

	assert(multipleGreaterEqual( 0,  8)  == 0);
	assert(multipleGreaterEqual( 7,  8)  == 8);
	assert(multipleGreaterEqual( 8,  8)  == 8);
	assert(multipleGreaterEqual( 9,  8)  == 16);
}

pure nothrow /*@nogc*/ @safe
unittest {
version(X86_64) {
	const integralVal = 0xFFEEDDCCBBAA9988UL;
	assert(equal(integral2uba!8(integralVal), [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88][]));
version(LittleEndian)
	assert(equal(integral2uba!4(integralVal),                         [0xBB, 0xAA, 0x99, 0x88][]));

	ubyte[2] p1p2 = [0, 255];
	ubyte[2] res = integral2uba!2(ub22integral(p1p2) + 112)[];
	assert(equal(res[], [1,111]));
}
else version(X86) {
	const integralVal = 0xFFEEDDCCUL;
	assert(equal(integral2uba!4(integralVal), [0xFF, 0xEE, 0xDD, 0xCC][]));
}
else
	static assert(0);
}

@safe unittest {
	writeln("PASSED: bitswap");
	writeln("PASSED: ub22integral");
version(X86_64) {
	writeln("PASSED: integral2uba!8");
	version(LittleEndian)
		writeln("PASSED: integral2uba!4");
	writeln("PASSED: integral2uba!2(ub22integral(x) + y)");
}
else
	version(X86)
		writeln("PASSED: integral2uba!4");
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
