/*
 * Written in the D programming language, part of package acos5_64_gui.
 * util_opensc.d:
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

module util_opensc;

import core.sys.posix.dlfcn;

import core.runtime : Runtime;
import core.stdc.stdlib : EXIT_SUCCESS, EXIT_FAILURE, exit, getenv;
import core.stdc.config : c_long, c_ulong;
import core.stdc.string;
import std.string;
import std.conv : to;
import std.format;
import std.exception : assumeWontThrow;
import std.algorithm.comparison : min, equal, /*max, clamp, mismatch,*/ among;
import std.algorithm.searching : count, minElement, minIndex, countUntil;
import std.algorithm : remove;
import std.traits : EnumMembers;
import std.typecons : Tuple;
import std.digest : toHexString;

import libopensc.opensc;
import libopensc.types;
import libopensc.errors;
import libopensc.log;
import libopensc.iso7816;
import libopensc.pkcs15 : SC_PKCS15_DF;

import iup.iup_plusD;
import asn1.codecs.der;
import tree_k_ary;
import acos5_64_shared;

import util_general;

enum PKCS15_FILE_TYPE : ubyte {
	PKCS15_PRKDF          = SC_PKCS15_DF.SC_PKCS15_PRKDF,         // = 0,
	PKCS15_PUKDF          = SC_PKCS15_DF.SC_PKCS15_PUKDF,         // = 1,
	PKCS15_PUKDF_TRUSTED  = SC_PKCS15_DF.SC_PKCS15_PUKDF_TRUSTED, // = 2,
	PKCS15_SKDF           = SC_PKCS15_DF.SC_PKCS15_SKDF,          // = 3,
	PKCS15_CDF            = SC_PKCS15_DF.SC_PKCS15_CDF,           // = 4,
	PKCS15_CDF_TRUSTED    = SC_PKCS15_DF.SC_PKCS15_CDF_TRUSTED,   // = 5,
	PKCS15_CDF_USEFUL     = SC_PKCS15_DF.SC_PKCS15_CDF_USEFUL,    // = 6,
	PKCS15_DODF           = SC_PKCS15_DF.SC_PKCS15_DODF,          // = 7,
	PKCS15_AODF           = SC_PKCS15_DF.SC_PKCS15_AODF,          // = 8,

    PKCS15_RSAPublicKey   = 9,  // file 0x4131  (arbitrary, asn1-encoded public RSA key file) RSA_PUB

    PKCS15_DIR            = 10, // file 0x2F00  (fix acc. to ISO/IEC 7816-4)
    PKCS15_ODF            = 11, // file 0x5031  (fix acc. to ISO/IEC 7816-4)
    PKCS15_TOKENINFO      = 12, // file 0x5032  (fix acc. to ISO/IEC 7816-4)
    PKCS15_UNUSED         = 13, // file 0x5033  (fix acc. to ISO/IEC 7816-4)   DOESN'T NEED DETECTION  ???
    PKCS15_APPDF          = 14, // file 0x4100  (arbitrary)                    DOESN'T NEED DETECTION !
    PKCS15_CERT           = 15,
    PKCS15_RSAPrivateKey  = 16,
    PKCS15_SecretKey      = 17,
    PKCS15_NONE           = 0xFF, // should not happen to extract a path for this
}
//mixin FreeEnumMembers!PKCS15_FILE_TYPE;

string[] PKCS15_FILE_TYPE_NAME = [
    "EF.PrKD",      // 0
    "EF.PuKD",
    "EF.PuKD_TRUSTED",
    "EF.SKD",
    "EF.CD",
    "EF.CD_TRUSTED",
    "EF.CD_USEFUL",
    "EF.DCOD",
    "EF.AOD",

    "EF.RSA_PUB",   // 9

    "EF.DIR",
    "EF.OD",
    "EF.CardInfo",
    "EF.UnUsed",
    "DF.CIA",       // 14
    "EF.CERT",      // 15
    "EF.RSA_PRIV",  // 16
    "EF.SecretKey", // 17
];

enum dim = 10;

enum indexArray  = [ // the order, in which patterns are stored in immutable ASN1patternElement[][dim] ASN1patterns
    PKCS15_FILE_TYPE.PKCS15_RSAPublicKey, // 0
    PKCS15_FILE_TYPE.PKCS15_DIR,          // 1
    PKCS15_FILE_TYPE.PKCS15_ODF,          // 2
    PKCS15_FILE_TYPE.PKCS15_TOKENINFO,    // 3
    PKCS15_FILE_TYPE.PKCS15_CERT,         // 4
    PKCS15_FILE_TYPE.PKCS15_PRKDF,        // 5
    PKCS15_FILE_TYPE.PKCS15_PUKDF,        // 6
    PKCS15_FILE_TYPE.PKCS15_SKDF,         // 7
    PKCS15_FILE_TYPE.PKCS15_CDF,          // 8
    PKCS15_FILE_TYPE.PKCS15_AODF,         // 9
];
//        detectResult = [ 9, 10, 11, 12, 15,   0, 1, 3, 4/*, 7*/, 8 ];
// the index (0 based) where a PKCS15_FILE_TYPE is positioned in indexArray
ubyte idx(const PKCS15_FILE_TYPE pft) /*@nogc*/ nothrow @safe {
    with (PKCS15_FILE_TYPE)
    assert(pft.among(PKCS15_RSAPublicKey, PKCS15_DIR, PKCS15_ODF, PKCS15_TOKENINFO, PKCS15_CERT,   PKCS15_PRKDF, PKCS15_PUKDF, PKCS15_SKDF, PKCS15_CDF/*, 7*/, PKCS15_AODF));
    return  cast(ubyte)countUntil(indexArray, pft);
}

struct PKCS15Path_FileType {
    ubyte[]           path;
    PKCS15_FILE_TYPE  pkcs15FileType;

    import mixin_templates_opensc;
    import std.algorithm.comparison : clamp;

version(ENABLE_TOSTRING)
	void toString(scope void delegate(const(char)[]) sink, FormatSpec!char fmt) const
	{
		mixin(frame_noPointer_OneArrayFormatx_noUnion!("path", "path.length", "path.length"));
	}
} // struct PKCS15Path_FileType

// The 8 bytes are: {FDB, DCB (replaced by length path), FILE ID, FILE ID, SIZE or MRL, SIZE or NOR, SFI (replaced by enum PKCS15_FILE_TYPE), LCSI};
/*
  The layout of the tree_k_ary.Tree!ub24 data/payload:
  ubyte[24]: It's first 8 bytes basically are the return value from acos command: Get Card Info/File Information,
             it's last 16 bytes are for storing a file path.
             Some bytes of the file information ubyte[8] are replaced though with other content:
        [0]: FDB File Descriptor Byte, see also Reference Manual for values
        [1]: (originally DCB always zero), replaced by the Length of path ubyte[16] actually used (from the beginning, i.e. path[0..Length])
        [2]: FILE ID (MSB)
        [3]: FILE ID (LSB)
        [4]: depending on FDB: FILE ID (MSB) or MRL (Max. Record Length)
        [5]: depending on FDB: FILE ID (LSB) or NOR (Number of Records)
        [6]: (originally SFI), replaced by default 0xFF or if applicable, the meaning expressed as  enum PKCS15_FILE_TYPE, that this file has for PKCS#15, i.e.
             tree traversal for all nodes with data[6]!=0xFF visits all files relevant for the PKCS#15 file structure or mentioned in PKCS#15 files,
             e.g. only those public RSA key files, that are listed in EF.PuKD will get the image symbol "IMGBLANK"; there may be other RSA files not known to PKCS#15,
             that get decaorated as any other non-PKCS#15 file with the default: "IMGLEAF" (a bullet).
        [7]: LCSI Life Cycle Status Integer
*/

alias  TreeTypeFS = tree_k_ary.Tree!ub24; // 8 bytes + length of pathlen_max considered, here SC_MAX_PATH_SIZE = 16
alias  sitTypeFS  = TreeTypeFS.sibling_iterator; // sibling iterator type

bool                          doCheckPKCS15 = true;
TreeTypeFS                    fs;
__gshared sc_card*            card;
__gshared void*               lh;
ft_cm_7_3_1_14_get_card_info  cm_7_3_1_14_get_card_info;
ft_acos5_64_short_select      acos5_64_short_select;
ft_uploadHexfile              uploadHexfile;


Tuple!(ushort, ubyte, ubyte) decompose(EFDB fdb, ub2 size_or_MRL_NOR) nothrow {
    with (EFDB)
    final switch (fdb) {
        case Purse_EF:            return Tuple!(ushort, ubyte, ubyte)(0,0,0) ;// TODO
        case MF, DF:              return Tuple!(ushort, ubyte, ubyte)(0,0,0);
        case RSA_Key_EF,
             Transparent_EF:      return Tuple!(ushort, ubyte, ubyte)(ub22integral(size_or_MRL_NOR),0,0);
        case Linear_Fixed_EF,
             Linear_Variable_EF,
             Cyclic_EF,
             CHV_EF,
             Sym_Key_EF,
             SE_EF:               return Tuple!(ushort, ubyte, ubyte)(0,size_or_MRL_NOR[0],size_or_MRL_NOR[1]);
    }
}

Tuple!(string, string, string) decompose_str(EFDB fdb, ub2 size_or_MRL_NOR) nothrow {
    import std.conv : to;
    with (EFDB)
    final switch (fdb) {
        case MF, DF:              return Tuple!(string, string, string)("0","0","0");
        case RSA_Key_EF,
             Transparent_EF:      return Tuple!(string, string, string)(ub22integral(size_or_MRL_NOR).to!string,"0","0");
        case Linear_Fixed_EF,
             Linear_Variable_EF,
             Cyclic_EF,
             CHV_EF,
             Sym_Key_EF,
             SE_EF,
             Purse_EF:            return Tuple!(string, string, string)((size_or_MRL_NOR[0]*size_or_MRL_NOR[1]).to!string,
                                      size_or_MRL_NOR[0].to!string, size_or_MRL_NOR[1].to!string);
    }
}


string file_type(int depth, EFDB fdb, ushort fid, ub2 size_or_MRL_NOR) { // acos5_64.d: enum EFDB : ubyte
    Tuple!(string, string, string) t = decompose_str(fdb, size_or_MRL_NOR);
    with (EFDB)
    final switch (fdb) {
    	case DF:                  return "DF";
    	case MF:                  return "MF";
    	case Transparent_EF:      return "wEF transparent, size "~t[0]~" B";// ~ msg;
    	case Linear_Fixed_EF:     return "wEF linear-fix, size "~t[0]~" ("~t[2]~"x"~t[1]~") B";
    	case Linear_Variable_EF:  return "wEF linear-var, size max. "~t[0]~" ("~t[2]~"x"~t[1]~" max.) B";
    	case Cyclic_EF:           return "wEF cyclic, size "~t[0]~" ("~t[2]~"x"~t[1]~") B";

    	case RSA_Key_EF:          return "iEF transparent, size "~t[0]~" B";
    	case CHV_EF:              return "iEF linear-fix, size "~t[0]~" ("~t[2]~"x"~t[1]~") B    Pin ("~ (depth==1? "global" : "local") ~ ")";
    	case Sym_Key_EF:          return "iEF linear-var, size max. "~t[0]~" ("~t[2]~"x"~t[1]~" max.) B    SymKeys ("~ (depth==1? "global" : "local") ~ ")";
    	case Purse_EF:            return "iEF cyclic ??, size "~t[0]~" ("~t[2]~"x"~t[1]~") B    Purse";
    	case SE_EF:               return "iEF linear-var, size max. "~t[0]~" ("~t[2]~"x"~t[1]~" max.) B    SecEnv of directory";
    }
}

int util_connect_card(sc_context* ctx, scope sc_card** cardp, const(char)* reader_id, int do_wait, int do_lock, int verbose) nothrow @trusted
{ // copy of tools/util.c:util_connect_card_ex

int is_string_valid_atr(const(char)* atr_str)
{ // copy of tools/is_string_valid_atr
    ubyte[SC_MAX_ATR_SIZE]  atr;
    size_t atr_len = atr.sizeof;

    if (sc_hex_to_bin(atr_str, atr.ptr, &atr_len))
        return 0;
    if (atr_len < 2)
        return 0;
    if (atr[0] != 0x3B && atr[0] != 0x3F)
        return 0;
    return 1;
}

    import core.stdc.errno;
    import core.stdc.stdlib : strtol;
    import core.stdc.string;
    import std.stdio;

    sc_reader*  reader, found;
    sc_card*    card;
    int r;

    if (do_wait) {
        uint event;

        if (sc_ctx_get_reader_count(ctx) == 0) {
            /*fprintf(stderr.getFP(),*/ assumeWontThrow(writeln("Waiting for a reader to be attached..."));
            r = sc_wait_for_event(ctx, SC_EVENT_READER_ATTACHED, &found, &event, -1, null);
            if (r < 0) {
                fprintf(assumeWontThrow(stderr.getFP()), "Error while waiting for a reader: %s\n", sc_strerror(r));
                return 3;
            }
            r = sc_ctx_detect_readers(ctx);
            if (r < 0) {
                fprintf(assumeWontThrow(stderr.getFP()), "Error while refreshing readers: %s\n", sc_strerror(r));
                return 3;
            }
        }
        fprintf(assumeWontThrow(stderr.getFP()), "Waiting for a card to be inserted...\n");
        r = sc_wait_for_event(ctx, SC_EVENT_CARD_INSERTED, &found, &event, -1, null);
        if (r < 0) {
            fprintf(assumeWontThrow(stderr.getFP()), "Error while waiting for a card: %s\n", sc_strerror(r));
            return 3;
        }
        reader = found;
    }
    else if (sc_ctx_get_reader_count(ctx) == 0) {
        fprintf(assumeWontThrow(stderr.getFP()), "No smart card readers found.\n");
        return 1;
    }
    else   {
        if (!reader_id) {
            uint i;
            /* Automatically try to skip to a reader with a card if reader not specified */
            for (i = 0; i < sc_ctx_get_reader_count(ctx); i++) {
                reader = sc_ctx_get_reader(ctx, i);
                if (sc_detect_card_presence(reader) & SC_READER_CARD_PRESENT) {
                    if (verbose)
                        fprintf(assumeWontThrow(stderr.getFP()), "Using reader with a card: %s\n", reader.name);
                    goto autofound;
                }
            }
            /* If no reader had a card, default to the first reader */
            reader = sc_ctx_get_reader(ctx, 0);
        }
        else {
            /* If the reader identifier looks like an ATR, try to find the reader with that card */
            if (is_string_valid_atr(reader_id))   {
                ubyte[SC_MAX_ATR_SIZE * 3]  atr_buf;
                size_t atr_buf_len = atr_buf.sizeof;
                uint i;

                sc_hex_to_bin(reader_id, atr_buf.ptr, &atr_buf_len);
                /* Loop readers, looking for a card with ATR */
                for (i = 0; i < sc_ctx_get_reader_count(ctx); i++) {
                    sc_reader* rdr = sc_ctx_get_reader(ctx, i);

                    if (!(sc_detect_card_presence(rdr) & SC_READER_CARD_PRESENT))
                        continue;
                    else if (rdr.atr.len != atr_buf_len)
                        continue;
                    else if (memcmp(rdr.atr.value.ptr, atr_buf.ptr, rdr.atr.len))
                        continue;

                    fprintf(assumeWontThrow(stderr.getFP()), "Matched ATR in reader: %s\n", rdr.name);
                    reader = rdr;
                    goto autofound;
                }
            }
            else   {
                const(char)*   endptr  = null;
                const(char)**  endptrptr = &endptr;
                uint num;

                errno = 0;
                num = cast(uint)strtol(reader_id, endptrptr, 0);
                if (!errno && endptr && *endptr == '\0')
                    reader = sc_ctx_get_reader(ctx, num);
                else
                    reader = sc_ctx_get_reader_by_name(ctx, reader_id);
            }
        }
autofound:
        if (!reader) {
            fprintf(assumeWontThrow(stderr.getFP()), "Reader \"%s\" not found (%i reader(s) detected)\n",
                    reader_id, sc_ctx_get_reader_count(ctx));
            return 1;
        }

        if (sc_detect_card_presence(reader) <= 0) {
            fprintf(assumeWontThrow(stderr.getFP()), "Card not present.\n");
            return 3;
        }
    }

    if (verbose)
        printf("Connecting to card in reader %s...\n", reader.name);
    r = sc_connect_card(reader, &card);
    if (r < 0) {
        fprintf(assumeWontThrow(stderr.getFP()), "Failed to connect to card: %s\n", sc_strerror(r));
        return 1;
    }

    if (verbose)
        printf("Using card driver %s.\n", card.driver.name);

	if (do_lock) {
        r = sc_lock(card);
        if (r < 0) {
            fprintf(assumeWontThrow(stderr.getFP()), "Failed to lock card: %s\n", sc_strerror(r));
            sc_disconnect_card(card);
            return 1;
        }
	}

    *cardp = card;
    lh = assumeWontThrow(Runtime.loadLibrary("libacos5_64.so")); // this works without path (at least on Linux), as it is loaded already
////    assumeWontThrow(writeln("Library libacos5_64.so handle: ", lh));
    assert(lh);

    cm_7_3_1_14_get_card_info = cast(ft_cm_7_3_1_14_get_card_info) dlsym(lh, "cm_7_3_1_14_get_card_info");
    char* error = dlerror();
    if (error)
    {
        printf("dlsym error cm_7_3_1_14_get_card_info: %s\n", error);
        exit(1);
    }
////    printf("cm_7_3_1_14_get_card_info() function is found\n");

    acos5_64_short_select = cast(ft_acos5_64_short_select) dlsym(lh, "acos5_64_short_select");
    error = dlerror();
    if (error)
    {
        printf("dlsym error acos5_64_short_select: %s\n", error);
        exit(1);
    }
////    printf("acos5_64_short_select() function is found\n");

    uploadHexfile = cast(ft_uploadHexfile) dlsym(lh, "uploadHexfile");
    error = dlerror();
    if (error)
    {
        printf("dlsym error uploadHexfile: %s\n", error);
        exit(1);
    }
////    printf("uploadHexfile() function is found\n");

    return 0;
} // util_connect_card


int enum_dir(int depth, sitTypeFS pos_parent, ref PKCS15Path_FileType[] collector)
{
    import std.stdio;
    import std.range : chunks;

    assert(pos_parent.node);
    assert(pos_parent.node.data.ptr);

    ubyte   fdb  = pos_parent.node.data[0];
    assert(fdb.among(EnumMembers!EFDB)); // [ EnumMembers!A ]
    ushort  fid = ub22integral(pos_parent.node.data[2..4]);
    ub2     size_or_MRL_NOR = pos_parent.node.data[4..6];
    ubyte   lcsi = pos_parent.node.data[7];
    AA["tree_fs"].SetAttributeId((fdb & 0x38) == 0x38? "ADDBRANCH" : "ADDLEAF",  depth, (format!" %04X  %s"(fid, file_type(depth, cast(EFDB)fdb, fid, size_or_MRL_NOR))).toStringz);
    int rv = (cast(iup.iup_plusD.Tree) AA["tree_fs"]).SetUserId(depth+1, pos_parent.node);
    assert(rv);
    AA["tree_fs"].SetAttributeId("TOGGLEVALUE", depth+1, lcsi==5? "ON" : "OFF");

    ubyte markedFileType = pos_parent.node.data[6];
    if (markedFileType<0xFF) {
        writefln("This node got PKCS#15-marked: 0x[ %(%02X %) ]", pos_parent.node.data);
        with (AA["tree_fs"])
        if (markedFileType.among(PKCS15_FILE_TYPE.PKCS15_DIR, PKCS15_FILE_TYPE.PKCS15_ODF)) {
            SetAttributeId("IMAGE",       depth+1, "IMGPAPER");
            string title = GetStringId ("TITLE", depth+1);
            SetStringId ("TITLE", depth+1, title~"    "~PKCS15_FILE_TYPE_NAME[markedFileType]);
        }
    }

    if (fdb.among(EFDB.CHV_EF, EFDB.Sym_Key_EF, EFDB.Purse_EF, EFDB.SE_EF))
        AA["tree_fs"].SetAttributeId("IMAGE",       depth+1, "IMGEMPTY");

	if ((fdb & 0x38) == 0x38) {
        sc_path path;
        int pos_parent_pathLen = pos_parent.node.data[1];
        sc_path_set(&path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, pos_parent.node.data.ptr+8, pos_parent_pathLen, 0, -1);

        if ((rv= sc_select_file(card, &path, null)) != SC_SUCCESS) {
            writeln("SELECT FILE failed: ", sc_strerror(rv).fromStringz);
            return rv;
        }

        ushort SW1SW2;
        ubyte dummy;
        if ((rv= cm_7_3_1_14_get_card_info(card, card_info_type.count_files_under_current_DF, 0, SW1SW2, dummy, null, 0, null)) != SC_SUCCESS) {
            writeln("FAILED: cm_7_3_1_14_get_card_info: count_files_under_current_DF");
            return rv;
        }
        foreach (ubyte fno; 0 .. cast(ubyte)SW1SW2) { // x"90 xx" ; XX is count files
            ub24 info; // acos will deliver 8 bytes: [FDB, DCB(always 0), FILE ID, FILE ID, SIZE or MRL, SIZE or NOR, SFI, LCSI]
            if ((rv= cm_7_3_1_14_get_card_info(card, card_info_type.File_Information, fno, SW1SW2, dummy, info, 0, null)) != SC_SUCCESS) {
                writeln("FAILED: cm_7_3_1_14_get_card_info: File_Information");
                return rv;
            }
            info[6] = 0xFF;
            if (!collector.empty && collector[0].path.equal(pos_parent.node.data[8..8+pos_parent.node.data[1]]~info[2..4]) ) {
//                assumeWontThrow(writefln("branch: ?, %(%02X %)", collector[0].path));
                import std.algorithm;
                if (depth==0 && info[0]==1) { // EF.DIR
//                    assumeWontThrow(writeln("branch: 1"));
                    ubyte expectedFileType = info[6] = collector[0].pkcs15FileType;
                    info[1] = 4;//cast(ubyte)(pos_parent.node.data[1]+2);
                    info[8..12] = collector[0].path[0..4];
                    collector = collector.remove(0);
                    ubyte detectedFileType = 0xFF;
//                    PKCS15Path_FileType[] pkcs15Extracted;
                    readFile_wrapped(info, pos_parent.node, expectedFileType, detectedFileType, true, collector);
//assumeWontThrow(writeln("detectedFileType: ", cast(PKCS15_FILE_TYPE)detectedFileType,", collector: ",collector));
                    assert(expectedFileType==detectedFileType);
                    // TODO mark previously appended childs, if required
                }
                else if (info[0]==0x38) { // EF.APP
//                    assumeWontThrow(writeln("branch: 2"));
                    ubyte expectedFileType = info[6] = collector[0].pkcs15FileType; // FIXME that assumes, there is 1 app only
                    info[1] = cast(ubyte)(pos_parent.node.data[1]+2);
                    info[8..8+info[1]] = collector[0].path[0..info[1]];
                    collector = collector.remove(0);
                    assert(collector.empty);
                    assert(PKCS15_FILE_TYPE.PKCS15_APPDF==expectedFileType);
                    uba path5031 = info[8..8+info[1]]~[ubyte(0x50), ubyte(0x31)];
                    collector ~= [ PKCS15Path_FileType( path5031, PKCS15_FILE_TYPE.PKCS15_ODF ) ];
                    uba path5032 = info[8..8+info[1]]~[ubyte(0x50), ubyte(0x32)];
                    collector ~= [ PKCS15Path_FileType( path5032, PKCS15_FILE_TYPE.PKCS15_TOKENINFO ) ];
//assumeWontThrow(writeln(collector));
                }
                else if (info[0]==1 && pos_parent.node.data[6]==PKCS15_FILE_TYPE.PKCS15_APPDF) { // EF.PKCS15_ODF
//                    assumeWontThrow(writeln("branch: 3"));
                    ubyte expectedFileType = info[6] = collector[0].pkcs15FileType;
                    info[1] = cast(ubyte)(pos_parent.node.data[1]+2);
                    info[8..8+info[1]] = collector[0].path[0..info[1]];
                    ubyte detectedFileType = 0xFF;
                    PKCS15Path_FileType[] pkcs15Extracted;
                    readFile_wrapped(info, pos_parent.node, expectedFileType, detectedFileType, true, collector);
//assumeWontThrow(writeln("detectedFileType: ", cast(PKCS15_FILE_TYPE)detectedFileType,", collector: ",collector));
                    collector = collector.remove(0);
                    assert(expectedFileType==detectedFileType);
//assumeWontThrow(writeln(collector));
                }
            }
            fs.append_child(pos_parent, info);
        }
        foreach_reverse (node, unUsed; fs.siblingRange(pos_parent.begin(), pos_parent.end())) {
            assert(node);
            int j = 8+pos_parent_pathLen;
            node.data[8..j] = pos_parent.node.data[8..j];
            node.data[j..j+2] = node.data[2..4];
            node.data[1] = cast(ubyte)(pos_parent_pathLen+2);
            assert(node.data[1] > 0  &&  node.data[1] <= 16  &&  node.data[1]%2 == 0);
            if ((rv= enum_dir(depth + 1, new sitTypeFS(node), collector)) != SC_SUCCESS)
                return rv;
        }
	}
	return 0;
}

/*
enum_dir does already some PKCS#15-related processing (but only what fits in the workflow of enum_dir: It doesn't jump back to files already processed as tree nodes):
read 2F00 EF.DIR -> mark e.g. 3F004100 as PKCS15_APPDF
  only if 3F004100 exists and is marked, then
    insert 3F0041005031 and 3F0041005032 and read PKCS15_ODF, store extracted in collector

this will do the remaining, based on the information collected in collector,
assuming, the files collected are children of e.g. 3F004100 as PKCS15_APPDF
*/
int post_process(ref PKCS15Path_FileType[] collector) {
    import std.stdio;

    TreeTypeFS.nodeType* appdf = fs.preOrderRange(fs.begin(), fs.end()).locate!"a[6]==b"(PKCS15_FILE_TYPE.PKCS15_APPDF);
    assert(appdf);
    // unroll/read the DF files
    sitTypeFS parent = new sitTypeFS(appdf);
    with (PKCS15_FILE_TYPE)
    foreach (TreeTypeFS.nodeType* nodeFS, unUsed; fs.siblingRange(parent.begin(), parent.end())) {
        ubyte len = nodeFS.data[1];
        assert(len>2 && len<=16 && len%2==0);
        ptrdiff_t  c_pos = countUntil!((a,b) => a.pkcs15FileType<=PKCS15_AODF && a.path.equal(b))(collector, nodeFS.data[8..8+len]);
//        assumeWontThrow(writefln("pos: %s,\t %(%02X %)", c_pos, pointer.data));
        if (c_pos>=0) {
            ubyte expectedFileType = nodeFS.data[6] = collector[c_pos].pkcs15FileType;
            assert(expectedFileType.among(EnumMembers!PKCS15_FILE_TYPE) && expectedFileType!=PKCS15_NONE);
            ubyte detectedFileType = 0xFF;
            readFile_wrapped(nodeFS.data, nodeFS, expectedFileType, detectedFileType, expectedFileType.among(PKCS15_AODF, PKCS15_SKDF)? false : true, collector);
            assert(detectedFileType.among(EnumMembers!PKCS15_FILE_TYPE));
            assert(expectedFileType==detectedFileType); // TODO think about changing to e.g. throw an exception and inform user what exactly is wrong
            // file xy was expected to have ASN.1 encoded content of PKCS#15 type z0, but the content inspection couldn't verify that (detected was PKCS#15 type z1)
            collector = collector.remove(c_pos);
            if (expectedFileType<0xFF) {
                writefln("This node got PKCS#15-marked: 0x[ %(%02X %) ]", nodeFS.data);
                with (cast(iup.iup_plusD.Tree) AA["tree_fs"]) {
                    int nodeID = GetId(nodeFS);
                    SetAttributeId("IMAGE", nodeID, expectedFileType<=PKCS15_AODF || expectedFileType.among(PKCS15_ODF, PKCS15_TOKENINFO, PKCS15_UNUSED) ? "IMGPAPER" : "IMGBLANK");
                    if (expectedFileType==detectedFileType) {
                        string title = GetStringId ("TITLE", nodeID);
                        SetStringId ("TITLE", nodeID, title~"    "~PKCS15_FILE_TYPE_NAME[expectedFileType]);
                    }
                }
            }
        }
    }
//    assumeWontThrow(writeln(collector));
    // read and mark the collector files; all files referring to others should have been processed already !
    with (PKCS15_FILE_TYPE)
    foreach (TreeTypeFS.nodeType* nodeFS, unUsed; fs.siblingRange(parent.begin(), parent.end())) {
        ubyte len = nodeFS.data[1];
        assert(len>2 && len<=16 && len%2==0);
        ptrdiff_t  c_pos = countUntil!((a,b) => a.pkcs15FileType>PKCS15_AODF && a.pkcs15FileType<PKCS15_NONE && a.path.equal(b))(collector, nodeFS.data[8..8+len]);
//        assumeWontThrow(writefln("pos: %s,\t %(%02X %)", c_pos, pointer.data));
        if (c_pos>=0) {
            ubyte expectedFileType = nodeFS.data[6] = collector[c_pos].pkcs15FileType;
            assert(expectedFileType.among(EnumMembers!PKCS15_FILE_TYPE) && expectedFileType!=PKCS15_NONE);
            ubyte detectedFileType = 0xFF;
            readFile_wrapped(nodeFS.data, nodeFS, expectedFileType, detectedFileType, false, collector);
            assert(detectedFileType.among(EnumMembers!PKCS15_FILE_TYPE));
//            assert(expectedFileType==detectedFileType); // TODO think about changing to e.g. throw an exception and inform user what exactly is wrong
            // file xy was expected to have ASN.1 encoded content of PKCS#15 type z0, but the content inspection couldn't verify that (detected was PKCS#15 type z0
            collector = collector.remove(c_pos);

            if (expectedFileType<0xFF) {
                writefln("This node got PKCS#15-marked: 0x[ %(%02X %) ]", nodeFS.data);
                with (cast(iup.iup_plusD.Tree) AA["tree_fs"]) {
                    int nodeID = GetId(nodeFS);
                    SetAttributeId("IMAGE", nodeID, expectedFileType<=PKCS15_AODF || expectedFileType.among(PKCS15_ODF, PKCS15_TOKENINFO, PKCS15_UNUSED) ? "IMGPAPER" : "IMGBLANK");
                    if (expectedFileType==detectedFileType || nodeFS.data[0]==EFDB.RSA_Key_EF) {
                        string title = GetStringId ("TITLE", nodeID);
                        SetStringId ("TITLE", nodeID, title~"    "~PKCS15_FILE_TYPE_NAME[expectedFileType]);
                    }
                }
            }
        }
    }
//    assumeWontThrow(writeln(collector));
    return 0;
}

/*
  calling acos5_64 exported function(s) directly requires a context/card handle from opensc
  will be logged to "/tmp/opensc-debug.log", section "acos5_64_gui"
  populate the gui tree of card file system
*/
int populate_tree_fs()
{
    int rv, id=1;
    with (AA["tree_fs"]) {
        SetAttribute("TITLE", " file system");  // 0  depends on ADDROOT's default==YES
        SetAttribute("TOGGLEVISIBLE", "NO");
    }
//// read 3F00 for correct '8byte info ! This will also make sure, we have a file system, otherwise return
    ub24  rootFS = [0x3F, 0x2, 0x3F, 0x0,  0x0, 0x0, 0xFF, 0x0,   0x3F, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]; // the last 2 bytes are incorrect
    fs = TreeTypeFS(rootFS);
//writefln("head(%s), head.nextSibling(%s), feet(%s), *head.nextSibling(%s)", fs.head, fs.head.nextSibling, fs.feet, *(fs.head.nextSibling)); // 0x[%(%02X %)]
//    ub8 info = [0x3F, 0, 0x3F, 0, 0,0,0,0]; // acos will deliver 8 bytes: [FDB, DCB(always 0), FILE ID, FILE ID, SIZE or MRL, SIZE or NOR, SFI, LCSI]
    auto pos_root = new sitTypeFS(fs.begin().node);

    uba path2F00 = [0x3F, 0x0, 0x2F, 0x0];
    PKCS15Path_FileType[] collector = new PKCS15Path_FileType[0]; // = [ PKCS15Path_FileType( path2F00, PKCS15_FILE_TYPE.PKCS15_DIR ) ];
    if (doCheckPKCS15)
        collector ~= PKCS15Path_FileType( path2F00, PKCS15_FILE_TYPE.PKCS15_DIR );
    rv = enum_dir(0,  pos_root.dup, collector);
    if (!collector.empty)
        rv = post_process(/*pos_root.dup,*/ collector);

	return rv;
}

ulong decodedLengthOctets(ubyte[] buf, size_t pos) nothrow {
/*
Start reading buf at specified location pos, indicating the startpos of Length octets
Length octets. There are two forms: short (for lengths between 0 and 127), and long definite (for lengths between 0 and 2^1008 -1).
    Short form. One octet. Bit 8 has value "0" and bits 7-1 give the length.
    Long form. Two to 127 octets. Bit 8 of first octet has value "1" and bits 7-1 give the number of additional length octets. Second and following octets give the length, base 256, most significant digit first.
offsetTable ~= min(cast(ushort) (offsetTable[$-1]+ decodedLengthOctets(buf, offsetTable[$-1]+1) ), size); // buf[ offsetTable[$-1] +1 ]  // 30 82 06 7C
*/
    assert(pos<buf.length);
    if ((buf[pos] & 0x80)==0)
        return buf[pos] +2;
    ubyte followBytes = buf[pos] & 0x0F;
    assert(followBytes<=8); // this is just because of current lack of implementation TODO this show handle >2 as well but there is currently only ub22integral, handling max 2
    assert(pos+followBytes<buf.length);
    return  ub82integral(buf[1+pos..1+pos+followBytes]) +followBytes+2;
}

void readFile_wrapped(ubyte[] info, TreeTypeFS.nodeType* pn, const ubyte expectedFileType, ref ubyte detectedFileType, bool doExtract, ref PKCS15Path_FileType[] collector) {
    import std.stdio;
    import std.range : chunks;
    import std.algorithm.iteration : uniq;

    assert(info[1]);
    int rv;
    foreach (ub2 fid2; chunks(info[8..8+info[1]], 2)) {
//        ubyte[MAX_FCI_GET_RESPONSE_LEN] rbuf;
        rv= acos5_64_short_select(card, null, fid2, false/*, rbuf*/);
//        assumeWontThrow(writefln("fci: 0X[ %(%02X %) ]", rbuf));
    }

    PKCS15Path_FileType[] pkcs15Extracted;
    ub2 fid2 = info[2..4];
    EFDB fdb2 = cast(EFDB) info[0];
    ub2     size_or_MRL_NOR = info[4..6];
/*
    assumeWontThrow(writeln(pos_parent.node)); // 7FC0B8C46700
    assumeWontThrow(writeln(fid2)); //  [0x2F, 0]
    assumeWontThrow(writeln(fdb2)); // Transparent_EF
    assumeWontThrow(writeln(decompose(fdb2, size_or_MRL_NOR)[0])); // 33
*/
    readFile(pn, fid2, fdb2, decompose(fdb2, size_or_MRL_NOR).expand, detectedFileType, pkcs15Extracted, doExtract);
//assumeWontThrow(writeln(detectedFileType, pkcs15Extracted));
    foreach (e; pkcs15Extracted.uniq!"a.path.equal(b.path)")
        collector ~= e;
//assumeWontThrow(writeln(collector));
} // readFile_wrapped

void readFile(TreeTypeFS.nodeType* pn, ub2 fid, EFDB fdb, ushort size, ubyte mrl, ubyte nor, ref ubyte PKCS15fileType, out PKCS15Path_FileType[] pkcs15Extracted, bool doExtract=false) nothrow
{
    import std.stdio;
    import std.range : slide, chunks/*, enumerate*/;
    import std.string : representation, fromStringz, toStringz;
//    assumeWontThrow(writeln("readFile(ub2 fid, EFDB fdb)"));
    with (EFDB) if (!fdb.among(Transparent_EF,  Linear_Fixed_EF, Linear_Variable_EF, SE_EF,  RSA_Key_EF))
        return;

    Handle h = AA["fs_text"];
    ubyte[] buf = new ubyte[size? size : mrl];
    ubyte* response;
    size_t responselen;
    int rv;
    ushort[] offsetTable = [0];

    with (EFDB)
    switch (fdb) {
        case Transparent_EF:
            rv = sc_read_binary(card, 0, buf.ptr, buf.length, 0 /*flags*/);
            assert(rv>0 && rv==buf.length);
            //assumeWontThrow(writefln("0x[%(%02X %)]", buf));
            AA["fs_text"].SetString("APPEND", " ");
            foreach (chunk; chunks(buf, 64)) {
                //assumeWontThrow(writefln("0x[%(%02X %)]", chunk));
                AA["fs_text"].SetString("APPEND",  assumeWontThrow(format!"%(%02X %)"(chunk)));
            }

            while (offsetTable[$-1] < size  &&  buf[offsetTable[$-1]] != 0)
                offsetTable ~= min(cast(ushort) (offsetTable[$-1]+ decodedLengthOctets(buf, offsetTable[$-1]+1) ), size);
            if (buf[0] == 0)
                return;
            break;
        case Linear_Fixed_EF, Linear_Variable_EF, SE_EF:
            foreach (rec_idx; 1 .. 1+nor) {
                buf[] = 0;
                rv = sc_read_record(card, rec_idx, buf.ptr, buf.length, 0 /*flags*/);
                assert(rv>0 && rv==buf.length);
                //assumeWontThrow(writefln("0x[%(%02X %)]", buf));
                AA["fs_text"].SetString("APPEND", "Record "~rec_idx.to!string);
                foreach (chunk; chunks(buf, 64))
                    AA["fs_text"].SetString("APPEND",  assumeWontThrow(format!"%(%02X %)"(chunk)));
            }
            return;
        case RSA_Key_EF:
            if ((rv= sc_get_data(card, 0, buf.ptr, buf.length)) != buf.length) return;
            AA["fs_text"].SetString("APPEND", " ");
            foreach (chunk; chunks(buf, 64)) {
                //assumeWontThrow(writefln("0x[%(%02X %)]", chunk));
                AA["fs_text"].SetString("APPEND",  assumeWontThrow(format!"%(%02X %)"(chunk)));
            }
//            assert(rv==buf.length /*rv>0 && rv <= buf.length*/);
//            assumeWontThrow(writefln("0x[%(%02X %)]", buf));
//            foreach (chunk; chunks(buf, 64))
//                assumeWontThrow(writefln("0x[%(%02X %)]", chunk));
            if (buf[0] != 0  ||  buf[1] == 0)
                return;
            //assumeWontThrow(writeln(RSA_public_openssh_formatted(fid, buf)));
            AA["fs_text_asn1"].SetStringVALUE(RSA_public_openssh_formatted(fid, buf));
            {
                sc_path path;
                sc_path_set(&path, SC_PATH_TYPE.SC_PATH_TYPE_PATH, pn.data.ptr+8, pn.data[1], 0, -1);
                if ((rv= card.ops.read_public_key(card, SC_ALGORITHM_RSA, &path, 0, decode_key_RSA_ModulusBitLen(buf[1]), &response, &responselen)) != SC_SUCCESS) return;
                offsetTable ~= cast(ushort)responselen;
                //assumeWontThrow(writefln("0x[%(%02X %)]", response[0..responselen]));
            }

    		break;
    	default:
        	rv = -1;
    		break;
    }


    import asn1.constants;
    import std.conv : ConvException;
    import std.stdio : write, writeln, writefln, stdin;
    import std.utf : UTFException;


    string stringifyUniversalValue (DERElement element) nothrow
    {
      import std.conv : text;
      try
        switch (element.tagNumber)
        {
            case (0u):  return "END OF CONTENT";
            case (1u):  return (element.boolean ? "TRUE" : "FALSE");
            case (2u):  return text(element.integer!ptrdiff_t);
            case (3u):  return text(element.bitString); //"BIT STRING";
            case (4u):  return toHexString(element.octetString);// text(element.octetString);
            case (5u):  return "NULL";
            case (6u):  return element.objectIdentifier.toString();
            case (7u):  return element.objectDescriptor;
            case (8u):  return "EXTERNAL"; // This should never be executed.
            case (9u):  return text(element.realNumber!double);
            case (10u): return text(element.enumerated!ptrdiff_t);
            case (11u): return "EmbeddedPDV"; // This should never be executed.
            case (12u): return element.utf8String;
            case (13u): return ("RELATIVE OID: " ~ text(element.value));
            case (14u): return "!!! INVALID TYPE : RESERVED 14 !!!";
            case (15u): return "!!! INVALID TYPE : RESERVED 15 !!!";
            case (16u): return "SEQUENCE"; // This should never be executed.
            case (17u): return "SET"; // This should never be executed.
            case (18u): return element.numericString;
            case (19u): return element.printableString;
            case (20u): return text(element.teletexString);
            case (21u): return text(element.videotexString);
            case (22u): return element.ia5String;
            case (23u): return element.utcTime.toISOString();
            case (24u): return element.generalizedTime.toISOString();
            case (25u): return element.graphicString;
            case (26u): return element.visibleString;
            case (27u): return element.generalString;
            case (28u): return "[ UniversalString that cannot be displayed. ]";
            case (29u): return "CharacterString"; // This should never be executed.
            case (30u): return "[ BMPString that cannot be displayed. ]";
            case (31u): return "!!! INVALID TYPE : UNDEFINED 31 !!!";
            default: return "!!! INVALID TYPE : tagNumber above 31 !!!";
        }
      catch(Exception e) { return ""; }
    }

    void display (DERElement element, ubyte indentation, ref ubyte PKCS15fileType, ref PKCS15Path_FileType[] pkcs15Extracted, bool doExtract, bool start=false) nothrow
    {
        PKCS15Path_FileType[] pkcs15ExtractedNew;
        detectPattern(element, PKCS15fileType, pkcs15ExtractedNew, doExtract, start);
        pkcs15Extracted ~= pkcs15ExtractedNew;
        string tagClassString = "";
        bool universal = false;
        switch (element.tagClass)
        {
            case (ASN1TagClass.universal):
            {
                tagClassString = "UNIV";
                universal = true;
                break;
            }
            case (ASN1TagClass.application):
            {
                tagClassString = "APPL";
                break;
            }
            case (ASN1TagClass.contextSpecific):
            {
                tagClassString = "CTXT";
                break;
            }
            case (ASN1TagClass.privatelyDefined):
            {
                tagClassString = "PRIV";
                break;
            }
            default: assert(0, "Impossible tagClass encountered!");
        }

        char[] indents;
        indents.length = indentation;
        indents[0 .. $] = ' ';

        if (element.construction == ASN1Construction.primitive)
        {
            if (universal) {
//                assumeWontThrow(writefln("%s[ %s %d ] : %s", cast(string) indents, tagClassString, element.tagNumber, stringifyUniversalValue(element)));
                AA["fs_text_asn1"].SetString("APPEND", assumeWontThrow(format!"%s[ %s %d ] : %s"(cast(string) indents, tagClassString, element.tagNumber, stringifyUniversalValue(element))));
            }
            else {
//                assumeWontThrow(writefln("%s[ %s %d ] : %(%02X %)", cast(string) indents, tagClassString, element.tagNumber, element.value));
                AA["fs_text_asn1"].SetString("APPEND", assumeWontThrow(format!"%s[ %s %d ] : %(%02X %)"(cast(string) indents, tagClassString, element.tagNumber, element.value)));
            }
        }
        else
        {
//            assumeWontThrow(writefln("%s[ %s %d ] :", cast(string) indents, tagClassString, element.tagNumber));
            AA["fs_text_asn1"].SetString("APPEND", assumeWontThrow(format!"%s[ %s %d ] :"(cast(string) indents, tagClassString, element.tagNumber)));
            indentation += 4;
            ubyte[] value = element.value.dup;
            DERElement[] subs;
            size_t i = 0u;
          try {
            while (i < value.length)
                subs ~= new DERElement(i, value);

            foreach (sub; subs)
            {
                display(new DERElement(element.value), indentation, PKCS15fileType/*, pathExtracted*/, pkcs15Extracted, doExtract);
            }
          }
          catch (Exception e) {}
        }
        indentation -= 4;
    } // display

    int main_envelope(ubyte[] data, bool doExtract) nothrow
    {
        enum ReturnValue : int
        {
            success = 0,
            elementTerminatedPrematurely = 1,
            invalidEncodedValue = 2,
            unexpectedException = int.max
        }
        DERElement[] tops;

        try
        {
            while (data.length > 0u)
                tops ~= new DERElement(data);
        }
        catch (ASN1ValueSizeException e)
        {
            assumeWontThrow(writeln("\n", e.msg, "\n"));
            return ReturnValue.elementTerminatedPrematurely;
        }
        catch (ASN1Exception e)
        {
            assumeWontThrow(writeln("\n", e.msg, "\n"));
            return ReturnValue.invalidEncodedValue;
        }
        catch (Exception e)
        {
            assumeWontThrow(writeln("\n", e.msg, "\n"));
            return ReturnValue.unexpectedException;
        }

        foreach (i, top; tops)
        {
            try
            {
                AA["fs_text_asn1"].SetString("APPEND", " ");
                display(top, 0u, PKCS15fileType/*, pathExtracted*/, pkcs15Extracted, doExtract, true);
            }
            catch (ASN1ValueSizeException e)
            {
                assumeWontThrow(writeln("\n", e.msg, "\n"));
                return ReturnValue.elementTerminatedPrematurely;
            }
            catch (ASN1Exception e)
            {
                assumeWontThrow(writeln("\n", e.msg, "\n"));
                return ReturnValue.invalidEncodedValue;
            }
            catch (Exception e)
            {
                assumeWontThrow(writeln("\n", e.msg, "\n"));
                return ReturnValue.unexpectedException;
            }
        }

        return ReturnValue.success;
    } // main_envelope

    assert(offsetTable.length>=2);
////    assumeWontThrow(writeln(offsetTable));
    foreach (sw; offsetTable.slide(2))
        rv = main_envelope(fdb==EFDB.Transparent_EF? buf[sw[0]..sw[1]] : response[0..responselen], doExtract);
} // readFile

/*
  Basically, it's not neccessary to do ASN.1 pattern detection of PKCS#15 files: It would suffice to start with EF(DIR) file 0x2F00 and follow where it points to.
  But as the content/internal structure of these essential PKCS#15 files might be wrong, it's a feature deemed valuable:
  Starting with EF(DIR) file 0x2F00 and following where it points to, the files are checked for a couple of patterns, and only if 1 matching remains,
  the file is recognized to be of that specific type, see enum PKCS15_FILE_TYPE
  In the file system tree, only those with a PKCS15_FILE_TYPE detected are marked by special IMAGE symbols, in order to visualize that.
  There are 2 different IMAGE symbols used:

  Also, some files that are pointed to by ..DF files like RSA private and public key files are marked that way, but the other internal elementary files are not, thus marking is reserved to

  TODO evaluate using the opensc parse functions, starting from sc_pkcs15_parse_df (why does that omit parsing SC_PKCS15_PUKDF_TRUSTED ?):
  They are avalable at least for/as:
  sc_pkcs15_decode_prkdf_entry  ->
  sc_pkcs15_decode_pukdf_entry
  sc_pkcs15_decode_skdf_entry
  sc_pkcs15_decode_cdf_entry
  sc_pkcs15_decode_dodf_entry
  sc_pkcs15_decode_aodf_entry

TODO
*/
void detectPattern(DERElement elem, ref ubyte PKCS15fileType, out PKCS15Path_FileType[] pkcs15Extracted, bool doExtract, const bool start) nothrow // top, i, tops, hint, ubyte[][] pointsToPath
{
    import std.stdio;

    static int         i;  // current ASN1patterns array index is i+ii
    static int[dim]    ii; // counts skipping optional values
    static bool[dim]   priv; // whether CommonObjectFlags OPTIONAL  is private // CommonObjectFlags ::= BIT STRING { private (0), modifiable (1) }
    static bool[dim]   pub;  // whether CommonObjectFlags OPTIONAL  is private // CommonObjectFlags ::= BIT STRING { private (0), modifiable (1) }
    static ubyte[dim]  detectResult = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    static ubyte[dim]  ctx;//       = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    if (start) {
        i  = 0;
        ii = ii.init;
        priv = priv.init;
        pub  = pub.init;
        detectResult = indexArray;//[ 9, 10, 11, 12, 15,   0, 1, 3, 4/*, 7*/, 8 ];
        ctx          = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    }
    scope(exit) ++i;
/* The task is to detect, what this special DER-encoded file is about, like e.g. identifying, if it's the EF(DIR) file exactly, or etc.
   It's done by comparing the sequence of tags with some known asn1-module patterns
   The result is an array of possible content, encoded as enum SC_PKCS15_DF + extended values
   If dim-count!"a==255"(detectResult[]) == 1, then it's identified exactly
*/
    struct ASN1patternElement {
        import std.algorithm.comparison : equal;

        bool               optional;
        bool               extract; // this is meańt to be used when analyzing PKCS#15 structure and will be set for path content then; e.g. for PrKDF it shall collect the pathes to PrivateRSAKeyFiles
        ASN1UniversalType  decodeAs;

        ASN1TagClass       tagClass;
        ASN1Construction   construction;
        size_t             tagNumber;
        string             what = "";
        ubyte[]            value;

        bool equals(DERElement der) const nothrow {
            return this.tagClass     == der.tagClass &&
                   this.construction == der.construction &&
                   this.tagNumber.among(der.tagNumber, 0xFFFF /* wildcard */);
        }
    }

    immutable ASN1patternElement[][dim] ASN1patterns = [
        [ //  PKCS15_RSAPublicKey   = 9,  // file 0x4131  (arbitrary, asn1-encoded public RSA key file) RSA_PUB
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence, "" }, // RSAPublicKey ::= SEQUENCE
            { false, false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer, "" }, // modulus  INTEGER,
            { false, false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer, "" }, // publicExponent  INTEGER
        ],
        [ //  EF(DIR)  10 : DIR       file 0x2F00
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.application, ASN1Construction.constructed,  1 }, // not optional for the first sequence, starting from second: YES
            { false, false, ASN1UniversalType.octetString, ASN1TagClass.application, ASN1Construction.primitive,   15, "aid" }, // aid    [APPLICATION 15] OCTET STRING,
            { true,  false, ASN1UniversalType.utf8String,  ASN1TagClass.application, ASN1Construction.primitive,   16, "label" }, // label  [APPLICATION 16] UTF8String OPTIONAL,
            { false, true,  ASN1UniversalType.octetString, ASN1TagClass.application, ASN1Construction.primitive,   17, "path" }, // path   [APPLICATION 17] OCTET STRING,
/*4*/       { true,  false, ASN1UniversalType.sequence,    ASN1TagClass.application, ASN1Construction.constructed, 19, "" }, // ddo    [APPLICATION 19] DDO OPTIONAL, // DDO ::= SEQUENCE
            { true,  false, ASN1UniversalType.objectIdentifier,  ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.objectIdentifier, "" }, // oid  OBJECT IDENTIFIER,
            { true,  false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence, "" }, // odfPath  Path OPTIONAL, // Path ::= SEQUENCE
            { true,  true,  ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString, "" }, // path  OCTET STRING,
            { true,  false, ASN1UniversalType.sequence,    ASN1TagClass.contextSpecific, ASN1Construction.constructed,  0, "" }, // tokenInfoPath [0] Path OPTIONAL, // Path ::= SEQUENCE
            { true,  true,  ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString, "" }, // path  OCTET STRING,
            { true,  false, ASN1UniversalType.sequence,    ASN1TagClass.contextSpecific, ASN1Construction.constructed,  1, "" }, // unusedPath    [1] Path OPTIONAL, // Path ::= SEQUENCE
            { true,  true,  ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString, "" }, // path  OCTET STRING,
        ],
        [ //  EF(ODF)  11 : ODF       file 0x5031
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.contextSpecific, ASN1Construction.constructed, 0xFFFF, ""  }, // not optional for the first sequence, starting from second: YES
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal,       ASN1Construction.constructed, ASN1UniversalType.sequence, "" }, // path  Path, // Path ::= SEQUENCE
            { false, true,  ASN1UniversalType.octetString, ASN1TagClass.universal,       ASN1Construction.primitive,   ASN1UniversalType.octetString, "path" }, // path  OCTET STRING,
        ],

        [ //  EF(CardInfo) : 12  PKCS15_TOKENINFO // file 0x5032
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // CardInfo ::= SEQUENCE
            { false, false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // version  INTEGER {v1(0),v2(1)} (v1|v2,...),
            { true,  false, ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString }, // serialNumber  OCTET STRING OPTIONAL,
            { true,  false, ASN1UniversalType.utf8String,  ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.utf8String }, // manufacturerID  Label OPTIONAL,
            { true,  false, ASN1UniversalType.utf8String,  ASN1TagClass.contextSpecific, ASN1Construction.primitive,  0 }, // label [0] Label OPTIONAL,
            { false, false, ASN1UniversalType.bitString,   ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.bitString }, // cardflags  CardFlags, // CardFlags ::= BIT STRING
            { true,  false, ASN1UniversalType.sequence,    ASN1TagClass.contextSpecific, ASN1Construction.constructed,  2 }, // supportedAlgorithms  [2] SEQUENCE OF AlgorithmInfo OPTIONAL,
            { true,  false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // AlgorithmInfo ::= SEQUENCE
            { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // reference Reference,
            { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // algorithm  CIO-ALGORITHM.&id({AlgorithmSet}), // &id INTEGER UNIQUE,
            { true,  false, ASN1UniversalType.nill,        ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.nill }, // parameters CIO-ALGORITHM.&Parameters({AlgorithmSet}{@algorithm}),
            { true,  false, ASN1UniversalType.bitString,   ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.bitString }, // supportedOperations CIO-ALGORITHM.&Operations({AlgorithmSet}{@algorithm}), // Operations ::= BIT STRING
            { true,  false, ASN1UniversalType.objectIdentifier,  ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.objectIdentifier }, // objId CIO-ALGORITHM.&objectIdentifier ({AlgorithmSet}{@algorithm}),
            { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // algRef Reference OPTIONAL

            { true,  false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // AlgorithmInfo ::= SEQUENCE
            { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // reference Reference,
            { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // algorithm  CIO-ALGORITHM.&id({AlgorithmSet}), // &id INTEGER UNIQUE,
            { true,  false, ASN1UniversalType.nill,        ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.nill }, // parameters CIO-ALGORITHM.&Parameters({AlgorithmSet}{@algorithm}),
            { true,  false, ASN1UniversalType.bitString,   ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.bitString }, // supportedOperations CIO-ALGORITHM.&Operations({AlgorithmSet}{@algorithm}), // Operations ::= BIT STRING
            { true,  false, ASN1UniversalType.objectIdentifier,  ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.objectIdentifier }, // objId CIO-ALGORITHM.&objectIdentifier ({AlgorithmSet}{@algorithm}),
            { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // algRef Reference OPTIONAL

            { true,  false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // AlgorithmInfo ::= SEQUENCE
            { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // reference Reference,
            { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // algorithm  CIO-ALGORITHM.&id({AlgorithmSet}), // &id INTEGER UNIQUE,
            { true,  false, ASN1UniversalType.nill,        ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.nill }, // parameters CIO-ALGORITHM.&Parameters({AlgorithmSet}{@algorithm}),
            { true,  false, ASN1UniversalType.bitString,   ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.bitString }, // supportedOperations CIO-ALGORITHM.&Operations({AlgorithmSet}{@algorithm}), // Operations ::= BIT STRING
            { true,  false, ASN1UniversalType.objectIdentifier,  ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.objectIdentifier }, // objId CIO-ALGORITHM.&objectIdentifier ({AlgorithmSet}{@algorithm}),
            { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // algRef Reference OPTIONAL
        ],

        [ //  PKCS15_CERT           = 15,
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // Certificate  ::=  SIGNED{TBSCertificate} // SIGNED{ToBeSigned} ::= SEQUENCE {
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // toBeSigned           TBSCertificate  ::=  SEQUENCE  {
            { true,  false, ASN1UniversalType.sequence,    ASN1TagClass.contextSpecific, ASN1Construction.constructed,  0 }, // version         [0]  Version DEFAULT v1, // Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
            { false, false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // version         CertificateSerialNumber, // CertificateSerialNumber  ::=  INTEGER

            { false, false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // serialNumber         CertificateSerialNumber, // CertificateSerialNumber  ::=  INTEGER
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // signature  AlgorithmIdentifier{SIGNATURE-ALGORITHM, {SignatureAlgorithms}}, // SEQUENCE
            { false, false, ASN1UniversalType.objectIdentifier,  ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.objectIdentifier }, // algorithm   ALGORITHM-TYPE.&amp;id({AlgorithmSet}),
            { true,  false, ASN1UniversalType.nill,        ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.nill }, // parameters  ALGORITHM-TYPE.&amp;Params({AlgorithmSet}{@algorithm}) OPTIONAL
        ],

        [ //  EF(PrKDF)  SC_PKCS15_PRKDF          = 0,  => file 0x4112
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // not optional for the first sequence, starting from second: YES

            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // CommonObjectAttributes ::= SEQUENCE
            { true,  false, ASN1UniversalType.utf8String,  ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.utf8String }, // label   Label OPTIONAL, // Label ::= UTF8String (SIZE(0..pkcs15-ub-label))
            { true,  false, ASN1UniversalType.bitString,   ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.bitString }, // flags   CommonObjectFlags OPTIONAL, // CommonObjectFlags ::= BIT STRING { private (0), modifiable (1) }
            { true,  false, ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString }, // authId  Identifier OPTIONAL, // Identifier ::= OCTET STRING (SIZE (0..pkcs15-ub-identifier))
            { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // userConsent INTEGER (1..pkcs15-ub-userConsent) OPTIONAL,
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // CommonKeyAttributes ::= SEQUENCE
            { false, false, ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString }, // iD  Identifier, // Identifier ::= OCTET STRING (SIZE (0..pkcs15-ub-identifier))
            { false, false, ASN1UniversalType.bitString,   ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.bitString }, // usage  KeyUsageFlags, //KeyUsageFlags ::= BIT STRING
            { true,  false, ASN1UniversalType.boolean,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.boolean }, // native  BOOLEAN DEFAULT TRUE,
            { true,  false, ASN1UniversalType.bitString,   ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.bitString }, // accessFlags KeyAccessFlags OPTIONAL, // KeyAccessFlags ::= BIT STRING
            { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // keyReference Reference OPTIONAL,
//          { true,  false, ASN1UniversalType.generalizedTime, ASN1TagClass.universal, ASN1Construction.primitive, ASN1UniversalType.generalizedTime }, // startDate  GeneralizedTime OPTIONAL,
//          { true,  false, ASN1UniversalType.generalizedTime, ASN1TagClass.contextSpecific, ASN1Construction.primitive,   0 }, // endDate  [0] GeneralizedTime OPTIONAL,
//          { true,  false, ASN1UniversalType.sequence,        ASN1TagClass.contextSpecific, ASN1Construction.constructed, 1 }, // algReference [1] SEQUENCE OF Reference OPTIONAL,
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.contextSpecific, ASN1Construction.constructed,  1 }, // PKCS15Object. typeAttributes  [1] TypeAttributes
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // PrivateRSAKeyAttributes ::= SEQUENCE
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // path  Path OPTIONAL, // Path ::= SEQUENCE
            { false, true,  ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString }, // path  OCTET STRING,
            { false, false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // modulusLength  INTEGER, -- modulus length in bits, e.g. 1024
//            { true,  false, ASN1UniversalType.,          ASN1TagClass.universal, ASN1Construction.primitive,      }, // keyInfo  KeyInfo {NULL, PublicKeyOperations} OPTIONAL, // KeyInfo {ParameterType, OperationsType} ::= CHOICE {
//          { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // reference  Reference,
        ],

        [ //  EF(PuKDF)  SC_PKCS15_PUKDF          = 1,  => file 0x4113
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // not optional for the first sequence, starting from second: YES

            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // CommonObjectAttributes ::= SEQUENCE
            { true,  false, ASN1UniversalType.utf8String,  ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.utf8String }, // label   Label OPTIONAL, // Label ::= UTF8String (SIZE(0..pkcs15-ub-label))
            { true,  false, ASN1UniversalType.bitString,   ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.bitString }, // flags   CommonObjectFlags OPTIONAL, // CommonObjectFlags ::= BIT STRING { private (0), modifiable (1) }
            { true,  false, ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString }, // authId  Identifier OPTIONAL, // Identifier ::= OCTET STRING (SIZE (0..pkcs15-ub-identifier))
            { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // userConsent INTEGER (1..pkcs15-ub-userConsent) OPTIONAL,
//          { true,  false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // TODO accessControlRules SEQUENCE SIZE (1..MAX) OF AccessControlRule OPTIONAL
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // CommonKeyAttributes ::= SEQUENCE
            { false, false, ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString }, // iD  Identifier, // Identifier ::= OCTET STRING (SIZE (0..pkcs15-ub-identifier))
            { false, false, ASN1UniversalType.bitString,   ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.bitString }, // usage  KeyUsageFlags, //KeyUsageFlags ::= BIT STRING
            { true,  false, ASN1UniversalType.boolean,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.boolean }, // native  BOOLEAN DEFAULT TRUE,
            { true,  false, ASN1UniversalType.bitString,   ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.bitString }, // accessFlags KeyAccessFlags OPTIONAL, // KeyAccessFlags ::= BIT STRING
            { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // keyReference Reference OPTIONAL,
//          { true,  false, ASN1UniversalType.generalizedTime, ASN1TagClass.universal, ASN1Construction.primitive, ASN1UniversalType.generalizedTime }, // startDate  GeneralizedTime OPTIONAL,
//          { true,  false, ASN1UniversalType., ASN1TagClass.contextSpecific, ASN1Construction.primitive, 0 }, // endDate  [0] GeneralizedTime OPTIONAL,
//          { true,  false, ASN1UniversalType.sequence,        ASN1TagClass.contextSpecific, ASN1Construction.constructed, 1 }, // algReference [1] SEQUENCE OF Reference OPTIONAL,
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.contextSpecific, ASN1Construction.constructed,  1 }, // PKCS15Object. typeAttributes  [1] TypeAttributes
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // PrivateRSAKeyAttributes ::= SEQUENCE
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // path  Path OPTIONAL, // Path ::= SEQUENCE
            { false, true,  ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString }, // path  OCTET STRING,
            { false, false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // modulusLength  INTEGER, -- modulus length in bits, e.g. 1024
//          { true,  false, ASN1UniversalType.,            ASN1TagClass.universal, ASN1Construction.primitive,      }, // keyInfo  KeyInfo {NULL, PublicKeyOperations} OPTIONAL, // KeyInfo {ParameterType, OperationsType} ::= CHOICE {
//          { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // reference  Reference,
        ],

        [ //  EF(SKDF)  SC_PKCS15_SKDF           = 3,  => file 0x4114
//        des3Key			[4] SecretKeyObject {GenericSecretKeyAttributes},
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.contextSpecific, ASN1Construction.constructed, 0xFFFF }, // not optional for the first sequence, starting from second: YES

            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // CommonObjectAttributes ::= SEQUENCE
            { true,  false, ASN1UniversalType.utf8String,  ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.utf8String }, // label   Label OPTIONAL, // Label ::= UTF8String (SIZE(0..pkcs15-ub-label))
/* !! */    { false, false, ASN1UniversalType.bitString,   ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.bitString }, // flags   CommonObjectFlags OPTIONAL, // CommonObjectFlags ::= BIT STRING { private (0), modifiable (1) }
            { true,  false, ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString }, // authId  Identifier OPTIONAL, // Identifier ::= OCTET STRING (SIZE (0..pkcs15-ub-identifier))
/*5*/       { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // userConsent INTEGER (1..pkcs15-ub-userConsent) OPTIONAL,
//          { true,  false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // TODO accessControlRules SEQUENCE SIZE (1..MAX) OF AccessControlRule OPTIONAL
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // CommonKeyAttributes ::= SEQUENCE
            { false, false, ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString }, // iD  Identifier, // Identifier ::= OCTET STRING (SIZE (0..pkcs15-ub-identifier))
            { false, false, ASN1UniversalType.bitString,   ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.bitString }, // usage  KeyUsageFlags, //KeyUsageFlags ::= BIT STRING
/*9*/       { true,  false, ASN1UniversalType.boolean,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.boolean }, // native  BOOLEAN DEFAULT TRUE,
            { true,  false, ASN1UniversalType.bitString,   ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.bitString }, // accessFlags KeyAccessFlags OPTIONAL, // KeyAccessFlags ::= BIT STRING
            { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // keyReference Reference OPTIONAL,
/*12*/      { true,  false, ASN1UniversalType.generalizedTime, ASN1TagClass.universal, ASN1Construction.primitive, ASN1UniversalType.generalizedTime }, // startDate  GeneralizedTime OPTIONAL,
/*13*/      { true,  false, ASN1UniversalType.generalizedTime, ASN1TagClass.contextSpecific, ASN1Construction.primitive, 0 }, // endDate  [0] GeneralizedTime OPTIONAL,
//          { true,  false, ASN1UniversalType.sequence,        ASN1TagClass.contextSpecific, ASN1Construction.constructed, 1 }, // algReference [1] SEQUENCE OF Reference OPTIONAL,

            { true,  false, ASN1UniversalType.sequence,    ASN1TagClass.contextSpecific, ASN1Construction.constructed,  0 }, // commonSecretKeyAttributes  [0] CommonSecretKeyAttributes OPTIONAL ::= SEQUENCE
            { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // keyLen INTEGER OPTIONAL, -- keylength (in bits)

            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.contextSpecific, ASN1Construction.constructed,  1 }, // PKCS15Object. typeAttributes  [1] TypeAttributes
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // GenericSecretKeyAttributes ::= SEQUENCE
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // path  Path OPTIONAL, // Path ::= SEQUENCE
            { false, true,  ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString }, // path  OCTET STRING,
            { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // index INTEGER (0..pkcs15-ub-index) OPTIONAL,
            { true,  false, ASN1UniversalType.integer,     ASN1TagClass.contextSpecific, ASN1Construction.primitive, 0 }, // length [0] INTEGER (0..pkcs15-ub-index) OPTIONAL
        ],


        [ //  EF(CDF)   SC_PKCS15_CDF,           = 4,  => file 0x4132
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // not optional for the first sequence, starting from second: YES

            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // CommonObjectAttributes ::= SEQUENCE
            { true,  false, ASN1UniversalType.utf8String,  ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.utf8String }, // label   Label OPTIONAL, // Label ::= UTF8String (SIZE(0..pkcs15-ub-label))
            { true,  false, ASN1UniversalType.bitString,   ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.bitString }, // flags   CommonObjectFlags OPTIONAL, // CommonObjectFlags ::= BIT STRING { private (0), modifiable (1) }
            { true,  false, ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString }, // authId  Identifier OPTIONAL, // Identifier ::= OCTET STRING (SIZE (0..pkcs15-ub-identifier))
//          { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // userConsent INTEGER (1..pkcs15-ub-userConsent) OPTIONAL,
//          { true,  false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // TODO accessControlRules SEQUENCE SIZE (1..MAX) OF AccessControlRule OPTIONAL
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // CommonCertificateAttributes ::= SEQUENCE
            { false, false, ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString }, // iD  Identifier,
//            { true,  false, ASN1UniversalType.boolean,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.boolean }, // authority  BOOLEAN DEFAULT FALSE,
//          { true,  false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // identifier CredentialIdentifier {{KeyIdentifiers}} OPTIONAL,
//          { true,  false, ASN1UniversalType.sequence,    ASN1TagClass.contextSpecific, ASN1Construction.constructed,  1 }, // trustedUsage  [1] Usage OPTIONAL, // Usage ::= SEQUENCE
//          { true,  false, ASN1UniversalType.sequence,    ASN1TagClass.contextSpecific, ASN1Construction.constructed,  2 }, // identifiers   [2] SEQUENCE OF CredentialIdentifier {{KeyIdentifiers}} OPTIONAL,
            { true,  false, ASN1UniversalType.boolean,     ASN1TagClass.contextSpecific, ASN1Construction.primitive,    3 }, // implicitTrust [3] BOOLEAN DEFAULT FALSE
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.contextSpecific, ASN1Construction.constructed,  1 }, // PKCS15Object. typeAttributes  [1] X509CertificateAttributes
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // X509CertificateAttributes ::= SEQUENCE
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // value  ObjectValue { Certificate }, // indirect  ReferencedValue {Certificate}, // path  Path,
            { false, true,  ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString }, // path  OCTET STRING,
        ],

        [ //  EF(AODF)  SC_PKCS15_AODF           = 8  => file 0x4111
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // not optional for the first sequence, starting from second: YES

            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // CommonObjectAttributes ::= SEQUENCE
            { true,  false, ASN1UniversalType.utf8String,  ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.utf8String }, // label   Label OPTIONAL, // Label ::= UTF8String (SIZE(0..pkcs15-ub-label))
            { true,  false, ASN1UniversalType.bitString,   ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.bitString }, // flags   CommonObjectFlags OPTIONAL, // CommonObjectFlags ::= BIT STRING { private (0), modifiable (1) }
//          { true,  false, ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString }, // authId  Identifier OPTIONAL, // Identifier ::= OCTET STRING (SIZE (0..pkcs15-ub-identifier))
//          { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // userConsent INTEGER (1..pkcs15-ub-userConsent) OPTIONAL,
//          { true,  false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // TODO accessControlRules SEQUENCE SIZE (1..MAX) OF AccessControlRule OPTIONAL
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // CommonAuthenticationObjectAttributes ::= SEQUENCE
            { false, false, ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString }, // authId Identifier,
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.contextSpecific, ASN1Construction.constructed,  1 }, // PKCS15Object. typeAttributes  [1] TypeAttributes
            { false, false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // PinAttributes ::= SEQUENCE
            { false, false, ASN1UniversalType.bitString,   ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.bitString }, // pinFlags  PinFlags, // PinFlags ::= BIT STRING
            { false, false, ASN1UniversalType.enumerated,  ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.enumerated }, // pinType PinType, // PinType ::= ENUMERATED {bcd, ascii-numeric, utf8, ..., half-nibble-bcd, iso9564-1}
            { false, false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // minLength  INTEGER (pkcs15-lb-minPinLength..pkcs15-ub-minPinLength),
            { false, false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // storedLength INTEGER (0..pkcs15-ub-storedPinLength),
            { true,  false, ASN1UniversalType.integer,     ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.integer }, // maxLength  INTEGER OPTIONAL,
            { false, false, ASN1UniversalType.integer,     ASN1TagClass.contextSpecific, ASN1Construction.primitive, 0 }, // , pinReference [0] Reference DEFAULT 0, // Reference ::= INTEGER (0..pkcs15-ub-reference)
            { true,  false, ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString }, // padChar  OCTET STRING (SIZE(1)) OPTIONAL,
//          { true,  false, ASN1UniversalType.generalizedTime, ASN1TagClass.universal, ASN1Construction.primitive, ASN1UniversalType.generalizedTime }, // lastPinChange GeneralizedTime OPTIONAL,
            { true,  false, ASN1UniversalType.sequence,    ASN1TagClass.universal, ASN1Construction.constructed, ASN1UniversalType.sequence }, // path  Path OPTIONAL, // Path ::= SEQUENCE
            { true,  true,  ASN1UniversalType.octetString, ASN1TagClass.universal, ASN1Construction.primitive,   ASN1UniversalType.octetString }, // path  OCTET STRING,
        ],
    ];

    bool unique() { return dim-count!"a==255"(detectResult[]) == 1; }
    bool  bique() { return dim-count!"a==255"(detectResult[]) == 2; }

    with (PKCS15_FILE_TYPE)
    foreach (n; 0 .. dim) {
        if (n==idx(PKCS15_CERT) && detectResult[n]==PKCS15_CERT && unique)
            break;
loop_optional:
        if (detectResult[n] == 0xFF  ||  i + ii[n] >= ASN1patterns[n].length)
            continue;

        with (ASN1patterns[n][i+ii[n]])
        if   (ASN1patterns[n][i+ii[n]].equals(elem)) {
//            assumeWontThrow(writefln("Y %s:%s, tag %s: 0x[%(%02X %)] :", n, i+ii[n], elem.tagNumber, elem.value));
            if (n==idx(PKCS15_ODF) && i+ii[n] == 0 && elem.tagNumber.among(0,1,2,3,4,5,6,7,8))
                ctx[n] = cast(ubyte)elem.tagNumber;

            if (n==idx(PKCS15_PRKDF) && i+ii[n] == 3 && elem.tagClass==ASN1TagClass.universal && elem.construction==ASN1Construction.primitive && elem.tagNumber==ASN1UniversalType.bitString &&
                (elem.value[$-1] & 0x80))
                priv[n] = true;
            if (n==idx(PKCS15_PUKDF) && i+ii[n] == 3 && elem.tagClass==ASN1TagClass.universal && elem.construction==ASN1Construction.primitive && elem.tagNumber==ASN1UniversalType.bitString &&
                (elem.value[$-1] & 0x80)==0)
                pub[n] = true;
            ubyte other = idx(PKCS15_PUKDF);
            if (n==idx(PKCS15_PRKDF) && i+ii[n]==14 && priv[n] && !priv[other] && detectResult[other]!=0xFF && detectResult[n]!=0xFF)
                detectResult[other] = 0xFF;
            other = idx(PKCS15_PRKDF);
            if (n==idx(PKCS15_PUKDF) && i+ii[n]==14 && pub[n]  && !pub[other]  && detectResult[other]!=0xFF && detectResult[n]!=0xFF)
                detectResult[other] = 0xFF;

            if (doExtract && extract && decodeAs==ASN1UniversalType.octetString && (unique || (bique && detectResult[idx(PKCS15_ODF)]==PKCS15_ODF && detectResult[idx(PKCS15_SKDF)]==PKCS15_SKDF && ctx[idx(PKCS15_ODF)]!=2 ) ) ) {
                if (bique)
                    detectResult[idx(PKCS15_SKDF)] = 0xFF;

                assert(n==minIndex(detectResult[]));
                PKCS15_FILE_TYPE pft;
                with (PKCS15_FILE_TYPE)
                switch (n) {
                	case  idx(PKCS15_RSAPublicKey): pft = PKCS15_RSAPublicKey;  break;
                	case  idx(PKCS15_DIR):          pft = PKCS15_APPDF;         break; //       PKCS15_ODF, PKCS15_TOKENINFO, PKCS15_UNUSED
                	case  idx(PKCS15_ODF):          pft = cast(PKCS15_FILE_TYPE) ctx[n]; break;
                	case  idx(PKCS15_TOKENINFO):    pft = PKCS15_NONE;          break;
                	case  idx(PKCS15_CERT):         pft = PKCS15_CERT;          break;

                	case  idx(PKCS15_PRKDF): pft = PKCS15_RSAPrivateKey; break;
                	case  idx(PKCS15_PUKDF): pft = PKCS15_RSAPublicKey;  break;
                	case  idx(PKCS15_SKDF):  pft = PKCS15_APPDF;         break; // Deviating from PKCS#15, this is handled same as for idx(PKCS15_AODF)
                	case  idx(PKCS15_CDF):   pft = PKCS15_CERT;          break;
                	case  idx(PKCS15_AODF):  pft = PKCS15_APPDF;         break; // the pin file path doesn't get encoded, but it's enclosing DF

                	default: pft = PKCS15_NONE;          break;
                }
                pkcs15Extracted ~= PKCS15Path_FileType(elem.value.dup, pft);
            }
        }
        else if (optional) {
//            assumeWontThrow(writefln("optional %s:%s", n, i+ii[n]));
            ++ii[n];
            goto loop_optional;
        }
        else {
//            assumeWontThrow(writefln("N %s:%s, tag %s: 0x[%(%02X %)] :", n, i+ii[n], elem.tagNumber, elem.value));
            detectResult[n] = 0xFF;
        }
    }

    PKCS15fileType =  unique ? minElement(detectResult[]) : 0xFF;
} // detectPattern

string RSA_public_openssh_formatted(ub2 fid, scope const ubyte[] rsa_raw_acos5_64) nothrow
{
    import std.conv : to;
    import std.base64 : Base64;
    import std.digest.md;

    if (rsa_raw_acos5_64[0] != 0  ||  rsa_raw_acos5_64[1] == 0) // no public key
        return "";
    string prolog;
    ubyte[] pre_openssh = [0,0,0,7, 0x73, 0x73, 0x68, 0x2D, 0x72, 0x73, 0x61,
                           0,0,0,0];
    bool valid = rsa_raw_acos5_64[4] == 3;
    prolog = "\nThis is a "~(valid?"":"in")~"valid "~to!string(rsa_raw_acos5_64[1]*128)~" bit public RSA key with file id 0x " ~ toHexString!(Order.increasing,LetterCase.upper)(fid)~
        " (it's partner private key file id is 0x " ~ toHexString!(Order.increasing,LetterCase.upper)(rsa_raw_acos5_64[2..4]) ~ ") :\n\n";
    ptrdiff_t  e_len =  rsa_raw_acos5_64[5..21].countUntil!"a>0"; //16- rsa_raw_acos5_64[5..21].until!"a>0"[].length;
    assert(e_len != -1); // exponent MUST NOT be zero! e_len>=0 && e_len<=15
    e_len = 16 - e_len;
    pre_openssh[$-1] = cast(ubyte) e_len;
    ushort modLenBytes = rsa_raw_acos5_64[1]*16;
    assert(rsa_raw_acos5_64.length == 21+modLenBytes);
    pre_openssh ~= rsa_raw_acos5_64[21-e_len .. 21] ~ integral2ub!4(modLenBytes);
    if (rsa_raw_acos5_64[21] & 0x80) {
        pre_openssh ~= 0;
        ++pre_openssh[$-2];
    }
    pre_openssh ~= rsa_raw_acos5_64[21..$];
    string result = Base64.encode(pre_openssh);

    auto md5 = new MD5Digest();
    ubyte[] hash = md5.digest(pre_openssh);
    string fingerprint = toHexString!(LetterCase.lower)(hash);
//    assumeWontThrow(writeln(fingerprint)); // "2d 0d 76 4f 21 ea fb e1 27 98 f0 14 8b 56 35 0c"

    return prolog~"ssh-rsa "~result~ "  comment_file_" ~ toHexString!(Order.increasing,LetterCase.upper)(fid) ~
        "\n\nThe fingerprint(MD5) is: "~fingerprint;
}
