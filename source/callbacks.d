/*
 * Written in the D programming language, part of package acos5_64_gui.
 * callbacks.d: Callbacks file, based on IUP
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

module callbacks;

import core.runtime : Runtime;
import core.stdc.stdio : printf;
import std.stdio;
import std.string : /*fromStringz,*/ toStringz;
import std.exception : assumeWontThrow;//(expr, msg, file, line)
import std.algorithm.comparison : max, /*min, clamp, equal, mismatch,*/ among;
import std.algorithm.searching : maxElement, countUntil, canFind;
import std.traits : EnumMembers;
import std.conv : to;

import libopensc.opensc;
import libopensc.types;
import libopensc.errors;
import libopensc.log;

import iup.iup_plusD;

import libintl : _, __;

import util_general;// : ub22integral;
import acos5_64_shared;

import util_opensc : lh, card, TreeTypeFS, acos5_64_short_select, readFile, decompose, PKCS15Path_FileType, PKCS15_FILE_TYPE, fs, sitTypeFS,
    util_connect_card, connect_card, cm_7_3_1_14_get_card_info;


ub8 map2DropDown = [1, 2, 3, 4, 5, 6, 7, 8];


nothrow :


void populate_list_op_file_possible(TreeTypeFS.nodeType* pn, ub2 fid, EFDB fdb, ub2 size_or_MRL_NOR, ubyte lcsi, ub8 sac) {
    import std.string : empty;

    immutable string[7][6] textSCB_FileType = [
      [_("Delete Child"),   "Create EF",        "Create DF",        "Deactivate/Invalidate", "Activate/Rehabilitate", "Terminate/Lock", "Delete Self"], // DF/MF
      [_("Read"),           "Update/Erase",     "",                 "Deactivate/Invalidate", "Activate/Rehabilitate", "Terminate/Lock", "Delete Self"], // EF     binary
      [_("Read"),           "Update",           "",                 "Deactivate/Invalidate", "Activate/Rehabilitate", "Terminate/Lock", "Delete Self"], // EF_lin_fix/CHV record
      [_("Read"),           "Update/Append",    "",                 "Deactivate/Invalidate", "Activate/Rehabilitate", "Terminate/Lock", "Delete Self"], // EF_lin_var record
      [_("Read (Get Key)"), "Put Key",          "MSE/PSO Commands", "Deactivate/Invalidate", "Activate/Rehabilitate", "Terminate/Lock", "Delete Self"], // Key File
      [_("Read"),           "MSE Store/Delete", "MSE Restore",      "Deactivate/Invalidate", "Activate/Rehabilitate", "Terminate/Lock", "Delete Self"], // SE File
    ];

    int index_textSCB_FileType(EFDB fdb) {
        with (EFDB)
        final switch (fdb) {
            case MF, DF:              return 0;
            case Transparent_EF:      return 1;
            case Linear_Fixed_EF,
                 CHV_EF,
                 Purse_EF,// TODO for this and Cyclic_EF ???
                 Cyclic_EF:           return 2;
            case Linear_Variable_EF:  return 3;
            case RSA_Key_EF,
                 Sym_Key_EF:          return 4;
            case SE_EF:               return 5;
        }
    }

    Handle h = AA["list_op_file_possible"];
    h.SetCallback(IUP_VALUECHANGED_CB, null); // &list_op_file_possible_val_changed_cb
    h.SetIntegerVALUE(0);
    h.SetAttribute(IUP_REMOVEITEM, IUP_ALL);

    int idx = index_textSCB_FileType(fdb);
    ubyte j;
    bool suppress  = AA["toggle_op_file_possible_suppress"].GetStringVALUE()==IUP_ON;
    bool auto_read = AA["toggle_auto_read"].GetStringVALUE()==IUP_ON;
    map2DropDown = ub8.init;
    /* Don't show superfluous operations e.g. like Activate, if the file is activated already*/
    foreach (i, b; sac) {
        if      (i==0 && idx==0) // suppresses Delete Child, which is a access condition, but deleting a file is selected by Delete Self on EF/DF
            continue;
        else if (i==2 && textSCB_FileType[idx][i].empty)
            continue;
        else if (i==3 && (lcsi!=5 || suppress))
            continue;
        else if (i==4 && (lcsi==5 || suppress))
            continue;
        else if (i.among(5,6) && suppress)
            continue;
        else if (i==7)
            continue;
        else if (b<255) {
            h.SetString(IUP_APPENDITEM, textSCB_FileType[idx][i]);
            map2DropDown[i] = ++j;
        }
    }
    bool fileReadPossible = idx!=0 && map2DropDown[0]==1;
    if (fileReadPossible || maxElement(map2DropDown[])==1)
        h.SetIntegerVALUE(1);

    h.SetCallback(IUP_VALUECHANGED_CB, &list_op_file_possible_val_changed_cb);
//    assumeWontThrow(writeln(map2DropDown));

    if (fileReadPossible && auto_read && (sac[0]==0 || sac[0]&0x40)) {
        ubyte expectedFileType = pn.data[6];
        ubyte detectedFileType;
        PKCS15Path_FileType[] dummyPkcs15Extracted;
        readFile(pn, fid, fdb, decompose(fdb, size_or_MRL_NOR).expand, expectedFileType, detectedFileType, dummyPkcs15Extracted);
//assumeWontThrow(writefln("expectedFileType: %s, detectedFileType: %s, dummyPkcs15Extracted: ", expectedFileType, cast(PKCS15_FILE_TYPE)detectedFileType, dummyPkcs15Extracted));
    }
}


extern(C) :


int slot_token_dropcheck_cb(Ihandle* self, int lin, int col)
{
  return IUP_IGNORE; // draw nothing
}

int selectbranchleaf_cb(Ihandle* /*ih*/, int id, int status)
{ // status==1 (enter);  status==0 (leave the node)
    import std.range : chunks, enumerate, retro;
    import std.format : format;

////    printf("selectbranchleaf_cb id(%d), status(%d)\n", id, status);

    if (status==0 || id==0) {
        AA["fs_text"].SetAttributeVALUE(""); // clear content
        AA["fs_text_asn1"].SetAttributeVALUE("");

        Handle h = AA["list_op_file_possible"];
        h.SetCallback(IUP_VALUECHANGED_CB, null/*&list_op_file_possible_val_changed_cb*/);
        h.SetAttribute(IUP_REMOVEITEM, IUP_ALL);
        h.SetCallback(IUP_VALUECHANGED_CB, &list_op_file_possible_val_changed_cb);
        return IUP_DEFAULT;
    }
    auto pn = cast(TreeTypeFS.nodeType*) (cast(iup.iup_plusD.Tree) AA["tree_fs"]).GetUserId(id);
//    printf("selectbranchleaf_cb id(%d), status(%d), data(%s)\n", id, status, sc_dump_hex(pn.data.ptr, pn.data.length)); // selectbranchleaf_cb id(2), status(1), data(0A04000115010105 3F00 0001)
    // selectbranchleaf_cb id(5), status(1), data(01 04 2F00 00 21 00 05  3F00 2F00)

    fci_se_info info;
//    fci_se_info info_df;
    int rv;

    enum string commands = `
        assert(pn.data[1]);
        ubyte[MAX_FCI_GET_RESPONSE_LEN] rbuf;
        ubyte len2 = pn.data[1]/2;
        int i = 1;
        AA["fs_text"].SetString(IUP_APPEND, "Header/meta infos (FCI):");
        foreach (ub2 fid; chunks(pn.data[8..8+pn.data[1]], 2)) {
            info = fci_se_info.init;
            rbuf = typeof(rbuf).init;
            rv= acos5_64_short_select(card, &info, fid, false, rbuf);
            if (i.among(len2, len2==1? 1 : len2-1)) {
//                info_df = info;
//            assumeWontThrow(writeln(info)); //writefln("0x[%(%02X %)]", fid);
//                while (buf.length>=5 && !any(buf[$-5..$]))
//                    buf.length = buf.length-1;
                ptrdiff_t pos = max(1, countUntil!"a>0"(rbuf[].retro))-1; // if possible, show 00 at the end for AB
                AA["fs_text"].SetString(IUP_APPEND,  assumeWontThrow(format!"%(%02X %)"(rbuf[0..$-pos])));
            }
            ++i;
        }
//        with (PKCS15_FILE_TYPE) if (pn.data[6].among(PKCS15_Pin, PKCS15_SecretKey, PKCS15_RSAPrivateKey))
        with (EFDB) if (pn.data[0].among(CHV_EF, Sym_Key_EF, RSA_Key_EF) && pn.data[6]!=PKCS15_FILE_TYPE.PKCS15_RSAPublicKey)
            return IUP_DEFAULT;
        AA["fs_text"].SetString(IUP_APPEND, "\nContent:");

//        assumeWontThrow(writefln("fci: 0X[ %(%02X %) ]", rbuf));
//assumeWontThrow(writeln(info)); //writefln("0x[%(%02X %)]", fid);
        assert(info.fdb.among(EnumMembers!EFDB));
        ub2 size_or_MRL_NOR = pn.data[4..6];
        populate_list_op_file_possible(pn, info.fid, cast(EFDB)info.fdb, size_or_MRL_NOR, pn.data[7], info.sac);
`;
    mixin (connect_card!commands);
    return IUP_DEFAULT;
} // selectbranchleaf_cb


int executeleaf_cb(Ihandle* h, int id)
{
  auto pn = cast(TreeTypeFS.nodeType*) (cast(iup.iup_plusD.Tree) AA["tree_fs"]).GetUserId(id);
////  printf("executeleaf_cb (%d) %s\n", id, sc_dump_hex(pn.data.ptr, pn.data.length));
//  assumeWontThrow(writefln("0x [%(%0sX, %)]", pn.data[0..8]));
  return IUP_DEFAULT;
}


int branchopen_cb(Ihandle* h, int id)
{
////  printf("branchopen_cb (%d)\n", id);
  return IUP_DEFAULT;
}


int branchclose_cb(Ihandle* h, int id)
{
////  printf("branchclose_cb (%d)\n", id);
  return IUP_DEFAULT;
}


/* Callback called when a key is hit */
int k_any_cb(Ihandle* h, int c)
{
  if (c == K_DEL)
  {
    IupSetAttribute(h,"DELNODE","MARKED");
  }

  return IUP_DEFAULT;
}


//  list.SetCallback(IUP_VALUECHANGED_CB, &list_op_file_possible_val_changed_cb);
int list_op_file_possible_val_changed_cb(Ihandle* ih)
{
    Handle h = createHandle(ih);
    int val = h.GetIntegerVALUE;
////  printf("list_op_file_possible_val_changed_cb (%p), val(%d)\n", h, val);
  return IUP_DEFAULT;
}


int toggle_op_file_possible_suppress_cb(Ihandle* ih, int state)
{
////  printf("toggle_op_file_possible_suppress_cb (%d)\n", state);
  return IUP_DEFAULT;
}


int toggle_auto_read_cb(Ihandle* ih, int state)
{
////  printf("toggle_auto_read_cb (%d)\n", state);
  return IUP_DEFAULT;
}


int toggle_auto_decode_asn1_cb(Ihandle* ih, int state)
{
////  printf("toggle_auto_decode_asn1_cb (%d)\n", state);
  return IUP_DEFAULT;
}


int btn_sanity_cb(Ihandle* ih)
{
    enum string commands = `
    AA["matrixsanity"].SetIntegerId2("", 1, 1, card.type);
    AA["matrixsanity"].Update;
    with (card.version_)
    AA["matrixsanity"].SetStringId2 ("", 2, 1, hw_major.to!string~" / "~hw_minor.to!string);
    int rv;
    if (card.type==16004) { //61
		ushort   SW1SW2;
		ubyte    responseLen;
		ubyte[]  response;
		if ((rv= cm_7_3_1_14_get_card_info(card, card_info_type.Operation_Mode_Byte_Setting, 0, SW1SW2, responseLen, response)) < 0) return IUP_DEFAULT;
		assert(responseLen==0);
		ubyte sw2 = cast(ubyte)SW1SW2;
		assert(canFind([ 0,1,2,16 ], sw2));
		with (AA["matrixsanity"])
		switch (sw2) {
			case  0: SetStringId2 ("",   3, 1, "FIPS 140-2 Level 3–Compliant Mode"); break;
			case  1: SetStringId2 ("",   3, 1, "Emulated 32K Mode"); break;
			case  2: SetStringId2 ("",   3, 1, "Non-FIPS 64K Mode"); break;
			case 16: SetStringId2 ("",   3, 1, "NSH-1 Mode"); break;
			default: break;
		}
    }
`;
    mixin (connect_card!commands);
    return IUP_DEFAULT;
} // btn_sanity_cb
