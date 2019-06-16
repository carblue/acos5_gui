/*
 * callbacks.d: Program acos5_64_gui's callbacks file, based on the IUP library
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

module callbacks;

import core.stdc.stdio : printf;
import std.stdio;
import std.string : /*fromStringz,*/ toStringz;
import std.exception : assumeWontThrow;//(expr, msg, file, line)
import std.algorithm.comparison : max, /*min, clamp, equal, mismatch,*/ among;
import std.algorithm.searching : maxElement, countUntil, canFind;
import std.traits : EnumMembers;
import std.conv : to, hexString;
import std.range : iota, slide, chunks;


import libopensc.opensc;
import libopensc.types;
import libopensc.errors;
import libopensc.log;
import libopensc.cards;
import libopensc.iso7816;

import iup.iup_plusD;

import libintl : _, __;

import util_general;// : ub22integral;
import acos5_64_shared;

import util_opensc : connect_card, readFile, decompose, PKCS15Path_FileType, PKCS15_FILE_TYPE,
    is_ACOSV3_opmodeV3_FIPS_140_2L3, is_ACOSV3_opmodeV3_FIPS_140_2L3_active, tnTypePtr, tlv_Range_mod, fsInfoSize;


ub8 map2DropDown = [1, 2, 3, 4, 5, 6, 7, 8];

Config config;
string groupCfg;
/* Config keys */
int isMFcreated;
int isEF_DIRcreated;
int isappDFdefined;
int isappDFexists;
string appDF;

nothrow :


void populate_list_op_file_possible(tnTypePtr pn, ub2 fid, EFDB fdb, ub2 size_or_MRL_NOR, ubyte lcsi, ub8 sac)
{
    import std.string : empty;

    immutable string[7][6] textSCB_FileType = [
        [_("Delete Child"),   "Create EF",        "Create DF",        "Deactivate/Invalidate", "Activate/Rehabilitate", "Terminate/Lock", "Delete Self"], // DF/MF
        [_("Read"),           "Update/Erase",     "",                 "Deactivate/Invalidate", "Activate/Rehabilitate", "Terminate/Lock", "Delete Self"], // EF     binary
        [_("Read"),           "Update",           "",                 "Deactivate/Invalidate", "Activate/Rehabilitate", "Terminate/Lock", "Delete Self"], // EF_lin_fix/CHV record
        [_("Read"),           "Update/Append",    "",                 "Deactivate/Invalidate", "Activate/Rehabilitate", "Terminate/Lock", "Delete Self"], // EF_lin_var record
        [_("Read (Get Key)"), "Put Key",          "MSE/PSO Commands", "Deactivate/Invalidate", "Activate/Rehabilitate", "Terminate/Lock", "Delete Self"], // Key File
        [_("Read"),           "MSE Store/Delete", "MSE Restore",      "Deactivate/Invalidate", "Activate/Rehabilitate", "Terminate/Lock", "Delete Self"], // SE File
    ];

    int index_textSCB_FileType(EFDB fdb)
    {
        with (EFDB)
        final switch (fdb)
        {
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
    immutable suppress  = AA["toggle_op_file_possible_suppress"].GetStringVALUE()==IUP_ON;
    immutable auto_read = AA["toggle_auto_read"].GetStringVALUE()==IUP_ON;
    map2DropDown = ub8.init;
    /* Don't show superfluous operations e.g. like Activate, if the file is activated already*/
    foreach (i, b; sac)
    {
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
        else if (b<255)
        {
            h.SetString(IUP_APPENDITEM, textSCB_FileType[idx][i]);
            map2DropDown[i] = ++j;
        }
    }
    immutable fileReadPossible = idx!=0 && map2DropDown[0]==1;
    if (fileReadPossible || maxElement(map2DropDown[])==1)
        h.SetIntegerVALUE(1);

    h.SetCallback(IUP_VALUECHANGED_CB, &list_op_file_possible_val_changed_cb);
//    assumeWontThrow(writeln(map2DropDown));

    if (fileReadPossible && auto_read && (sac[0]==0 || sac[0]&0x40 ||
        (is_ACOSV3_opmodeV3_FIPS_140_2L3 && sac[0].among(1,3))))
    {
        immutable expectedFileType = pn.data[6];
        ubyte dummydetectedFileType;
        PKCS15Path_FileType[] dummyPkcs15Extracted;
        readFile(pn, fid, fdb, sac[0], decompose(fdb, size_or_MRL_NOR).expand, expectedFileType, dummydetectedFileType,
                                                 dummyPkcs15Extracted);
//assumeWontThrow(writefln("expectedFileType: %s, detectedFileType: %s, dummyPkcs15Extracted: ", expectedFileType, cast(PKCS15_FILE_TYPE)detectedFileType, dummyPkcs15Extracted));
    }
}


extern(C) :


int slot_token_dropcheck_cb(Ihandle* self, int /*lin*/, int /*col*/)
{
  return IUP_IGNORE; // draw nothing
}


int selectbranchleaf_cb(Ihandle* /*ih*/, int id, int status)
{ // status==1 (enter);  status==0 (leave the node)
    import std.range : chunks, enumerate, retro;
    import std.format : format;

////    printf("selectbranchleaf_cb id(%d), status(%d)\n", id, status);

    if (status==0 || id==0)
    {
        AA["fs_text"].SetAttributeVALUE(""); // clear content
        AA["fs_text_asn1"].SetAttributeVALUE("");

        Handle h = AA["list_op_file_possible"];
        h.SetCallback(IUP_VALUECHANGED_CB, null/*&list_op_file_possible_val_changed_cb*/);
        h.SetAttribute(IUP_REMOVEITEM, IUP_ALL);
        h.SetCallback(IUP_VALUECHANGED_CB, &list_op_file_possible_val_changed_cb);
        return IUP_DEFAULT;
    }
    auto pn = cast(tnTypePtr) (cast(iup.iup_plusD.Tree) AA["tree_fs"]).GetUserId(id);
//    printf("selectbranchleaf_cb id(%d), status(%d), data(%s)\n", id, status, sc_dump_hex(pn.data.ptr, pn.data.length)); // selectbranchleaf_cb id(2), status(1), data(0A04000115010105 3F00 0001)
    // selectbranchleaf_cb id(5), status(1), data(01 04 2F00 00 21 00 05  3F00 2F00)

////    FCISEInfo info;
//    FCISEInfo info_df;
    int rv;

    enum string commands = `
        assert(pn.data[1]);
        ubyte[MAX_FCI_GET_RESPONSE_LEN] rbuf;
        ubyte len2 = pn.data[1]/2;
////        int i = 1;
        AA["fs_text"].SetString(IUP_APPEND, "Header/meta infos (FCI):");

            ubyte len;
            sc_path path;
            sc_file* file;
        if (len2>1) { // for file's directory
            rbuf = typeof(rbuf).init;
            sc_format_path(ubaIntegral2string(pn.data[8..6+2*len2]).toStringz , &path);
            if ((rv= sc_select_file(card, &path, &file)) == SC_SUCCESS) {
                rbuf[0] = ISO7816_TAG_FCI;
                rbuf[1] = len  = cast(ubyte) file.prop_attr_len;
                rbuf[2..2+len] = file.prop_attr[0..len];
                sc_file_free(file);
                ptrdiff_t pos = max(1, countUntil!"a>0"(rbuf[].retro))-1; // if possible, show 00 at the end for AB
                AA["fs_text"].SetString(IUP_APPEND,  assumeWontThrow(format!"%(%02X %)"(rbuf[0..$-pos])));
            }
        }
        { // for the file itself
            rbuf = typeof(rbuf).init;
            sc_format_path(ubaIntegral2string(pn.data[6+2*len2..8+2*len2]).toStringz , &path);
            path.type = SC_PATH_TYPE_FILE_ID;
            if ((rv= sc_select_file(card, &path, &file)) == SC_SUCCESS) {
                rbuf[0] = ISO7816_TAG_FCI;
                rbuf[1] = len  = cast(ubyte) file.prop_attr_len;
                rbuf[2..2+len] = file.prop_attr[0..len];
                sc_file_free(file);
                ptrdiff_t pos = max(1, countUntil!"a>0"(rbuf[].retro))-1; // if possible, show 00 at the end for AB
                AA["fs_text"].SetString(IUP_APPEND,  assumeWontThrow(format!"%(%02X %)"(rbuf[0..$-pos])));
            }
        }
/+
        foreach (ub2 fid; chunks(pn.data[8..8+2*len2], 2))
        {
//            info = FCISEInfo.init;
            rbuf = typeof(rbuf).init;

            rv= acos5_64_short_select(card, fid, &info, rbuf);
            if (i.among(len2, len2==1? 1 : len2-1))
            {
//                info_df = info;
//            assumeWontThrow(writeln(info)); //writefln("0x[%(%02X %)]", fid);
//                while (buf.length>=5 && !any(buf[$-5..$]))
//                    buf.length = buf.length-1;
                ptrdiff_t pos = max(1, countUntil!"a>0"(rbuf[].retro))-1; // if possible, show 00 at the end for AB
                AA["fs_text"].SetString(IUP_APPEND,  assumeWontThrow(format!"%(%02X %)"(rbuf[0..$-pos])));
            }
            ++i;
        }
+/
//        with (PKCS15_FILE_TYPE) if (pn.data[6].among(PKCS15_Pin, PKCS15_SecretKey, PKCS15_RSAPrivateKey))
        with (EFDB) if (pn.data[0].among(CHV_EF, Sym_Key_EF/*, RSA_Key_EF*/) && pn.data[6]!=PKCS15_FILE_TYPE.PKCS15_RSAPublicKey)
            return IUP_DEFAULT;
        AA["fs_text"].SetString(IUP_APPEND, "\nContent:");

//        assumeWontThrow(writefln("fci: 0X[ %(%02X %) ]", rbuf));
//assumeWontThrow(writeln(info)); //writefln("0x[%(%02X %)]", fid);
//        assert(info.fdb.among(EnumMembers!EFDB));
//        ub2 size_or_MRL_NOR = pn.data[4..6];

        populate_list_op_file_possible(pn,
                                       [ pn.data[2], pn.data[3] ], // info.fid,
                                       cast(EFDB)pn.data[0], // cast(EFDB)info.fdb,
                                       pn.data[4..6], // size_or_MRL_NOR,
                                       pn.data[7],
                                       pn.data[24..32], // info.sac
                                       );
`;
    mixin (connect_card!commands);
    return IUP_DEFAULT;
} // selectbranchleaf_cb


int executeleaf_cb(Ihandle* h, int /*id*/)
{
////  auto pn = cast(tnTypePtr) (cast(iup.iup_plusD.Tree) AA["tree_fs"]).GetUserId(id);
////  printf("executeleaf_cb (%d) %s\n", id, sc_dump_hex(pn.data.ptr, pn.data.length));
//  assumeWontThrow(writefln("0x [%(%0sX, %)]", pn.data[0..8]));
    return IUP_DEFAULT;
}


int branchopen_cb(Ihandle* h, int /*id*/)
{
////  printf("branchopen_cb (%d)\n", id);
    return IUP_DEFAULT;
}


int branchclose_cb(Ihandle* h, int /*id*/)
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
////    Handle h = createHandle(ih);
////    int val = h.GetIntegerVALUE;
////    printf("list_op_file_possible_val_changed_cb (%p), val(%d)\n", h, val);
    return IUP_DEFAULT;
}


int toggle_op_file_possible_suppress_cb(Ihandle* ih, int /*state*/)
{
////  printf("toggle_op_file_possible_suppress_cb (%d)\n", state);
    return IUP_DEFAULT;
}


int toggle_auto_read_cb(Ihandle* ih, int /*state*/)
{
////  printf("toggle_auto_read_cb (%d)\n", state);
    return IUP_DEFAULT;
}


int toggle_auto_decode_asn1_cb(Ihandle* ih, int /*state*/)
{
////  printf("toggle_auto_decode_asn1_cb (%d)\n", state);
    return IUP_DEFAULT;
}

int btn_exit_cb(Ihandle* /*ih*/)
{
  /* Exits the main loop */
  return IUP_CLOSE;
}

int btn_sanity_cb(Ihandle* ih)
{
//    printf("btn_sanity_cb: IupGetName(ih): %s", IupGetName(ih)); // btn_sanity_cb: IupGetName(ih): btn_sanity
    enum string commands = `
    Handle h = AA["matrixsanity"];
    h.SetIntegerId2("", 1, 1, card.type);
    h.Update;
    with (card.version_)
    h.SetStringId2 ("", 2, 1, hw_major.to!string~"."~hw_minor.to!string);
    int rv;
    if (card.type==SC_CARD_TYPE_ACOS5_64_V3)
    {
        uint  op_mode_byte = 0x7FFF_FFFF;
        rv = sc_card_ctl(card, SC_CARDCTL_ACOS5_GET_OP_MODE_BYTE, &op_mode_byte);
        if (rv < 0)
            return IUP_DEFAULT;
        with (h)
        switch (op_mode_byte)
        {
            case  0: SetStringId2 ("",   3, 1, "FIPS 140-2 Level 3 Mode (The card is not necessarily FIPS-compliant in that mode)"); break;
            case  1: SetStringId2 ("",   3, 1, "Emulated 32K Mode"); break;
            case  2: SetStringId2 ("",   3, 1, "Non-FIPS 64K Mode"); break;
            case 16: SetStringId2 ("",   3, 1, "NSH-1 Mode"); break;
            default: break;
        }
    }

    sc_path path;
    sc_format_path("3F00", &path);
    rc = sc_select_file(card, &path, null);
    isMFcreated =  rc==SC_SUCCESS? 1 : 0;
    config.SetVariableInt(groupCfg.toStringz, "isMFcreated", isMFcreated);
    AA["sanity_text"].SetString(IUP_APPEND, "isMFcreated = "~isMFcreated.to!string);
    if (!isMFcreated)
        return IUP_DEFAULT;//assert(0);

    ubyte[MAX_FCI_GET_RESPONSE_LEN] fci_2f00; // without leading 0x6F and L_byte
////    ub2 fid = [0x2F, 0];
////    rc = acos5_64_short_select(card, fid, null, fci_2f00);
    // the new rust driver uses sc_file_set_prop_attr, where the fci_2f00 can be read from
    sc_file* file;
    sc_format_path("3F002F00", &path);
    rc = sc_select_file(card, &path, &file);
    isEF_DIRcreated =  rc==SC_SUCCESS? 1 : 0;
    if (isEF_DIRcreated)
        fci_2f00[0..file.prop_attr_len] = file.prop_attr[0..file.prop_attr_len];
    sc_file_free(file);
    AA["sanity_text"].SetString(IUP_APPEND, "isEF_DIRcreated = "~isEF_DIRcreated.to!string);
    if (isEF_DIRcreated)
    {
        ushort size_2f00;
        foreach (d,T,L,V; tlv_Range_mod(fci_2f00/*[2..$]*/))
             if (T==0x80)
                size_2f00 = ub22integral(V);

        auto  buf = new ubyte[](size_2f00);
        rv = sc_read_binary(card, 0, buf.ptr, buf.length, 0 /*flags*/);
        assert(rv>0 && rv==buf.length);

        foreach (d,T,L,V; tlv_Range_mod(buf[2..$]))
            if (T==0x51)
            {
                isappDFdefined = 1;
                appDF = ubaIntegral2string(V[0..L]);
                AA["sanity_text"].SetString(IUP_APPEND, "isappDFdefined = "~isappDFdefined.to!string);
                AA["sanity_text"].SetString(IUP_APPEND, "appDF = "~appDF);
            }

        sc_format_path(appDF.toStringz, &path);
        rc = sc_select_file(card, &path, null);
        isappDFexists =  rc==SC_SUCCESS? 1 : 0;
        AA["sanity_text"].SetString(IUP_APPEND, "isappDFexists = "~isappDFexists.to!string);
    }
`;
    mixin (connect_card!commands);

    with (config)
    {
//        SetVariableInt(groupCfg.toStringz, "isMFcreated",     isMFcreated);
        SetVariableInt(groupCfg.toStringz, "isEF_DIRcreated", isEF_DIRcreated);
        SetVariableInt(groupCfg.toStringz, "isappDFdefined",  isappDFdefined);
        SetVariableStr(groupCfg.toStringz, "appDF",           appDF.toStringz);
        SetVariableInt(groupCfg.toStringz, "isappDFexists",   isappDFexists);
    }
    return IUP_DEFAULT;
} // btn_sanity_cb
