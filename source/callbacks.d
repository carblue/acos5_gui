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
import std.algorithm.searching : maxElement;
import std.traits : EnumMembers;

import libopensc.opensc;
import libopensc.types;
import libopensc.errors;
import libopensc.log;

import iup.iup_plusD;

import libintl : _, __;

import util_general;
import acos5_64_shared;

import util_opensc : lh, card, util_connect_card, TreeTypeFS, acos5_64_short_select, readFile, decompose, PKCS15Path_FileType;


extern(C) int slot_token_dropcheck_cb(Ihandle* self, int lin, int col) nothrow
{
  return IUP_IGNORE; // draw nothing
}


ub8 map2DropDown = [1, 2, 3, 4, 5, 6, 7, 8];

void populate_list_op_file_possible(TreeTypeFS.nodeType* pn, ub2 fid, EFDB fdb, ub2 size_or_MRL_NOR, ubyte lcsi, ub8 sac) nothrow {
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
    h.SetCallback("VALUECHANGED_CB", null); // &list_op_file_possible_val_changed_cb
    h.SetIntegerVALUE(0);
    h.SetAttribute("REMOVEITEM", "ALL");

    int idx = index_textSCB_FileType(fdb);
    ubyte j;
    bool suppress  = AA["toggle_op_file_possible_suppress"].GetStringVALUE()=="ON";
    bool auto_read = AA["toggle_auto_read"].GetStringVALUE()=="ON";
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
            h.SetString("APPENDITEM", textSCB_FileType[idx][i]);
            map2DropDown[i] = ++j;
        }
    }
    bool fileReadPossible = idx!=0 && map2DropDown[0]==1;
    if (fileReadPossible || maxElement(map2DropDown[])==1)
        h.SetIntegerVALUE(1);

    h.SetCallback("VALUECHANGED_CB", &list_op_file_possible_val_changed_cb);
//    assumeWontThrow(writeln(map2DropDown));

    ubyte PKCS15fileType;
    PKCS15Path_FileType[] pkcs15Extracted;
    if (fileReadPossible && auto_read && (sac[0]==0 || sac[0]&0x40))
        readFile(pn, fid, fdb, /*size, mrl, nor*/ decompose(fdb, size_or_MRL_NOR).expand, PKCS15fileType/*, pathExtracted*/, pkcs15Extracted);
}


extern(C) int selectbranchleaf_cb(Ihandle* ih, int id, int status) nothrow
{
    import std.range : chunks, enumerate;

    if (status==0 || id==0) {
        AA["fs_text"].SetAttributeVALUE("");
        AA["fs_text_asn1"].SetAttributeVALUE("");

        Handle h = AA["list_op_file_possible"];
        h.SetCallback("VALUECHANGED_CB", null/*&list_op_file_possible_val_changed_cb*/);
        h.SetAttribute("REMOVEITEM", "ALL");
        h.SetCallback("VALUECHANGED_CB", &list_op_file_possible_val_changed_cb);
        return IUP_DEFAULT;
    }
    auto pn = cast(TreeTypeFS.nodeType*) (cast(iup.iup_plusD.Tree) AA["tree_fs"]).GetUserId(id);
////    printf("selectbranchleaf_cb id(%d), status(%d), data(%s)\n", id, status, sc_dump_hex(pn.data.ptr, pn.data.length)); // selectbranchleaf_cb id(2), status(1), data(0A04000115010105 3F00 0001)
  // selectbranchleaf_cb id(5), status(1), data(01 04 2F00 00 21 00 05  3F00 2F00)
    fci_se_info info;
    fci_se_info info_df;
    int rv;

    /* connect to card */
    {
        string debug_file = "/tmp/opensc-debug.log";

        sc_context*         ctx;
        sc_context_param_t  ctx_param = { 0, "acos5_64_gui " };
        if (sc_context_create(&ctx, &ctx_param)) // assumeWontThrow(writeln(19));
            return IUP_CONTINUE;
//        assert(ctx);
//        assumeWontThrow(writeln(*ctx));

version(OPENSC_VERSION_LATEST)
        ctx.flags |= SC_CTX_FLAG_ENABLE_DEFAULT_DRIVER;
        ctx.debug_ = SC_LOG_DEBUG_NORMAL/*verbose*/;
        sc_ctx_log_to_file(ctx, toStringz(debug_file));
        if (sc_set_card_driver(ctx, "acos5_64")) // assumeWontThrow(writeln(29));
            return IUP_CONTINUE;

        int rc;
        rc = util_connect_card(ctx, &card, null/*opt_reader*/, 0/*opt_wait*/, 1 /*do_lock*/, 0/*SC_LOG_DEBUG_NORMAL*//*verbose*/); // does: sc_lock(card) including potentially card.sm_ctx.ops.open
        mixin (log!(__FUNCTION__, " util_connect_card returning with: %i (%s)", "rc", "sc_strerror(rc)"));
//        writeln("PASSED: util_connect_card");
        scope(exit) {
			if (card) {
				if (! assumeWontThrow(Runtime.unloadLibrary(lh)))
    				assumeWontThrow(writeln("Failed to do: Runtime.unloadLibrary(lh)"));//return IUP_CONTINUE;
version(Windows) {}
else {
	version(unittest) {}
	else {
				if (! assumeWontThrow(Runtime.terminate()))
					assumeWontThrow(writeln("Failed to do: Runtime.terminate()"));//return IUP_CONTINUE;
	}
}

				sc_unlock(card);
				sc_disconnect_card(card);
			}

            if (ctx)
                sc_release_context(ctx);
//            {
//                auto f = File(debug_file, "w"); // open for writing, i.e. Create an empty file for output operations. If a file with the same name already exists, its contents are discarded and the file is treated as a new empty file.
//            }
        } // scope(exit)
        if (rc || !card)
            return IUP_CONTINUE;

        assert(pn.data[1]);
        int i = 1;
        foreach (ub2 fid; chunks(pn.data[8..8+pn.data[1]], 2)) {
            info = fci_se_info.init;
            rv= acos5_64_short_select(card, &info, fid, false);
            if (i < pn.data[1]/2 /* last i*/)
                info_df = info;
//            assumeWontThrow(writeln(info)); //writefln("0x[%(%02X %)]", fid);
            ++i;
        }
        assert(info.fdb.among(EnumMembers!EFDB));
        ub2 size_or_MRL_NOR = pn.data[4..6];
        populate_list_op_file_possible(pn, info.fid, cast(EFDB)info.fdb, size_or_MRL_NOR, pn.data[7], info.sac);
    } // disconnected from card now !
    return IUP_DEFAULT;
}

extern(C) int executeleaf_cb(Ihandle* h, int id) nothrow
{
  auto pn = cast(TreeTypeFS.nodeType*) (cast(iup.iup_plusD.Tree) AA["tree_fs"]).GetUserId(id);
  printf("executeleaf_cb (%d) %s\n", id, sc_dump_hex(pn.data.ptr, pn.data.length));
//  assumeWontThrow(writefln("0x [%(%0sX, %)]", pn.data[0..8]));
  return IUP_DEFAULT;
}

extern(C) int branchopen_cb(Ihandle* h, int id) nothrow
{
  printf("branchopen_cb (%d)\n", id);
  return IUP_DEFAULT;
}

extern(C) int branchclose_cb(Ihandle* h, int id) nothrow
{
  printf("branchclose_cb (%d)\n", id);
  return IUP_DEFAULT;
}

/* Callback called when a key is hit */
extern(C) int k_any_cb(Ihandle* h, int c) nothrow
{
  if (c == K_DEL)
  {
    IupSetAttribute(h,"DELNODE","MARKED");
  }

  return IUP_DEFAULT;
}

//  list.SetCallback("VALUECHANGED_CB", &list_op_file_possible_val_changed_cb);
extern(C) int list_op_file_possible_val_changed_cb(Ihandle* ih) nothrow
{
    Handle h = createHandle(ih);
    int val = h.GetIntegerVALUE;
  printf("list_op_file_possible_val_changed_cb (%p), val(%d)\n", h, val);
  return IUP_DEFAULT;
}

extern(C) int toggle_op_file_possible_suppress_cb(Ihandle* ih, int state) nothrow
{
  printf("toggle_op_file_possible_suppress_cb (%d)\n", state);
  return IUP_DEFAULT;
}

extern(C) int toggle_auto_read_cb(Ihandle* ih, int state) nothrow
{
  printf("toggle_auto_read_cb (%d)\n", state);
  return IUP_DEFAULT;
}

extern(C) int toggle_auto_decode_asn1_cb(Ihandle* ih, int state) nothrow
{
  printf("toggle_auto_decode_asn1_cb (%d)\n", state);
  return IUP_DEFAULT;
}
