/*
 * Written in the D programming language, part of package acos5_64_gui.
 * gui.d: Graphical User Interface file, based on IUP
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

module gui;

import std.stdio : write, writeln, writefln, stdout;
import std.algorithm.comparison : among;

import iup.iup_plusD;

import libintl : _, __;

import callbacks;


private Hbox create_cryptoki_slot_tokeninfo_tab() {
    Control[]  child_array;
    Matrix     matrix;
    Text       text;
    Vbox       vbox1, vbox2;
    List       list;

    matrix = new Matrix("slot_token");
    with (matrix) {
        SetInteger("NUMLIN",         41);
        SetInteger("NUMLIN_VISIBLE", 41);
        SetInteger("NUMCOL",          1);
        SetInteger("NUMCOL_VISIBLE",  1);
        SetAttribute("RESIZEMATRIX", "YES");
//      SetAttribute("LIMITEXPAND",  "YES");
        SetAttribute("READONLY",     "YES");
//      SetAttribute("FLATSCROLLBAR",     "YES");
//      SetAttribute("EDITNEXT",     "COL");
        SetIntegerId("WIDTH",   0,    215);
        SetIntegerId("WIDTH",   1,    120);
        SetInteger("HEIGHTDEF",  5);

        SetAttributeId2("", 0,  1,   __("value")); // SetAttributeId2("", 1,  1, "");

        SetAttributeId2("",  1,  0,   "Cryptoki version"); //  SetAttributeId2("",  7,  1, "CKF_REMOVABLE_DEVICE");
        SetAttributeId2("",  2,  0,   __("Cryptoki manufacturerID")); //         SetAttributeId2("",  3,  1, "-");
        SetAttributeId2("",  3,  0,   "Cryptoki flags bitfield"); //  SetAttributeId2("",  7,  1, "CKF_REMOVABLE_DEVICE");
        SetAttributeId2("",  4,  0,   "Cryptoki libraryDescription"); //         SetAttributeId2("",  3,  1, "-");
        SetAttributeId2("",  5,  0,   "Cryptoki libraryVersion"); //  SetAttributeId2("",  7,  1, "CKF_REMOVABLE_DEVICE");

        SetAttributeId2("",  6,  0,   "Slot id"); //                  SetAttributeId2("",  1,  1, "-");
        SetAttributeId2("",  7,  0,   __("Slot description")); //        SetAttributeId2("",  2,  1, "-");
        SetAttributeId2("",  8,  0,   __("Slot manufacturerID")); //         SetAttributeId2("",  3,  1, "-");
        SetAttributeId2("",  9,  0,   "Slot flag CKF_TOKEN_PRESENT"); //           SetAttributeId2("",  4,  1, "CKF_REMOVABLE_DEVICE");
        SetAttributeId2("", 10,  0,   "Slot flag CKF_REMOVABLE_DEVICE"); //           SetAttributeId2("",  5,  1, "CKF_REMOVABLE_DEVICE");
        SetAttributeId2("", 11,  0,   "Slot flag CKF_HW_SLOT"); //           SetAttributeId2("",  6,  1, "CKF_REMOVABLE_DEVICE");
        SetAttributeId2("", 12,  0,   "Slot hardware/firmware version"); //  SetAttributeId2("",  7,  1, "CKF_REMOVABLE_DEVICE");

        SetAttributeId2("", 13,  0,   __("Token label")); //              SetAttributeId2("",  8,  1, "-");
        SetAttributeId2("", 14,  0,   __("Token manufacturer")); //       SetAttributeId2("",  9,  1, "-");
        SetAttributeId2("", 15,  0,   "Token model"); //              SetAttributeId2("", 10,  1, "-");
        SetAttributeId2("", 16,  0,   "Token serialnr"); //           SetAttributeId2("", 11,  1, "-");

        SetAttributeId2("", 17,  0,   "Token flags bitfield (summary, below the details)"); //        SetAttributeId2("", 12,  1, "-");
        SetAttributeId2("", 18,  0,   "Token flag CKF_RNG"); //      SetAttributeId2("", 13,  1, "-");
        SetAttributeId2("", 19,  0,   "Token flag CKF_WRITE_PROTECTED"); //        SetAttributeId2("", 14,  1, "-");
        SetAttributeId2("", 20,  0,   "Token flag CKF_LOGIN_REQUIRED"); //         SetAttributeId2("", 15,  1, "-");
        SetAttributeId2("", 21,  0,   "Token flag CKF_USER_PIN_INITIALIZED"); //           SetAttributeId2("", 16,  1, "-");

        SetAttributeId2("", 22,  0,   "Token flag CKF_PROTECTED_AUTHENTICATION_PATH"); //             SetAttributeId2("", 17,  1, "-");
        SetAttributeId2("", 23,  0,   "Token flag CKF_DUAL_CRYPTO_OPERATIONS"); //    SetAttributeId2("", 18,  1, "-");
        SetAttributeId2("", 24,  0,   "Token flag CKF_TOKEN_INITIALIZED"); //    SetAttributeId2("", 19,  1, "-");
        SetAttributeId2("", 25,  0,   "Token flag CKF_SECONDARY_AUTHENTICATION"); //      SetAttributeId2("", 20,  1, "-");

        SetAttributeId2("", 26,  0,   "Token flag CKF_USER_PIN_COUNT_LOW"); // SetAttributeId2("", 21,  1, "-");
        SetAttributeId2("", 27,  0,   "Token flag CKF_USER_PIN_FINAL_TRY"); //      SetAttributeId2("", 22,  1, "-");
        SetAttributeId2("", 28,  0,   "Token flag CKF_USER_PIN_LOCKED"); //      SetAttributeId2("", 23,  1, "-");
        SetAttributeId2("", 29,  0,   "Token flag CKF_USER_PIN_TO_BE_CHANGED"); //        SetAttributeId2("", 24,  1, "-");

        SetAttributeId2("", 30,  0,   "Token flag CKF_SO_PIN_COUNT_LOW"); //   SetAttributeId2("", 25,  1, "-");
        SetAttributeId2("", 31,  0,   "Token flag CKF_SO_PIN_FINAL_TRY"); //   SetAttributeId2("", 25,  1, "-");
        SetAttributeId2("", 32,  0,   "Token flag CKF_SO_PIN_LOCKED"); //   SetAttributeId2("", 25,  1, "-");
        SetAttributeId2("", 33,  0,   "Token flag CKF_SO_PIN_TO_BE_CHANGED"); //   SetAttributeId2("", 25,  1, "-");

        SetAttributeId2("", 34,  0,   "Token flag CKF_ERROR_STATE"); //   SetAttributeId2("", 25,  1, "-");

        SetAttributeId2("", 35,  0,   "Token SessionCount cur/max"); //   SetAttributeId2("", 25,  1, "-");
        SetAttributeId2("", 36,  0,   "Token RwSessionCount cur/max"); //   SetAttributeId2("", 25,  1, "-");
        SetAttributeId2("", 37,  0,   "Token PinLen min/max"); //   SetAttributeId2("", 25,  1, "-");
        SetAttributeId2("", 38,  0,   "Token PublicMemory free/total"); //   SetAttributeId2("", 25,  1, "-");
        SetAttributeId2("", 39,  0,   "Token PrivateMemory free/total"); //   SetAttributeId2("", 25,  1, "-");
        SetAttributeId2("", 40,  0,   "Token hardware/firmware version"); //  SetAttributeId2("",  7,  1, "CKF_REMOVABLE_DEVICE");
        SetAttributeId2("", 41,  0,   "Token utcTime"); //  SetAttributeId2("",  7,  1, "CKF_REMOVABLE_DEVICE");

        SetAttribute("TOGGLECENTERED",  "YES");
        SetCallback("DROPCHECK_CB",  cast(Icallback) &slot_token_dropcheck_cb);
    }
    child_array ~= matrix;
    vbox1 = new Vbox(child_array, FILL_TYPE.FILL_BETWEEN);

    auto hbox = new Hbox(vbox1, new Fill/*, vbox2*/);
    hbox.SetAttribute("TABTITLE", "Cryptoki/Slot/Token-Info");
    return hbox;
}

private Vbox create_opensc_conf_tab() {
    Control[] child_array;

    child_array ~= new Label(  "This page allows editing opensc.conf (and later acos5_64.profile). Root privileges will be required for storing"); // will be collected
    child_array ~= new Label(  "There are 2 modes how to handle Root privileges: Either enter admin password in this app, or in a shell for a command sudo patch -b /etc/opensc/opensc.conf conf.diff"); // will be collected

    auto vbox = new Vbox(new Vbox(child_array, FILL_TYPE.FILL_BETWEEN), new Fill);
    vbox.SetAttribute("TABTITLE", "opensc.conf");
    return vbox;
}

private Hbox create_filesystem_tab() {
    Control[] child_array1, child_array2;
    auto tree_fs = new Tree("tree_fs");
    with (tree_fs) {
        SetAttribute("SHOWTOGGLE", "YES");

        SetCallback("SELECTION_CB", cast(Icallback) &selectbranchleaf_cb);
        SetCallback("EXECUTELEAF_CB", cast(Icallback) &executeleaf_cb);
//      SetCallback("RENAME_CB", cast(Icallback) &rename_cb);
        SetCallback("BRANCHCLOSE_CB", cast(Icallback) &branchclose_cb);
        SetCallback("BRANCHOPEN_CB", cast(Icallback) &branchopen_cb);
//      SetCallback("DRAGDROP_CB", cast(Icallback) &dragdrop_cb);
//      SetCallback("RIGHTCLICK_CB", cast(Icallback) &rightclick_cb);
////    SetCallback("K_ANY", cast(Icallback) &k_any_cb);

//      SetAttribute("FONT","COURIER_NORMAL");
//      SetAttribute("CTRL","YES");
//      SetAttribute("SHIFT","YES");
//      SetAttribute("ADDEXPANDED", "NO");
//      SetAttribute("SHOWDRAGDROP", "YES");
////    SetAttribute("SHOWRENAME", "YES");

    }

    child_array1 ~= tree_fs;

    auto toggle1 = new Toggle("toggle_op_file_possible_suppress", __("Suppress rare operations like delete, de-/activate"));
    toggle1.SetAttributeVALUE("ON");
    toggle1.SetCallback("ACTION", cast(Icallback) &toggle_op_file_possible_suppress_cb);
    child_array2 ~= toggle1;
    auto toggle2 = new Toggle("toggle_auto_read", __("Perform 'Read operation' automatically, if applicable and doesn't require authorization (except SM related)"));
    toggle2.SetAttributeVALUE("ON");
    toggle2.SetCallback("ACTION", cast(Icallback) &toggle_auto_read_cb);
    child_array2 ~= toggle2;

    auto list = new List("list_op_file_possible");
    with (list) {
        SetAttribute("SIZE", "100");
        SetAttribute("DROPDOWN", "YES");
        SetAttribute("VISIBLEITEMS", "7");
        SetAttribute("1", "Read");
        SetAttribute("2", "Update");
        SetAttribute("3", "---");
        SetAttribute("4", "Deactivate/Invalidate");
        SetAttribute("5", "Activate/Rehabilitate");
        SetAttribute("6", "Terminate/Lock");
        SetAttribute("7", "Delete Self");
        SetAttribute("8", null);
//      SetAttribute("VALUE", "1");
        SetCallback("VALUECHANGED_CB", &list_op_file_possible_val_changed_cb);
    }
    child_array2 ~= list;
    child_array2 ~= new Label("Read-Result (hexadecimal)");

    auto text1 = new Text("fs_text");
    with (text1) {
        SetAttribute("SIZE", "780");
        SetAttribute("MULTILINE", "YES");
        SetAttribute("VISIBLELINES", "20");
        SetAttribute("WORDWRAP", "YES");
    }
    child_array2 ~= text1;

    auto toggle3 = new Toggle("toggle_auto_decode_asn1", __("Perform 'Read operation result ASN.1-decoding' (for RSA: openssh format) automatically, if applicable"));
    toggle3.SetAttributeVALUE("ON");
    toggle3.SetCallback("ACTION", cast(Icallback) &toggle_auto_decode_asn1_cb);
    child_array2 ~= toggle3;

    auto text2 = new Text("fs_text_asn1");
    with (text2) {
        SetAttribute("SIZE", "780");
        SetAttribute("MULTILINE", "YES");
        SetAttribute("VISIBLELINES", "20");
        SetAttribute("WORDWRAP", "YES");

        SetAttribute("READONLY", "YES");
    }
    child_array2 ~= text2;

    child_array1 ~= new Vbox(child_array2, FILL_TYPE.FILL_BETWEEN);

    auto hbox = new Hbox(child_array1, FILL_TYPE.FILL_FRONT_AND_BACK_AND_BETWEEN);
    hbox.SetAttribute("TABTITLE", "file system (read only)");
    return hbox;
}

private Vbox create_ssh_tab() {
    auto vbox = new Vbox();
    vbox.SetAttribute("TABTITLE", "ssh");
    return vbox;
}


Dialog create_dialog_dlg0() {
    /* Example of i18n usage */
    auto btn_exit    = new Button(  __("Exit")); // __("Beenden")
////  btn_exit.SetCallback("ACTION", &dlg0_exit);
    btn_exit.SetAttribute("TIP", __("more to come"));

    auto hbox = new Hbox([ btn_exit ], FILL_TYPE.FILL_FRONT_AND_BACK_AND_BETWEEN);

    Control[] child_array = [create_cryptoki_slot_tokeninfo_tab/*, create_opensc_conf_tab*/, create_filesystem_tab /*, create_ssh_tab*/];
    auto tabs = new Tabs("tabCtrl", child_array);
//  tabs.SetAttribute("TABTYPE", "TOP"); // Default is "TOP"

    auto lbl_statusbar = new Label("statusbar", "statusbar");
    lbl_statusbar.SetAttribute("EXPAND", "HORIZONTAL");
    lbl_statusbar.SetAttribute("PADDING", "10x5");

    auto vbox = new Vbox(/*new Fill, */ hbox /*, new Fill*/, tabs, lbl_statusbar);
    auto dialog = new Dialog("dlg0", true, vbox);
    dialog.SetAttribute("TITLE", __("tool for driver acos5_64"));
    dialog.SetAttribute("MARGIN", "2x2");
    return dialog;
}
