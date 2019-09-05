/*
 * acos5_64_gui.d: Program acos5_64_gui's main file
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

/*
 * This program MUST NOT be used in parallel to using libacos5_64.so in other ways like through opensc-pkcs11.so,
 * as it may alter the selected file unexpected by other software!
 * TODO check about countermeasures like locking etc. provided by PKCS#11
 */

module acos5_64_gui;


import core.memory : GC;
import core.stdc.config : c_long, c_ulong;
import core.stdc.stdlib : EXIT_SUCCESS, EXIT_FAILURE, exit, getenv;
import core.stdc.locale : setlocale, LC_ALL;
import std.stdio : write, writeln, writefln, stdout;
import std.conv : to;
import std.format : format;
import std.string : toStringz, fromStringz, stripRight, representation, assumeUTF;
import std.algorithm.searching : startsWith;

import libintl : _, __;
version(I18N)
    import libintl : bindtextdomain, textdomain, bind_textdomain_codeset;

import iup.iup_plusD : AA, Handle, Config, IupOpenD, IupControlsOpen, IupClose, IupMainLoop, IUP_APPEND, IupSetGlobal, IUP_YES;

//import deimos.p11; "dependencies" : "p11:deimos": "~>0.0.3", // it's an alternative for "dependencies" : "pkcs11": "~>2.40.0-alpha.3"
//import deimos.sodium;

import wrapper.libtasn1 : asn1_array2tree, asn1_parser2tree, asn1_delete_structure, ASN1_SUCCESS;
import tasn1_pkcs15 : tasn1_pkcs15_tab;

import gui : create_dialog_dlg0;
import util_opensc : connect_card, populate_tree_fs, PKCS15_FILE_TYPE, PKCS15,
    errorDescription, fs, appdf, is_ACOSV3_opmodeV3_FIPS_140_2L3,
    is_ACOSV3_opmodeV3_FIPS_140_2L3_active, tnTypePtr;
//    , PRKDF, PUKDF, PUKDF_TRUSTED, SKDF, CDF, CDF_TRUSTED, CDF_USEFUL, DODF, AODF;
import callbacks : btn_sanity_cb,
////    config,
    groupCfg,
    isMFcreated,
    isEF_DIRcreated,
//    isEF_DIRpopulated,
    isappDFdefined,
    isappDFexists,
    appDF,
    cos_version;


import key_asym : keyAsym_initialize_PubObs, prkdf, pukdf;
import key_sym  : keySym_initialize_PubObs,  skdf;


/+
Local imports:
enum string commands1 : import util_general : ubaIntegral2string;
                        import libopensc.opensc : sc_card_ctl;
                        import libopensc.types : sc_serial_number;
                        import libopensc.cardctl    : SC_CARDCTL_GET_SERIALNR;
                        import acos5_64_shared_rust : SC_CARDCTL_ACOS5_HASHMAP_SET_FILE_INFO;
main:                   import pkcs11;
                        import util_pkcs11 : pkcs11_check_return_value/*, pkcs11_get_slot*/;
+/

int main(string[])
{
    writeln;
    /* ASN.1 Initialize PKCS#15 declarations, originating from PKCS15.asn,  via libtasn1 (results in: asn1_node  PKCS15; available in module util_opensc) */
    int parse_result;
    if (true)
        parse_result = asn1_array2tree (tasn1_pkcs15_tab, &PKCS15, errorDescription);
    else
        parse_result = asn1_parser2tree ("PKCS15.asn", &PKCS15, errorDescription);

    if (parse_result != ASN1_SUCCESS)
    {
        writeln(errorDescription);
        exit(EXIT_FAILURE);
    }
/+  once create the array/vector  /* C VECTOR CREATION, to be translated to D */
    import wrapper.libtasn1 : asn1_parser2array, ASN1_MAX_ERROR_DESCRIPTION_SIZE;
    char[ASN1_MAX_ERROR_DESCRIPTION_SIZE] error_desc;
    parse_result = asn1_parser2array ("PKCS15.asn".ptr,
                                      "tasn1_pkcs15.c".ptr,
                                      "tasn1_pkcs15_tab".ptr, error_desc.ptr);
+/

version(I18N)
{
    /* Setting the i18n environment */
    setlocale (LC_ALL, "");
    cast(void) bindtextdomain ("acos5_64_gui", getenv("PWD"));
    cast(void) textdomain ("acos5_64_gui");
    /*printf("bind_textdomain_codeset: %s\n",*/cast(void) bind_textdomain_codeset("acos5_64_gui", "UTF-8");//);
}

    /* IUP initialization */
    IupOpenD();
    IupControlsOpen(); // without this, no Matrix etc. will be visible
    version(Windows)  IupSetGlobal("UTF8MODE", IUP_YES);

    /* Shows dialog */
    create_dialog_dlg0.Show; // this does the mapping; it's early here because some things can be done only after mapping

    int ret;
    /* IUP Config */
/*
    config = new Config;
    config.SetAttribute("APP_NAME", "acos5_64_gui");
    if ((ret= config.LoadConfig) != 0)
    {
        writeln("IupConfigLoad return value: ", ret);
//        exit(EXIT_FAILURE);
    }
*/
    /*
    Workflow:

    entry in $HOME/.acos5_64_gui
    [group]  group shall be the token serial no.
    key=1
    Configuration file
      If there is none, then this card/token wasn't seen before by acos5_64_gui: Be conservative and do basic checks including:
        Is there a MF ?
        Run sanityCheck, if yes
        If no MF, then offer initialization, perhaps based on export/archive
        Remember in Configuration file, thus no superfluous efforts required:
          MF    exists yes/no
          2F00  exists yes/no
          appDF exists yes/no (at least 1 shall exist, more can't be handled currently)
          sanityCheck has run (at least once)

    acos5_64_gui runMode:
       - reduced
       - full (no restrictions what to select from the user interface)

       If the basic requiremnts for full runMode are not met, than

    */

    /* get card's serial no., catch up on everything that was lazily done by the driver */
    enum string commands1 = `
        import libopensc.opensc : sc_card_ctl;
        import libopensc.types : sc_serial_number;
        import libopensc.cardctl : SC_CARDCTL_GET_SERIALNR;
        import util_general : ubaIntegral2string;
        import acos5_64_shared_rust : SC_CARDCTL_ACOS5_GET_COS_VERSION;

        sc_serial_number  serial_number;
        rc = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serial_number);
        if (rc != SC_SUCCESS)
        {
            writeln("FAILED: SC_CARDCTL_GET_SERIALNR");
            exit(1);
        }
        groupCfg = ubaIntegral2string(serial_number.value[0..serial_number.len]);
        rc = sc_card_ctl(card, SC_CARDCTL_ACOS5_GET_COS_VERSION, &cos_version);
        if (rc != SC_SUCCESS)
        {
            writeln("FAILED: SC_CARDCTL_ACOS5_GET_COS_VERSION");
            exit(1);
        }
`;
    mixin (connect_card!(commands1, "EXIT_FAILURE", "3"));
    AA["slot_token"].SetStringId2("", 41,  1, cos_version.value[5].to!string~"."~cos_version.value[6].to!string);
/*
    if (config.GetVariableIntDef(groupCfg.toStringz, "seen", 99) == 99) // then not yet seen this card before, do some sanity-check
    {
        config.SetVariableInt(groupCfg.toStringz, "seen", 1);*/
        AA["sanity_text"].SetString(IUP_APPEND, "Invoked by main, because this card was seen for the first time !");
        btn_sanity_cb(AA["btn_sanity"].GetHandle());/*
        config.SaveConfig();
    }
    else with (config)
    {
        isMFcreated =      GetVariableIntDef(groupCfg.toStringz, "isMFcreated", 0);
        isEF_DIRcreated  = GetVariableIntDef(groupCfg.toStringz, "isEF_DIRcreated", 0);
        isappDFdefined   = GetVariableIntDef(groupCfg.toStringz, "isappDFdefined", 0);
        isappDFexists    = GetVariableIntDef(groupCfg.toStringz, "isappDFexists", 0);
        if (isappDFexists)
            appDF        = GetVariableStrDef(groupCfg.toStringz, "appDF", "").fromStringz.idup;
    }
*/
    /* TODO Make accessible from GUI only, what makes sense acccording to card contents. E.g. if no MF, then no file system tree-view etc.*/
    if (isMFcreated /*&& isEF_DIRcreated && isappDFdefined && isappDFexists*/)
    {
        enum string commands2 = `
        import libopensc.opensc : sc_card_ctl;
        import acos5_64_shared_rust : SC_CARDCTL_ACOS5_HASHMAP_SET_FILE_INFO;

        /*
           This is the idea:
           OpenSC-centric code (including PKCS#15-File-type detection) moves to the driver, ideally no opensc dependency anymore
           The driver offers functions to get all information about the file system, via sc_card_ctl:
           sc_card_ctl(card, SC_CARDCTL_ACOS5_HASHMAP_SET_FILE_INFO, null); // catch up on everything that was lazily done by the driver
           sc_card_ctl(card, SC_CARDCTL_ACOS5_HASHMAP_GET_FILE_INFO, CardCtlArray32*); // get the info for a given key/file id
        */

        rc = sc_card_ctl(card, SC_CARDCTL_ACOS5_HASHMAP_SET_FILE_INFO, null);
        populate_tree_fs(); // populates PrKDF, PuKDF (and dropdown key pair id),
/+
        sc_path  path;
        sc_format_path("3F0041004120", &path);
        rc= sc_select_file(card, &path, null);

//        ubyte[8] pin = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
//        int tries_left;
//        rc= sc_verify(card, SC_AC.SC_AC_CHV, 0x81, pin.ptr, pin.length, &tries_left);
        assert(rc == SC_SUCCESS); // return EXIT_FAILURE;

        rc= uploadHexfile(card, "/path/to/cert.hex", 0, 1664, 0);
//        assert(rc==1664 /*lenWritten*/); // return EXIT_FAILURE;
+/
`;
        mixin (connect_card!(commands2, "EXIT_FAILURE", "3"));
/* * /
        writeln("PRKDF.length:         ", PRKDF.length);
        writeln("PUKDF.length:         ", PUKDF.length);
        writeln("PUKDF_TRUSTED.length: ", PUKDF_TRUSTED.length);

        writeln("SKDF.length:          ", SKDF.length);
        writeln("CDF.length:           ", CDF.length);
        writeln("CDF_TRUSTED.length:   ", CDF_TRUSTED.length);
        writeln("CDF_USEFUL.length:    ", CDF_USEFUL.length);
        writeln("DODF.length:          ", DODF.length);
        writeln("AODF.length:          ", AODF.length);

        foreach (nodeFS; fs.rangePreOrder()) {
            writefln("0x[%(%02X %)]", nodeFS.data);
        }
/ * */

        prkdf = fs.rangePreOrder().locate!"a.data[6]==b"(PKCS15_FILE_TYPE.PKCS15_PRKDF);
        pukdf = fs.rangePreOrder().locate!"a.data[6]==b"(PKCS15_FILE_TYPE.PKCS15_PUKDF);
        skdf  = fs.rangePreOrder().locate!"a.data[6]==b"(PKCS15_FILE_TYPE.PKCS15_SKDF);

        if (prkdf && pukdf)
            keyAsym_initialize_PubObs();
        else
            AA["tabCtrl"].SetStringId("TABVISIBLE", 2, "NO");
        if (skdf)
            keySym_initialize_PubObs();
        else
            AA["tabCtrl"].SetStringId("TABVISIBLE", 3, "NO");
    }

/+
    // testing, that the 2 tree representations (AA["tree_fs"] and fs) are well connnected/synchronized and
         how to retrieve data via id or the other direction, via tnTypePtr nodeFS:
    import std.string;
    auto   tr = cast(iup.iup_plusD.Tree) AA["tree_fs"];
    int cnt = tr.GetInteger("COUNT");

    writeln("tree node count: ", cnt);
    foreach (id; 0..cnt) {
        auto nodeFS = cast(tnTypePtr) tr.GetUserId(id);
        writefln("%d  %s   %(%02X %)", id, tr.GetAttributeId("TITLE", id).fromStringz, nodeFS? nodeFS.data : ub32.init);
    }
tree node count: 40
0   file system   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
1   3F00  MF                                                                   3F 02 3F 00 00 00 FF 05   3F 00
2   0001  iEF linear-fix, size 21 (1x21) B    Pin (global)                     0A 04 00 01 15 01 FF 05   3F 00 00 01
3   0002  iEF linear-var, size max. 148 (4x37 max.) B    SymKeys (global)      0C 04 00 02 25 04 FF 05   3F 00 00 02
4   0003  iEF linear-var, size max. 48 (1x48 max.) B    SecEnv of directory    1C 04 00 03 30 01 FF 05   3F 00 00 03
5   2F00  wEF transparent, size 33 B    EF(DIR)                                01 04 2F 00 00 21 0A 05   3F 00 2F 00 00 00 00 00 00 00 00 00 00 00 00 00   00 01 FF 01 01 FF 01 FF
6   4100  DF                                                                   38 04 41 00 00 00 0E 05   3F 00 41 00 00 00 00 00 00 00 00 00 00 00 00 00   01 01 01 01 00 FF 03 FF
7   4101  iEF linear-fix, size 21 (1x21) B    Pin (local)                      0A 06 41 01 15 01 FF 05   3F 00 41 00 41 01
8   4102  iEF linear-var, size max. 444 (12x37 max.) B    SymKeys (local)      0C 06 41 02 25 0C FF 05   3F 00 41 00 41 02
9   4103  iEF linear-var, size max. 448 (8x56 max.) B    SecEnv of directory   1C 06 41 03 38 08 FF 05   3F 00 41 00 41 03
10   4111  wEF transparent, size 128 B    EF(AODF)                             01 06 41 11 00 80 08 01   3F 00 41 00 41 11 00 00 00 00 00 00 00 00 00 00   00 00 FF 03 00 FF 03 FF
11   4112  wEF transparent, size 768 B    EF(PrKDF)                            01 06 41 12 03 00 00 01   3F 00 41 00 41 12 00 00 00 00 00 00 00 00 00 00   00 00 FF 03 00 FF 03 FF
12   4113  wEF transparent, size 1536 B    EF(PuKDF)                           01 06 41 13 06 00 01 01   3F 00 41 00 41 13 00 00 00 00 00 00 00 00 00 00   00 00 FF 03 00 FF 03 FF
13   4114  wEF transparent, size 256 B    EF(SKDF)                             01 06 41 14 01 00 03 01   3F 00 41 00 41 14 00 00 00 00 00 00 00 00 00 00   00 00 FF 03 00 FF 03 FF
14   4115  wEF transparent, size 256 B    EF(CDF)                              01 06 41 15 01 00 04 01   3F 00 41 00 41 15 00 00 00 00 00 00 00 00 00 00   00 00 FF 03 00 FF 03 FF
15   4120  wEF transparent, size 1664 B    EF(Cert)                            01 06 41 20 06 80 0F 01   3F 00 41 00 41 20 00 00 00 00 00 00 00 00 00 00   00 01 FF 01 00 FF 01 FF
16   41F4  iEF transparent, size 261 B    EF(RSA_PRIV)                         09 06 41 F4 01 05 10 05   3F 00 41 00 41 F4 00 00 00 00 00 00 00 00 00 00   FF 01 01 01 00 FF 01 FF
17   4134  iEF transparent, size 277 B    EF(RSA_PUB)                          09 06 41 34 01 15 09 05   3F 00 41 00 41 34 00 00 00 00 00 00 00 00 00 00   00 01 00 01 00 FF 01 FF
18   5032  wEF transparent, size 192 B    EF(TokenInfo)                        01 06 50 32 00 C0 0C 05   3F 00 41 00 50 32 00 00 00 00 00 00 00 00 00 00   00 00 FF 03 00 FF 03 FF
19   5031  wEF transparent, size 108 B    EF(ODF)                              01 06 50 31 00 6C 0B 05   3F 00 41 00 50 31 00 00 00 00 00 00 00 00 00 00   00 00 FF 03 00 FF 03 FF
20   5155  wEF linear-var, size max. 260 (2x130 max.) B                        04 06 51 55 82 02 FF 05   3F 00 41 00 51 55
21   4129  wEF linear-fix, size 40 (2x20) B                                    02 06 41 29 14 02 FF 05   3F 00 41 00 41 29
22   4131  iEF transparent, size 533 B    EF(RSA_PUB)                          09 06 41 31 02 15 09 05   3F 00 41 00 41 31 00 00 00 00 00 00 00 00 00 00   00 01 00 01 00 FF 01 FF
23   41F1  iEF transparent, size 1285 B    EF(RSA_PRIV)                        09 06 41 F1 05 05 10 05   3F 00 41 00 41 F1 00 00 00 00 00 00 00 00 00 00   FF 01 01 01 00 FF 01 FF
24   4132  iEF transparent, size 533 B    EF(RSA_PUB)                          09 06 41 32 02 15 09 05   3F 00 41 00 41 32 00 00 00 00 00 00 00 00 00 00   00 01 00 01 00 FF 01 FF
25   41F2  iEF transparent, size 1285 B    EF(RSA_PRIV)                        09 06 41 F2 05 05 10 05   3F 00 41 00 41 F2 00 00 00 00 00 00 00 00 00 00   FF 01 01 01 00 FF 01 FF
26   4133  iEF transparent, size 533 B    EF(RSA_PUB)                          09 06 41 33 02 15 09 05   3F 00 41 00 41 33 00 00 00 00 00 00 00 00 00 00   00 01 00 01 00 FF 01 FF
27   41F3  iEF transparent, size 1285 B    EF(RSA_PRIV)                        09 06 41 F3 05 05 10 05   3F 00 41 00 41 F3 00 00 00 00 00 00 00 00 00 00   FF 01 01 01 00 FF 01 FF
28   3908  wEF transparent, size 16 B                                          01 06 39 08 00 10 FF 05   3F 00 41 00 39 08
29   4300  DF                                                                        38 06 43 00 00 00 FF 05 3F 00 41 00 43 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
30   4301  iEF linear-fix, size 21 (1x21) B    Pin (local)                           0A 08 43 01 15 01 FF 05 3F 00 41 00 43 00 43 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
31   4302  iEF linear-var, size max. 74 (2x37 max.) B    SymKeys (local)             0C 08 43 02 25 02 FF 05 3F 00 41 00 43 00 43 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
32   4303  iEF linear-var, size max. 168 (3x56 max.) B    SecEnv of directory        1C 08 43 03 38 03 FF 05 3F 00 41 00 43 00 43 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
33   4331  iEF transparent, size 533 B    EF(RSA)                                    09 08 43 31 02 15 FF 05 3F 00 41 00 43 00 43 31 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
34   4305  wEF transparent, size 16 B                                                01 08 43 05 00 10 FF 05 3F 00 41 00 43 00 43 05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
35   43F1  iEF transparent, size 1285 B    EF(RSA)                                   09 08 43 F1 05 05 FF 05 3F 00 41 00 43 00 43 F1 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
36   3903  wEF linear-fix, size 32 (2x16) B                                    02 06 39 03 10 02 FF 05   3F 00 41 00 39 03
37   3904  wEF linear-fix, size 32 (2x16) B                                    02 06 39 04 10 02 FF 05   3F 00 41 00 39 04
38   3905  wEF linear-var, size max. 32 (2x16 max.) B                          04 06 39 05 10 02 FF 05   3F 00 41 00 39 05
39   3906  wEF linear-var, size max. 32 (2x16 max.) B                          04 06 39 06 10 02 FF 05   3F 00 41 00 39 06

    foreach (id; 0..cnt)
        with (tr) writefln("%d  %d  %d  %d  %d  %d  %d    %d  %d   %s   %s",  id, GetIntegerId("PARENT", id), GetIntegerId("PREVIOUS", id), GetIntegerId("NEXT", id),
            GetIntegerId("FIRST", id), GetIntegerId("LAST", id),    GetIntegerId("DEPTH", id),
            GetIntegerId("CHILDCOUNT", id), GetIntegerId("TOTALCHILDCOUNT", id),  GetAttributeId("KIND", id).fromStringz, GetAttributeId("TITLE", id).fromStringz);


id   p
0    0   0   0   0   0  0     1  39   BRANCH  file system

1    0   0   0   1   1  1     5  38   BRANCH  3F00  MF
2    1   0   3   2   6  2     0   0   LEAF    0001  iEF linear-fix, size 21 (1x21) B    Pin (global)
3    1   2   4   2   6  2     0   0   LEAF    0002  iEF linear-var, size max. 148 (4x37 max.) B    SymKeys (global)
4    1   3   5   2   6  2     0   0   LEAF    0003  iEF linear-var, size max. 48 (1x48 max.) B    SecEnv of directory
5    1   4   6   2   6  2     0   0   LEAF    2F00  wEF transparent, size 33 B    EF(DIR)

6    1   5   0   2   6  2    27  33   BRANCH  4100  DF
7    6   0   8   7  39  3     0   0   LEAF    4101  iEF linear-fix, size 21 (1x21) B    Pin (local)
8    6   7   9   7  39  3     0   0   LEAF    4102  iEF linear-var, size max. 444 (12x37 max.) B    SymKeys (local)
9    6   8  10   7  39  3     0   0   LEAF    4103  iEF linear-var, size max. 448 (8x56 max.) B    SecEnv of directory
10   6   9  11   7  39  3     0   0   LEAF    4111  wEF transparent, size 128 B    EF(AODF)
11   6  10  12   7  39  3     0   0   LEAF    4112  wEF transparent, size 768 B    EF(PrKDF)
12   6  11  13   7  39  3     0   0   LEAF    4113  wEF transparent, size 1536 B    EF(PuKDF)
13   6  12  14   7  39  3     0   0   LEAF    4114  wEF transparent, size 256 B    EF(SKDF)
14   6  13  15   7  39  3     0   0   LEAF    4115  wEF transparent, size 256 B    EF(CDF)
15   6  14  16   7  39  3     0   0   LEAF    4120  wEF transparent, size 1664 B    EF(Cert)
16   6  15  17   7  39  3     0   0   LEAF    41F4  iEF transparent, size 261 B    EF(RSA_PRIV)
17   6  16  18   7  39  3     0   0   LEAF    4134  iEF transparent, size 277 B    EF(RSA_PUB)
18   6  17  19   7  39  3     0   0   LEAF    5032  wEF transparent, size 192 B    EF(TokenInfo)
19   6  18  20   7  39  3     0   0   LEAF    5031  wEF transparent, size 108 B    EF(ODF)
20   6  19  21   7  39  3     0   0   LEAF    5155  wEF linear-var, size max. 260 (2x130 max.) B
21   6  20  22   7  39  3     0   0   LEAF    4129  wEF linear-fix, size 40 (2x20) B
22   6  21  23   7  39  3     0   0   LEAF    4131  iEF transparent, size 533 B    EF(RSA_PUB)
23   6  22  24   7  39  3     0   0   LEAF    41F1  iEF transparent, size 1285 B    EF(RSA_PRIV)
24   6  23  25   7  39  3     0   0   LEAF    4132  iEF transparent, size 533 B    EF(RSA_PUB)
25   6  24  26   7  39  3     0   0   LEAF    41F2  iEF transparent, size 1285 B    EF(RSA_PRIV)
26   6  25  27   7  39  3     0   0   LEAF    4133  iEF transparent, size 533 B    EF(RSA_PUB)
27   6  26  28   7  39  3     0   0   LEAF    41F3  iEF transparent, size 1285 B    EF(RSA_PRIV)
28   6  27  29   7  39  3     0   0   LEAF    3908  wEF transparent, size 16 B
29   6  28  36   7  39  3     6   6   BRANCH  4300  DF
30  29   0  31  30  35  4     0   0   LEAF    4301  iEF linear-fix, size 21 (1x21) B    Pin (local)
31  29  30  32  30  35  4     0   0   LEAF    4302  iEF linear-var, size max. 74 (2x37 max.) B    SymKeys (local)
32  29  31  33  30  35  4     0   0   LEAF    4303  iEF linear-var, size max. 168 (3x56 max.) B    SecEnv of directory
33  29  32  34  30  35  4     0   0   LEAF    4331  iEF transparent, size 533 B    EF(RSA)
34  29  33  35  30  35  4     0   0   LEAF    4305  wEF transparent, size 16 B
35  29  34   0  30  35  4     0   0   LEAF    43F1  iEF transparent, size 1285 B    EF(RSA)
36   6  29  37   7  39  3     0   0   LEAF    3903  wEF linear-fix, size 32 (2x16) B
37   6  36  38   7  39  3     0   0   LEAF    3904  wEF linear-fix, size 32 (2x16) B
38   6  37  39   7  39  3     0   0   LEAF    3905  wEF linear-var, size max. 32 (2x16 max.) B
39   6  38   0   7  39  3     0   0   LEAF    3906  wEF linear-var, size max. 32 (2x16 max.) B



    foreach (tnTypePtr nodeFS, ref typeof(tnTypePtr.data) elem; fs.preOrderRange(fs.begin(), fs.end()))
        writefln("%d  %(%02X %)", tr.GetId(nodeFS), elem);

1   3F 02 3F 00 00 00 FF 05   3F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
2   0A 04 00 01 15 01 FF 05   3F 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
3   0C 04 00 02 25 04 FF 05   3F 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
4   1C 04 00 03 30 01 FF 05   3F 00 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
5   01 04 2F 00 00 21 0A 05   3F 00 2F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 FF 01 01 FF 01 FF
6   38 04 41 00 00 00 0E 05   3F 00 41 00 00 00 00 00 00 00 00 00 00 00 00 00 01 01 01 01 00 FF 03 FF
7   0A 06 41 01 15 01 FF 05   3F 00 41 00 41 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
8   0C 06 41 02 25 0C FF 05   3F 00 41 00 41 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
9   1C 06 41 03 38 08 FF 05   3F 00 41 00 41 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
10  01 06 41 11 00 80 08 01   3F 00 41 00 41 11 00 00 00 00 00 00 00 00 00 00 00 00 FF 03 00 FF 03 FF
11  01 06 41 12 03 00 00 01   3F 00 41 00 41 12 00 00 00 00 00 00 00 00 00 00 00 00 FF 03 00 FF 03 FF
12  01 06 41 13 06 00 01 01   3F 00 41 00 41 13 00 00 00 00 00 00 00 00 00 00 00 00 FF 03 00 FF 03 FF
13  01 06 41 14 01 00 03 01   3F 00 41 00 41 14 00 00 00 00 00 00 00 00 00 00 00 00 FF 03 00 FF 03 FF
14  01 06 41 15 01 00 04 01   3F 00 41 00 41 15 00 00 00 00 00 00 00 00 00 00 00 00 FF 03 00 FF 03 FF
15  01 06 41 20 06 80 0F 01   3F 00 41 00 41 20 00 00 00 00 00 00 00 00 00 00 00 01 FF 01 00 FF 01 FF
16  09 06 41 F4 01 05 10 05   3F 00 41 00 41 F4 00 00 00 00 00 00 00 00 00 00 FF 01 01 01 00 FF 01 FF
17  09 06 41 34 01 15 09 05   3F 00 41 00 41 34 00 00 00 00 00 00 00 00 00 00 00 01 00 01 00 FF 01 FF
18  01 06 50 32 00 C0 0C 05   3F 00 41 00 50 32 00 00 00 00 00 00 00 00 00 00 00 00 FF 03 00 FF 03 FF
19  01 06 50 31 00 6C 0B 05   3F 00 41 00 50 31 00 00 00 00 00 00 00 00 00 00 00 00 FF 03 00 FF 03 FF
20  04 06 51 55 82 02 FF 05   3F 00 41 00 51 55 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
21  02 06 41 29 14 02 FF 05   3F 00 41 00 41 29 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
22  09 06 41 31 02 15 09 05   3F 00 41 00 41 31 00 00 00 00 00 00 00 00 00 00 00 01 00 01 00 FF 01 FF
23  09 06 41 F1 05 05 10 05   3F 00 41 00 41 F1 00 00 00 00 00 00 00 00 00 00 FF 01 01 01 00 FF 01 FF
24  09 06 41 32 02 15 09 05   3F 00 41 00 41 32 00 00 00 00 00 00 00 00 00 00 00 01 00 01 00 FF 01 FF
25  09 06 41 F2 05 05 10 05   3F 00 41 00 41 F2 00 00 00 00 00 00 00 00 00 00 FF 01 01 01 00 FF 01 FF
26  09 06 41 33 02 15 09 05   3F 00 41 00 41 33 00 00 00 00 00 00 00 00 00 00 00 01 00 01 00 FF 01 FF
27  09 06 41 F3 05 05 10 05   3F 00 41 00 41 F3 00 00 00 00 00 00 00 00 00 00 FF 01 01 01 00 FF 01 FF
28  01 06 39 08 00 10 FF 05   3F 00 41 00 39 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
29  38 06 43 00 00 00 FF 05   3F 00 41 00 43 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
30  0A 08 43 01 15 01 FF 05   3F 00 41 00 43 00 43 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
31  0C 08 43 02 25 02 FF 05   3F 00 41 00 43 00 43 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
32  1C 08 43 03 38 03 FF 05   3F 00 41 00 43 00 43 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
33  09 08 43 31 02 15 FF 05   3F 00 41 00 43 00 43 31 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
34  01 08 43 05 00 10 FF 05   3F 00 41 00 43 00 43 05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
35  09 08 43 F1 05 05 FF 05   3F 00 41 00 43 00 43 F1 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
36  02 06 39 03 10 02 FF 05   3F 00 41 00 39 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
37  02 06 39 04 10 02 FF 05   3F 00 41 00 39 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
38  04 06 39 05 10 02 FF 05   3F 00 41 00 39 05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
39  04 06 39 06 10 02 FF 05   3F 00 41 00 39 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
+/

// some explanatory texts
    AA["fs_text_asn1"].SetAttributeVALUE("");
    AA["fs_text"].SetAttributeVALUE("");
    AA["fs_text"].SetString(IUP_APPEND, " ");
    AA["fs_text"].SetString(IUP_APPEND, "The translation feature is used currently for the superfluous button text Exit only.\n");
    AA["fs_text"].SetString(IUP_APPEND, "It translates to Beenden, if the locale is a german one and if de/LC_MESSAGES/acos5_64_gui.mo got pushed\n");
    AA["fs_text"].SetString(IUP_APPEND, `
A remark upfront: While ACOS supports SFI (Short File Identifier), it's used neither by opensc, nor by the driver or this app. Only regular FID (File Identifier) 2 Bytes long are used !
Also, pathes are used only as absolute pathes, thus beginning at root FID 0x3F00. A path may consist of max 8 FID components (opensc limitation), but it's recommended to use only max 5 FID components,
an acos limitation: Access control information of files/directories in deeper levels of the file system hierarchy don't get stored ! Thus You would go unprotected there.

It's warmly recommended to have only distinct FIDs within the card file system. This can be respected even with multiple PKCS#15 applications by specific entries in EF.DIR, replacing the mandatory standard FIDs.
The reason is, that acos has a putative smart file search algorithm if a file doesn't get found immediately. Thus with duplicate FIDs there is a potential to select and possibly operate on a different file than intended.
Also, the driver does track the current position of file selection in order to minimize the number of selections required to get to a new selected target. In rare cases, a disoriented tracking by duplicated FID may lead to
problems finding a file (if only a FID but no absolute path is given as select target; in the past opensc sometimes did that) !
Sadly, there is no means to detect explicitely, where the acos internal file selection points to !
It's better to not find a file than find the wrong file, but the acos putative smart file search algorithm can't be disabled.


The semantic/meaning of files is either implicitely known to acos (by File Descriptor Byte FDB) or
known to this application (by file introspection for transparent files) or
unknown (visualized by a dot image symbol).
Symbol images and last text component in each node's text further contain semantic information, if available.

There are 2 kind of trees maintained by this application:
1. Tne file system tree with it's visual representation of hierarchical file structure.
2. The 'PKCS#15 file tree' (a subset of file system tree), which is visualized by 'sheet of paper' images (blank or written)
   and comprises those files, that are detected/introspected and verified to be mentioned in PKCS#15 file structure.
   Only files with 'sheet of paper'-image are known to PKCS#15/opensc (+ the internal Elementary Files of type Pin, Symkey and SecEnv,
   which are shown without any image at all: They (usually all 3, maybe except Symkey) are core files for security and access control in each directory.
   written-'sheet of paper'-image files are organizational (object directory) files.
   blank-'sheet of paper'-image files are the leaf files containing specific objects like RSA key, certificate etc. .

Also, some files are mandatory for a PKCS#15 file structure and have (acc. standard) a meaning by file id, which are:
3F00 : MF, the file system root
2F00 : EF.DIR
5031 : EF.OD  in each application directory
5032 : EF.CardInfo  in each application directory

Usually, there should be no (unknown meaning) dot-symbol files, except You know what they are for.
Those existing in this example are:
5155, 4129: Leftovers from ACOS client kit, subject to removal where possible and still to be compatible with ACS ACOS5-64 PKCS#11 library.
3901-3908 and 4300 + it's sub-files: Temporary dot-symbol files for testing purposes

The checkbox/toggle is not meant to be used by the user: It just visualizes, whether a file is 'activated' and thus subject to acos access control,
recommended for all files for security reasons.

The access control information is visualized (indirectly) by contents of the Dropdown/ComboBox:
Each file/direcory has 7 bits (Security Attributes Compact SAC) in it's header/meta data storing access control information, different for diverging file descriptor bytes.
thus the maximum of entries in the ComboBox is 7, reduced depending on the "Suppress rare operations"-Checkbox and all operations removed, that are inhibited for that file.
The complete picture of Access Control involves directory file (for delete permission) as well and maybe also Security Attributes Expanded SAE and of course the directory's SecEnv
(Security Environment File). Anyway, what the ComboBox offers, are those operation (groups), that are not forbidden, but they may be subject to further authorization
according to access control (most notably by Pin entry for User or Security Officer (global Pin))
The handling of access control condition 'Secure Messaging required' is handled transparently if no Pin Authorization is involved in the access control,
otherwise, same as for other cases You will be asked for Pin entry if required.

If the Dropdown offers Read-Operation only, this is (depending on Checkbox "Perform 'Read operation' automatically", the sole operation done automatically.
In this sense, the page offers read-only access to the file system.
Any other operation, including writing-to-the-card-operations, require explicit control by clicking button "do it"
Usually all those 'explicit' operations involve some kind of authorization.

Also, You should know this about Pins:
1. opensc is able to cache pin entries for repeated usage (e.g. 10 times) without user consent: This is controlled by the userConsent entry in EF.AOD.
   This is convenient, but my not be what You want. Set userConsent to 1 then.
2. Whether we like it or not, some mainstream applications like Thunderbird/Firefox ask for the user pin upfront, once a PKCS#11 library shall be loaded,
   even if it's not required. Worse, there is no information, what the revealed credential is used for.
   This practice absolutely dissatisfies me, and that's why I tend to not rely on the user pin as a security feature and why the acos5_64 driver offers an
   additional level of control against 'misuse' of private RSA keys: By opensc.conf settings, a graphical popup for additional user consent may be enabled,
   which pops up when a private RSA key shall be used for signing or decrypting, effectively giving control from case to case.
   This is a warmly recommended feature (though not enabled by default currently; disable that only temporarily for pkcs11-tool --test).
   (UPDATE: For some unknown reason that doesn't work and isn't yet implemented by the Rust driver)
  `);

    AA["cst_text"].SetString(IUP_APPEND, `
Some remarks:
The PKCS#11 standard specifies an application programming interface (API), called “Cryptoki,” for devices that hold cryptographic information and perform cryptographic functions.
The standard gets maintained/advanced by OASIS, see also https://en.wikipedia.org/wiki/PKCS_11

The tool works with 1 slot currently only, which is the first one found with a token present ! (There may be more slots with tokens present;
 the first one usually has Slot id : 0; later, there will be a selection for other present tokens)

The version of PKCS#15 / ISO 7816-15 supported by opensc version 19 roughly but not exactly is PKCS#15 v1.1 / ISO 7816-15:2004

Relating to tab 'filesystem':
Toggle: Perform 'Read operation' automatically, if applicable and doesn't require authorization (except SM related):
This means: The read operation will be done automatically if not disallowed by file access permission and if
- No pin verification nor key authentication is required by file access condition, except
  if the file access condition is 'key to be authenticated' and that key is authenticated (automatically) already
  (like it may be configured for SM-protected files if the external authentication key is the key referred to here and
   external authentication was successful; SM-protected file operations invoke external authentication automatically), then do read automatically.

The tool aims at shielding the possibly complex access conditions of files (and commands) from the user and just ask for the required permission(s).
But the sophisticated ACOS features of access conditions like "AND" and "OR" operator aren't implemented currently: Just use simple entries in the SE-file for verification/authentication, with 1 pin or 1 key reference only.
(The nigthmare counter-example would be a file deletion requiring e.g. 4 or more pin verifications/key authentications; the rule above limits that to max. 2 pins/keys, which is also the max. of opensc).
Deletion checks access rigths concerning the file itself and of the DF, this file resides in.
In order to be able to check that, 2 file headers (including the SCB bytes) get printed, the enclosing DF's header and the header of the selected file/DF.


PUKDF doesn't declare any public  RSA key  as private !
PrKDF does    declare all private RSA keys as private and thus also declares an authId!
`);

    AA["gkpRSA_text"].SetString(IUP_APPEND, `
This page is dedicated to 'manipulating/handling' anything about RSA key pair content and/or files, as well as EF(PrKDF) and EF(PuKDF) content.
The basic requirement merely is, that the files PrKDF and PuKDF do exist and are known to opensc (by respective entries in EF(ODF)). PrKDF and PuKDF files may be empty though.

PKCS#15 tells, what EF(PrKDF) and EF(PuKDF) are for: They contain essential information about existing private/public RSA key files as a kind of directory type.
Any operation done on this page will likely have to update these files to be up to date.
ACOS stores a RSA key pair as 2 distinct files within the card's filesystem: A RSA public key file (for modulus N and public exponent e + 5 administrative bytes) and
a RSA private key file (for modulus N and private exponent d + 5 administrative bytes; there is an option to store instead of d the components according to Chinese Remainder Theorem CRT).
Also note the reason, why there is 'Private key usage ACOS' and 'Private key usage PrKDF' and how they are different. The only combinations that make sense, are these:
Private key usage:                           ACOS            PrKDF
Intention: sign (SHA1/SHA256)                sign            sign (,signRecover,nonRepudiation)
Intention: sign (SHA512)                     decrypt,sign    sign (,signRecover,nonRepudiation)
Intention: decrypt,sign (not recommended)    decrypt,sign    decrypt,sign (...)
Intention: decrypt                           decrypt         decrypt (,unwrap)

The primary choice among 4 alternatives is, what to do (choosable within the following radio buttons)
A - Don't change anything stored in the RSA key pair files, thus modifiable is only: "Key pair label", "authId", within reasonable limits "Private key usage PrKDF", "Key pair is modifiable?"
B - Do remove a RSA key pair (delete files and adapt EF(PrKDF) and EF(PuKDF).
C - The RSA key pair files do exist already and get reused: Do regenerate the RSA key pair, with private file known to the card only (should be unreadable, thus it never can be compromised).
D - The RSA key pair files don't exist: Do create new RSA key pair files sized as required and generate the RSA key pair. The file ids are not freely choosable but dictated by the acos5_64.profile file.

It seems to be non-deterministic which parameters N (modulus) and d (private exponent) will be choosen by the internal acos library code and it isn't affected by the CVE-2017-15361 vulnerability (ROCA)
Choices C and B allow to change everything (for B there is the limit what fits into the existing files, possibly limiting modulus bits and/or the CRT choice).
Depending on the primary choice, the following table 'RSA key pair generation attributes' will have varying fields blocked as read-only. The table works Excel-like, i.e. recalculating depending fields and status.
In order to keep the code simple, not all 'impossible' options (e.g. from Drop-Down choices selectable) get blocked rigth away, but all entries constantly get checked afterwards whether they are appropriate for the selected primary choice operation, signaling the overall status by color.
E.g. for choice D, a red status may occur, if EF(PrKDF) and/or EF(PuKDF) aren't sized sufficiently to hold new content to be added, or for choice C, if the required storage size of private/public key files is larger then available.

Wrong usage of opensc tools or bug(s) in opensc may lead to 'exploding' EF(PuKDF) file size in that undesirably the modulus gets stored within EF(PuKDF). That may be repaired with the A choice



The files themselves (create/delete) are handled in tab filesystem.

Useful commands for the command line:
$ pkcs15-tool --list-keys

RSA key pair generation can be done in several ways:
(a) By opensc tools (or by PKCS#11 functions C_CreateObject files and C_GenerateKeyPair and update EF(PrKDF) and EF(PuKDF) manually).
    This method lacks full control of acos key pair generation parameters (like CRT style yes/no, sign_only/decrypt_only/sign_and_decrypt.
    The driver handles these possible decisions for this method by hard-coded defaults (CRT yes, sign_and_decrypt).
    pkcs15-init --generate-key rsa/3072 --auth-id 01 --id 46 -vvvv

(b) By this tool with full control of acos key pair generation parameters, and I believe, the algorithm is superior with better user feed back.
    Also, a private key guaranteed to be able to sign or decrypt only, can be generated with method (b) only. This is an additional safety level over declaring in PrKDF/PuKDF only, what the keys are going to be used for: A private key acos-generated e.g. for signing only, can't by design be used for anything else than signing, no matter what PrKDF states (possibly differently; though that should match of course).

The simplest use of this facility is to just replace an existing key pair, i.e. nothing changes from what goes into existing PrKDF/PuKDF entry (also no size-required change), except changing CRT yes/no (as long as it still fits within size limit) and/or changing private/public key usage is allowed:
Enter all 'RSA key pair generation attributes' required (except Key pair label which will not change from existing). They will be checked and used for generation of new key pair in existing files.
There is a checkbox for that intent, but this is not allowed if a certificate refers to this key as the cert would be rendered useless then (thus first delete the cert)

Reminder: The acos command for signing is rather limited in that it does accept only SHA1 and SHA256 hashes. It detects the digest algo from input hash length, generates the digestInfo, ASN.1 encodes and applies the padding selected (PKCS#1 or ISO) and finally signs. Any other hash to be signed (e.g. SHA512 used by Thunderbird) or different padding scheme will rely on driver code which must use acos command 'decrypt' (raw RSA exponentiation) in order to sign. I.e. the key for that must be generated with setting 'private key usage ACOS sign+decrypt !
In order to perform this workaround, the key must be generated as sign+decrypt (dual functionality is not recommended, but there is no way out here). In that case (You want a fully capable key for signing only), don't declare to PrKDF, that the key actually is capable to decrypt as well and opensc will use it for signing only. Merely the driver will switch to try 'decrypt' (there is no way to retrieve whether the key actually is capable of and will allow that) for signing if required, and it will do so in a safe way: Only DigestInfo content for a couple of digest algorithms with valid PKCS#1 padding will be allowed to be signed this way.

The following table works akin Excel does, i.e. deoending on input values, others are calculated based on hidden formulas.
E.g. 'Key pair id' is the input value having the longest chain of recalculation (and also is a special field capable to overwrite other 'input' values: It reads PrKDF and PuKDF for the matching id, resulting in file ids of private and public keys overwritten - and then updating everything depending on that  almost all other fields to 'current' values (all except file id directory and CRT, which is non-retrievable),
The general principle is: The value entered is taken as fixed, all others may change, even if those seem to be (otherwise are) input values only: E.g. Key pair id' also sets RSAModulusBits to the value of the respective key pair referenced, i.e. the order of inputs is significant !
This page assumes, that the directory for the new/existing RSA key pair does exist already, otherwise first create it in tab 'filesystem'

Note on using the RSA keys for signing:
The driver won't sign everything, but only what is valid according to RSASSA-PKCS1-v1_5, where digestAlgorithm may be SHA1 or SHA256.
As the padding will be done by the tools like pkcs11-tool, the following command will work (pin is 12345678 ascii here, the key with id 04 used):
cat data | pkcs11-tool --id 04 -s -p 12345678 -m RSA-PKCS --module /usr/lib/opensc-pkcs11.so > data.sig
if the data file contains exactly:
30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14               + 20 arbitrary bytes  or
30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20   + 32 arbitrary bytes

which is the ASN.1 DER-encoding of
      DigestInfo ::= SEQUENCE {
          digestAlgorithm DigestAlgorithm,
          digest OCTET STRING
      }

If the key to be used for signing was generated using 'Private key usage ACOS'='decrypt, sign', a lot more digestAlgorithm are allowed, and data like this is allowed:
30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40   + 64 arbitrary bytes

ACOS allows specifying a 16 byte public exponent prime, but opensc is limited to max 4 bytes, the lower value of opensc is relevant.
`);
/+
    AA["importExport_text"].SetString(IUP_APPEND, `
Work in progress, writes/exports readable files to /tmp . The archiving to a compressed file is missing and any import is missing.
It's intended, that such an archive file may serve as a backup and be used for initializing the card, populating it with what is in the archive file.
Unreadable contents need to be archived manually or omitted, pins must be written so there are default values to start with. The design needs to be fleshed out.

This applies to the whole file system: (Currently, the output is in /tmp)
First select whether to import or export and enter from/to which file  /path/from//to/file  on the hosting computer.
Export will collect all information retrievable from the card/token and write it to an archive file on the hosting computer.
Import will take an archive file and apply all commands necessary to reconstruct a file system from scratch, based on the enclosed archive information, i.e. 'Import' starts from a virgin card (no existing MF)

The format of the archive file: tar
Files within the archive:
commands_create
tab_hierarchy
...
as many files as mentioned in tab_hierarchy

The non-content files 'commands_create' and 'tab_hierarchy' are ASCII-encoded, thus they can be easily inspected. For processing, they will be translated internally to hex-encoding again.
The content files are raw, hex content, to be inspected by a hex-editor.

An example:
'commands_create' lists all commands that need to be executed to generate the file structure skeleton (i.e. everything except commands to activate and except file contents)
A tool like scriptor from package pcsc-tools would accept file 'commands_create' as batch file and do exactly that generation of the file structure skeleton.
file 'tab_hierarchy' is a no-edit/read-only file, which gets generated from 'commands_create' automatically in order to create the path of each file as a file name entry in this table file.
Suppose, the exported file system had 3 files/directories: The mandatory MF directory, a directory with file id 0x4100, and a file within  directory 0x4100 with file id 0x4101:
The entries in 'tab_hierarchy' will be then
#3F00  5
#3F004100  5
 3F0041004101  5

One more file (other than commands_create, commands_activate, tab_hierarchy)  must exist in this example, named 3F0041004101, which contains the hex content of file with file id 0x4101
If file id 0x4101 where a record-based file with 2 records, each record get's its own file name:
 3F0041004101_1  5
 3F0041004101_2  5

The last digit in the above examples (5) is the LifeCycleStatusInter. 5 means, those files have to be in activazed state in the end.

The import facility will read file contents from those files and write them to the card, For this to work, no file may be acticated until all reconstruction is done. Therefore,
the 'commands_create' may not include setting a LifeCycleStatusInteger nor any activate command
'tab_hierarchy' entries starting with a # are just comments and identify directories; they don't need storing of content

Now let's assume, file id 0x4101 identifies a pin file or a symetric key file; then the recommended file access for those files is non-readable and the export utility will have written a file
named 3F0041004101, but with no content.

For those cases, where You know the content or like to appear specific content, do change contents manually in the archive file.
So far this should work for everything except for RSA key files generated on-card: They never can/should be exportable.
The only way to have an exact clone of a card/token as archive file is to generate RSA keys outside the card, e.g. by openssl commands, write them to the archive manually, respecting the acos format of RSA files and then import the archive to the card/token.

Perhaps I'll offer some single-file-import facility, i.e. limitited to certain files like RSA or certificates etc.

At the moment, my intention is primaryly to get users started with some base installations/import archives supplied to choose from, which are known to work with acos5_64_gui


, but shall list activate commands in the end as required. The batch of 'commands_create' thus gets split into 2 parts:
First the mere create and select commands generating the skeletin, second the select and activate commands which will run in the end.
`);
+/
/* */
    AA["sanity_overview_text"].SetString(IUP_APPEND, `
These sanity checks are intended to be run with ACOS5-64 cards/tokens operating the first time with the acos5_64 driver (and this tool) and are run automatically, if dub.json has dlang version identifier SANITYCHECK defined:
My experience was with ACS client kit software for CryptoMate64, the worst software I ever was forced to buy in order to make use of the token at all, beyond that, constrained to the Windows OS. Don't know if things improved and which options are available nowadays for driver and tool.
Thus it's likely, that the card/token is setup incomplete or wrong or violating requirements of opensc or how the driver libacos5_64.so operates or incompatible with PKCS#15.

The checks may be grouped into these categories:
  Basic, MF, operation mode of the card
  File system (do files required by acos exist, are the settings consistent and appropriate (e.g. recommended access rigths))
  PKCS#15 checks (opensc get's to know - about what is on the token and what it's for - only by additional PKCS#15 files. If contents are wrong or pointing to nowhere, then opensc won't e.g. know about existing RSA keys and what they shall be used for, possibly won't know any pin etc. Thus it's vital that these PKCS#15 files are permanently sane.
    as many operations do change some PKCS#15 file content, it's worth to do the sanity check once in a while (opensc is not absolutely free of bugs in this regard))
  Limits. Ordinary file systems allow e.g. a deep hierarchy of nesting files, e.g on Linux /level2/level3.../level99/file_in_level99. opensc constrains this to max. file_in_level7, i.e. max 8x2byte path-components may be stored like e.g. max 3F004200430044004500460047004799.
    The acos limit is even shorter if You emphasize file access rigths: Acos doesn't store access rigths beyond levelx, Thus everything there is completely unprotected and should be avoided for a crypto-token
    Many limitations are imposed by the complexity of PKCS#15. When ASN.1-decoding such content, opensc does an "easy" job by just cherry-picking some interesting content

    There is another limitation from the driver: Do use unique file ids only! Why that? Just suppose You have 2 files named "1234" on Your token and now You do a select 1234. Which one will be selected? It depends (on where the internal current selection pointer is pointing to).
    Now suppose one of those got deleted but deletion got forgoten and You try to select the deleted 1234 right from a position where it would be selected first. Now do the select 1234. What is the answer expected? Probably 'File not found', but in reality most likely the other existing file 1234 will be selected !
    It's vital for the driver to always know, what exactly is the currently selected file.
    But ACS wanted to be smart and implemented some additional places to search for in case of 'File not found', which opened the door of ambiguity.
    Also, I once managed to have 2 files named "1234" within the same directory, impossible acc. to the ref. manual but doable and plain wrong; thus there must be some bug in acos while trying to prevent that.
`);

/*
    version (Windows) {}
    else
    AA["ssh_text"].SetString(IUP_APPEND, `Currently its required to first add token's keys to ssh-agent: ssh-add -s /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`);
*/
    /* all the above and any use of mixin (connect_card!... will be logged for [acos5_gui], only the next block scope will be logged for [opensc-pkcs11] */

    /*
       One way to access the card/token is via util_connect_card, which uses functions from libopensc.so, but nothing from opensc-pkcs11.so.
       The other way is through the PKCS#11/Cryptoki interface, used in the following. It uses the specified or preconfigured (p11-kit) PKCS#11 library,
       which may be any one capable to support ACOS5-64, likely opensc-pkcs11.so (or even better if installed: p11-kit-proxy.so)
    */
//    if (isMFcreated)
    { // scope for scope(exit)  PKCS11.unload();
        import util_pkcs11 : pkcs11_check_return_value/*, pkcs11_get_slot*/;
        import pkcs11 : PKCS11, NULL_PTR, CKR_OK, CK_RV, CK_ULONG, CK_TRUE, CK_SLOT_ID, CK_SLOT_INFO, CK_TOKEN_INFO,
            CK_INFO, CK_C_INITIALIZE_ARGS, CKF_OS_LOCKING_OK,
            CKF_TOKEN_PRESENT, CKF_REMOVABLE_DEVICE, CKF_HW_SLOT, CKF_RNG, CKF_WRITE_PROTECTED, CKF_LOGIN_REQUIRED,
            CKF_USER_PIN_INITIALIZED, CKF_PROTECTED_AUTHENTICATION_PATH, CKF_DUAL_CRYPTO_OPERATIONS,
            CKF_TOKEN_INITIALIZED, CKF_SECONDARY_AUTHENTICATION, CKF_ERROR_STATE,
            CKF_USER_PIN_COUNT_LOW, CKF_USER_PIN_FINAL_TRY, CKF_USER_PIN_LOCKED, CKF_USER_PIN_TO_BE_CHANGED,
            CKF_SO_PIN_COUNT_LOW, CKF_SO_PIN_FINAL_TRY, CKF_SO_PIN_LOCKED, CKF_SO_PIN_TO_BE_CHANGED,
            C_Initialize, C_Finalize, C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo, C_GetInfo;

        // this one-liner enables operating with the module specified
        PKCS11.load("opensc-pkcs11.so"); // or with p11-kit and highest priority for opensc-pkcs11.so: p11-kit-proxy.so
        scope(exit)
            PKCS11.unload();
        // Now PKCS#11 functions can be called, but as latest opensc-pkcs11.so implements Cryptoki API v2.20
        // and the headers cover API v2.40 as well, take care not to use/call anything unavailable !
        CK_RV rv;
        /* We aren't going to access the Cryptoki library from multiple threads simultaneously */
        CK_C_INITIALIZE_ARGS  init_args;
        init_args.flags = CKF_OS_LOCKING_OK;

        if ((rv= C_Initialize(&init_args)) != CKR_OK)  // CKR_ARGUMENTS_BAD, CKR_CANT_LOCK, CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_NEED_TO_CREATE_THREADS, CKR_OK.
        {
            writeln("Failed to initialze Cryptoki");
            return EXIT_FAILURE;
        }
        scope(exit)
            C_Finalize(NULL_PTR);

        Handle h = AA["slot_token"];

        CK_INFO  info; /* C_GetInfo returns general information about Cryptoki. */
        pkcs11_check_return_value(rv= C_GetInfo(&info), "get info");
        with (info) with (h)
        {
            SetStringId2("",  1,  1, cryptokiVersion.major.to!string ~"."~ cryptokiVersion.minor.to!string);
            SetStringId2("",  2,  1, manufacturerID.assumeUTF.stripRight.to!string);
         //SetIntegerId2("", ??,  1, cast(int) flags);
            SetStringId2("",  3,  1, libraryDescription.assumeUTF.stripRight.to!string);
            SetStringId2("",  4,  1, libraryVersion.major.to!string~"."~libraryVersion.minor.to!string);
        }

        CK_SLOT_ID[10]  slotIds; /* Slot       A logical reader that potentially contains a token. */
        CK_ULONG        slotCount;
        // size query
        pkcs11_check_return_value(rv= C_GetSlotList(CK_TRUE, null, &slotCount), "get slot list (size query)");
        if (rv != CKR_OK || slotCount == 0  ||  slotCount > slotIds.length)
        {
            h.SetIntegerId2 ("",  5,  1, cast(int) slotCount);
            if (slotCount==0 && rv == CKR_OK)
                writeln("### There is no PKCS#15 strucure, thus no slot can be assigned! ###");
            else
                writeln("Error: Could not find any slots or more than 10 slots with a token present found "~
                    "(dev: adjust array size?)");
//            exit(EXIT_FAILURE);
        }
        else
        {
            pkcs11_check_return_value(rv= C_GetSlotList(CK_TRUE, slotIds.ptr, &slotCount), "get slot list");
            if (rv != CKR_OK)
                exit(EXIT_FAILURE);

            CK_SLOT_ID  slotID;
/*
            foreach (slot; slotIds[0..slotCount]) {
                CK_SLOT_INFO  slotInfoLocal;
                pkcs11_check_return_value(rv= C_GetSlotInfo(slot, &slotInfoLocal), "get slot info");
                if (rv != CKR_OK)
                    continue;
//                if (slotInfoLocal.slotDescription.assumeUTF.stripRight.startsWith("ACS CryptoMate64"))
//                    slotID = slot;
//                if (slotInfoLocal.slotDescription.assumeUTF.stripRight.startsWith("ACS CryptoMate (T2)"))
//                    slotID = slot;
            }
*/
            slotID = slotIds[0];

            h.SetIntegerId2 ("",  5,  1, cast(int) slotCount);
            h.SetIntegerId2 ("",  6,  1, cast(int) slotID);

            CK_SLOT_INFO  slotInfo; /* C_GetSlotInfo obtains information about a particular slot in the system. */
            pkcs11_check_return_value(rv= C_GetSlotInfo(slotID, &slotInfo), "get slot info");
            with (slotInfo) with (h)
            {
                SetStringId2("",  7,  1, slotDescription.assumeUTF.stripRight.to!string);
                SetStringId2("",  8,  1, manufacturerID.assumeUTF.stripRight.to!string);
             //SetIntegerId2("", ??,  1, cast(int) flags);
                if (flags & CKF_TOKEN_PRESENT)     SetIntegerId2("",  9,  1,  1); /* a token is there */
                if (flags & CKF_REMOVABLE_DEVICE)  SetIntegerId2("", 10,  1,  1); /* removable devices*/
                if (flags & CKF_HW_SLOT)           SetIntegerId2("", 11,  1,  1); /* hardware slot */
                SetStringId2("", 12,  1, hardwareVersion.major.to!string~"."~hardwareVersion.minor.to!string~" / "~
                                     firmwareVersion.major.to!string~"."~firmwareVersion.minor.to!string);
            }

            CK_TOKEN_INFO tokenInfo; /* C_GetTokenInfo obtains information about a particular token in the system. */
            pkcs11_check_return_value(rv= C_GetTokenInfo(slotID, &tokenInfo), "get token info");
            with (tokenInfo) with (h)
            {
                SetStringId2("", 13,  1, label.assumeUTF.stripRight.to!string);
                SetStringId2("", 14,  1, manufacturerID.assumeUTF.stripRight.to!string);
                SetStringId2("", 15,  1, model.assumeUTF.stripRight.to!string);
                SetStringId2("", 16,  1, stripRight(cast(string) serialNumber[]));
                SetIntegerId2("",17,  1, cast(int) flags);
                if (flags & CKF_RNG)                           SetIntegerId2("", 18,  1,  1);
                if (flags & CKF_WRITE_PROTECTED)               SetIntegerId2("", 19,  1,  1);
                if (flags & CKF_LOGIN_REQUIRED)                SetIntegerId2("", 20,  1,  1);
                if (flags & CKF_USER_PIN_INITIALIZED)          SetIntegerId2("", 21,  1,  1);
                if (flags & CKF_PROTECTED_AUTHENTICATION_PATH) SetIntegerId2("", 22,  1,  1);
                if (flags & CKF_DUAL_CRYPTO_OPERATIONS)        SetIntegerId2("", 23,  1,  1);
                if (flags & CKF_TOKEN_INITIALIZED)             SetIntegerId2("", 24,  1,  1);
                if (flags & CKF_SECONDARY_AUTHENTICATION)      SetIntegerId2("", 25,  1,  1);
                if (flags & CKF_USER_PIN_COUNT_LOW)            SetIntegerId2("", 26,  1,  1);
                if (flags & CKF_USER_PIN_FINAL_TRY)            SetIntegerId2("", 27,  1,  1);
                if (flags & CKF_USER_PIN_LOCKED)               SetIntegerId2("", 28,  1,  1);
                if (flags & CKF_USER_PIN_TO_BE_CHANGED)        SetIntegerId2("", 29,  1,  1);
                if (flags & CKF_SO_PIN_COUNT_LOW)              SetIntegerId2("", 30,  1,  1);
                if (flags & CKF_SO_PIN_FINAL_TRY)              SetIntegerId2("", 31,  1,  1);
                if (flags & CKF_SO_PIN_LOCKED)                 SetIntegerId2("", 32,  1,  1);
                if (flags & CKF_SO_PIN_TO_BE_CHANGED)          SetIntegerId2("", 33,  1,  1);
                if (flags & CKF_ERROR_STATE)                   SetIntegerId2("", 34,  1,  1); // since version 2.30 ?

                SetStringId2("", 35,  1, ulSessionCount.to!string  ~" / "~ulMaxSessionCount.to!string);
                SetStringId2("", 36,  1, ulRwSessionCount.to!string~" / "~ulMaxRwSessionCount.to!string);
                SetStringId2("", 37,  1, ulMinPinLen.to!string     ~" / "~ulMaxPinLen.to!string);
              //SetStringId2("", 38,  1, format("%5.0f", ulFreePublicMemory /1024.) ~" / "~ format("%5.0f", ulTotalPublicMemory /1024.));
              //SetStringId2("", 39,  1, format("%5.0f", ulFreePrivateMemory/1024.) ~" / "~ format("%5.0f", ulTotalPrivateMemory/1024.));
                if (hardwareVersion.major)
                    SetStringId2("", 41,  1, hardwareVersion.major.to!string~"."~hardwareVersion.minor.to!string /* ~" / "~
                                             firmwareVersion.major.to!string~"."~firmwareVersion.minor.to!string*/);
                else
                {
                    SetStringId2("", 41,  1, cos_version.value[5].to!string~"."~cos_version.value[6].to!string);
                }
                SetStringId2("", 40,  1, cast(string) utcTime[]);
            } // what about other data like free space, ROM-SHA1 etc.
        }
    } // scope for scope(exit)  PKCS11.unload(); closes connection to the smart card/reader

    GC.collect(); // optional Garbage collection run, AFAIK put's any other threads on hold, but there shouldn't be any other than this main-thread
    /* Update IUP main dialog window and it's controls (IupUpdate()), set tab position to tab "filesystem" */
    AA["dlg0"].Update;
    AA["tabCtrl"].SetInteger("VALUEPOS", 1); // filesystem

    /* start event loop. From this point, control flow depends on user action and callback functions connected in gui.d, e.g. SetCallback(IUP_SELECTION_CB, cast(Icallback) &selectbranchleaf_cb); */
    /* Check why GIO (since OpenSC 0.18.0) occasionally crashes this program, Check multi-threading within event loop  */
    IupMainLoop();
    /* Close/Exit Button was clicked */
////    config.SaveConfig();
    IupClose();

    /* Destroy the "PKCS15" structure */
    asn1_delete_structure (&PKCS15);

    return EXIT_SUCCESS;
}
