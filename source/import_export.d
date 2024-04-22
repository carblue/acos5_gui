/*
 * import_export.d: Program acos5_gui's 'import from/export to filesystem' file
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

module import_export;

import std.stdio;
import std.conv: to;
import std.string : /*fromStringz,*/ toStringz;
import std.exception : assumeWontThrow;
import std.algorithm.comparison : /*min, max, clamp, equal, mismatch,*/ among;
import std.range : iota, chunks;

import libopensc.opensc;
import libopensc.types;
import libopensc.errors;
import libopensc.log;
import libopensc.iso7816;

import acos5_shared_rust;

import iup.iup_plusD;

//import libintl : _, __;
//
import util_general;// : ub22integral, ubaIntegral2string;
import acos5_64_shared;

import util_opensc : connect_card, readFile, decompose, PKCS15Path_FileType, fs, TreeTypeFS,
    PKCS15_FILE_TYPE, tlv_Range_mod, is_ACOSV3_opmodeV3_FIPS_140_2L3, is_ACOSV3_opmodeV3_FIPS_140_2L3_active;

struct ExportData
{
        ub2 fid;
        ubyte lcsi;
        ubyte fdb;
        ub2 seid;

        ubyte[16]  df_name;
        ubyte[8]   ambSAC;
        ubyte[32]  sae;
        ubyte saeRemoveLen;
        ubyte NOR, MRL;
        ushort fileSize;
        bool readable; // needs special treatment: e.g. for fdb==CHV will write a standard pin file
}


extern(C) nothrow:

int btn_exportArchive_cb(Ihandle* ih)
{
    int rv;
    string[] list_archiv_files = ["commands_create", "toc_files_active"];
    // all in /tmp ; in the end, take all files listed and package them in the archiv file
//    list_archiv_files ~= "commands_create";
//    list_archiv_files ~= "toc_files_active";
//    string  prefixPath = "";
    try
    {
        auto f_commands_create  = File("/tmp/commands_create", "w");  // open for writing, i.e. Create an empty file for output operations. If a file with the same name already exists, its contents are discarded and the file is treated as a new empty file.
        auto f_toc_files_active = File("/tmp/toc_files_active", "w"); // dito

        ubyte[MAX_FCI_GET_RESPONSE_LEN]  rbuf = void;
        enum string commands = `
        foreach (e; fs.rangePreOrder())
        {
            rbuf = typeof(rbuf).init;
            rbuf[0] = ISO7816_TAG_FCP;
            ubyte len;
            sc_path path;
            sc_file* file;
            sc_format_path(ubaIntegral2string(e.data[8..8+e.data[1]]).toStringz , &path);
            if ((rv= sc_select_file(card, &path, &file)) == SC_SUCCESS) {
                rbuf[1] = len  = cast(ubyte) file.prop_attr_len;
                rbuf[2..2+len] = file.prop_attr[0..len];
                sc_file_free(file);
            }

            ExportData ed;
            foreach (d,T,L,V; tlv_Range_mod(rbuf[2..2+len]))
            {
                if      (T == ISO7816_TAG_FCP_SIZE)
                    ed.fileSize = ub22integral(V[0..2]);
                else if (T == ISO7816_TAG_FCP_TYPE)
                {
                    ed.fdb = V[0];
                    if (iEF_FDB_to_structure(cast(EFDB)ed.fdb)&6  &&  L.among(5,6))  // then it's a record-based fdb
                    {
                        ed.MRL = V[3];
                        ed.NOR = V[L-1];
                    }
                }
                else if (T == ISO7816_TAG_FCP_FID)
                    ed.fid = V[0..2];
                else if (T == ISO7816_TAG_FCP_DF_NAME)
                    ed.df_name[0..L] = V[0..L];
                else if (T == ISO7816_TAG_FCP_LCS)
                {
                    ed.lcsi = V[0];
                    V[0] = 1;
                }
                else if (T == ISO7816_RFU_TAG_FCP_SAC)
                {
                    ed.ambSAC[0..L] = V[0..L];
                    ed.readable = ! ( L>1  &&  (V[0]&1)  &&  V[L-1]==0xFF);
                }
                else if (T == ISO7816_RFU_TAG_FCP_SEID)
                    ed.seid = V[0..2];
                else if (T == ISO7816_RFU_TAG_FCP_SAE)
                {
                // this is alway listed in the end, thus it's safe to omit  AB 00; and it must be omitted for non-DF/MF
                    ed.sae[0..L] = V[0..L];
                    if (!L)
                        ed.saeRemoveLen = 2;
                }
            } // foreach (d,T,L,V; tlv_Range_mod(rbuf[2..2+len]))

            string fileName;
            string tail = "  " ~ ed.lcsi.to!string;
            if (ed.NOR)
                foreach (i; 1..1+ed.NOR)
                {
                    fileName = ubaIntegral2string(e.data[8..8+e.data[1]]) ~ "_" ~ i.to!string;
                    f_toc_files_active.writeln(" " ~ fileName ~ tail);
                    auto buf = new ubyte[ed.MRL];
                    // possible fdb:
                    if (/*true*/ed.readable)
                    {
                        rv = sc_read_record(card, i, 0, buf.ptr, buf.length, SC_RECORD_BY_REC_NR);
                        if (!(rv>0 && rv==buf.length))
                        {
assumeWontThrow(writeln("### rv: ", rv));
assumeWontThrow(writefln("### ed.fid: %(%02X %)", ed.fid));
                        }
//                        assert(rv>0 && rv==buf.length);
                    }
                    else
assumeWontThrow(writefln("### unreadable: ed.fid: %(%02X %)", ed.fid));
                    auto f = File("/tmp/"~fileName, "wb");
                    f.rawWrite(buf);
                    list_archiv_files ~= fileName;
                }
            else
            {
                fileName = ubaIntegral2string(e.data[8..8+e.data[1]]);
                f_toc_files_active.writeln( (is_DFMF(ed.fdb)? "#" : " ") ~ fileName ~ tail);
                if (!is_DFMF(ed.fdb))
                {
                    auto buf = new ubyte[ed.fileSize];
                    // possible fdb: 1 (ordinary transparent), 9 (RSA transparent)
                    if (/*true*/ed.readable)
                    {
//                      if (ed.fdb == 1 || ed.fdb == 9)
                            rv = sc_read_binary(card, 0, buf.ptr, buf.length, null /*flags*/);
                        if (!(rv>0 && rv==buf.length))
                        {
assumeWontThrow(writeln("### rv: ", rv));
assumeWontThrow(writefln("### ed.fid: %(%02X %)", ed.fid));
                        }
//                        assert(rv>0 && rv==buf.length);
                    }
                    else
assumeWontThrow(writefln("### unreadable: ed.fid: %(%02X %)", ed.fid));
                    auto f = File("/tmp/"~fileName, "wb");
                    f.rawWrite(buf);
                    list_archiv_files ~= fileName;
                }
            }
            if (ed.saeRemoveLen)
                rbuf[1] -= ed.saeRemoveLen;
            f_commands_create.writeln(ubaIntegral2string(rbuf[0..len+2-ed.saeRemoveLen]));
        } // foreach (const ref e; fs.preOrderRange(fs.begin(), fs.end()))
        assumeWontThrow(writeln(list_archiv_files));
`;
        mixin(connect_card!commands);
    }
    catch (Exception e) { printf("### Exception in btn_exportArchive_cb\n"); /* todo: handle exception */ }
    return IUP_DEFAULT;
}
