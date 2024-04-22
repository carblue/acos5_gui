/*
 * notify.h: OpenSC library header file
 *
 * Copyright (C) 2017 Frank Morgner <frankmorgner@gmail.com>
 * Copyright (C) 2018-  for the binding: Carsten Blüggel <bluecars@posteo.eu>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
/*
Written in the D programming language.
For git maintenance (ensure at least one congruent line with originating C header):
#define _NOTIFY_H

Content covered by this file is ALL of header C/ui/notify.h
ALL extern(C) functions are exported from "libopensc.so|opensc.dll" binary.
*/

module ui.notify;

import libopensc.opensc : sc_context;
import libopensc.pkcs15 : sc_pkcs15_card;
import libopensc.types : sc_atr;
import ui.strings;


extern(C) @nogc nothrow {
    void sc_notify_init();
    void sc_notify_close();
    void sc_notify(const(char)* title, const(char)* text);
    void sc_notify_id(sc_context* ctx, sc_atr* atr, sc_pkcs15_card* p15card, ui_str id);
}

version(Windows) { //#ifdef _WIN32
    import core.sys.windows.windows; // core.sys.windows.windef; #include <windows.h>
    import core.sys.windows.winuser : WM_APP;
    /* If the code executes in a DLL, `sc_notify_instance_notify` should be
     * initialized before calling `sc_notify_init()`. If not initialized, we're
     * using the HINSTANCE of the EXE */
    extern(Windows) extern HINSTANCE sc_notify_instance;
    /* This is the message created when the user clicks on "exit". */
    enum WMAPP_EXIT = WM_APP + 2;
}
