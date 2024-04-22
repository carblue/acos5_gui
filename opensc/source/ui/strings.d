/*
 * strings.c: default UI strings
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
#define _SC_STRINGS_H

Content covered by this file is ALL of header C/ui/strings.h
ALL extern(C) functions are exported from "libopensc.so|opensc.dll" binary.
*/

module ui.strings;


    import libopensc.opensc : sc_context;
    import libopensc.pkcs15 : sc_pkcs15_card;
    import libopensc.types : sc_atr;

    enum ui_str {
        MD_PINPAD_DLG_TITLE,
        MD_PINPAD_DLG_MAIN,
        MD_PINPAD_DLG_CONTENT_USER,
        MD_PINPAD_DLG_CONTENT_ADMIN,
        MD_PINPAD_DLG_EXPANDED,
        MD_PINPAD_DLG_CONTROL_COLLAPSED,
        MD_PINPAD_DLG_CONTROL_EXPANDED,
        MD_PINPAD_DLG_ICON,
        MD_PINPAD_DLG_CANCEL,
        NOTIFY_CARD_INSERTED,
        NOTIFY_CARD_INSERTED_TEXT,
        NOTIFY_CARD_REMOVED,
        NOTIFY_CARD_REMOVED_TEXT,
        NOTIFY_PIN_GOOD,
        NOTIFY_PIN_GOOD_TEXT,
        NOTIFY_PIN_BAD,
        NOTIFY_PIN_BAD_TEXT,
        MD_PINPAD_DLG_CONTENT_USER_SIGN,

        NOTIFY_EXIT,
        MD_PINPAD_DLG_VERIFICATION,
    }

extern(C) const(char)* ui_get_str(sc_context* ctx, sc_atr* atr,
    sc_pkcs15_card* p15card, ui_str id) @nogc nothrow;
