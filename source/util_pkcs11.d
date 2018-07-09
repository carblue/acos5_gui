/*
 * Written in the D programming language, part of package acos5_64_gui.
 * util_pkcs11.d: Some utilities dealing with PKCS#11
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

module util_pkcs11;

import core.stdc.config : c_long, c_ulong;
import core.stdc.stdlib : EXIT_SUCCESS, EXIT_FAILURE, exit; // , malloc, free;

import std.string : toStringz, fromStringz;
import std.stdio : write, writeln, writefln, stdout, stderr;
import std.exception;

import pkcs11;

CK_SLOT_ID[10]  slotIds;
CK_ULONG        slotCount;


void pkcs11_check_return_value(CK_RV rv, string message) nothrow
{
    if (rv != CKR_OK) {
        assumeWontThrow(writefln("Error at %s: %s", message, rv));
        assumeWontThrow(stdout.flush());
//        exit(EXIT_FAILURE);
    }
}

/* returns the first "satisfying" CK_SLOT_ID */
CK_SLOT_ID pkcs11_get_slot() nothrow
{
    CK_RV           rv;
//    CK_SLOT_ID[10]  slotIds;// = malloc(CK_SLOT_ID.sizeof * slotCount);
//    CK_SLOT_ID* slotIds = malloc(CK_SLOT_ID.sizeof * slotCount);
//    slotCount = slotIds.length;

    // size query
    pkcs11_check_return_value(rv= C_GetSlotList(CK_TRUE, null, &slotCount), "get slot list");
    if (slotCount == 0  ||  slotCount > slotIds.length) {
        assumeWontThrow(writeln("Error: Could not find any slots or more than 10 slots with a token present found (dev: adjust array size)"));
//        stderr.writeln("Error; could not find any slots (or too many slots)");
        exit(EXIT_FAILURE);
    }

    pkcs11_check_return_value(rv= C_GetSlotList(CK_TRUE, slotIds.ptr, &slotCount), "get slot list");
    if (rv != CKR_OK)
        exit(EXIT_FAILURE);

    CK_SLOT_ID  slotId = slotIds[0];
//    free(slotIds);
    assumeWontThrow(writefln("slot count: %s", slotCount));
    return slotId;
}

CK_SESSION_HANDLE  pkcs11_start_session (CK_SLOT_ID slotId) nothrow {
	CK_RV              rv;
	CK_SESSION_HANDLE  session;
	rv = C_OpenSession(slotId,
		CKF_SERIAL_SESSION | CKF_RW_SESSION,
		null,
		null,
		&session);
	pkcs11_check_return_value(rv, "open session");
	return session;
}

void  pkcs11_login (CK_SESSION_HANDLE session, CK_BYTE[] pin) nothrow {
	CK_RV rv;
	if (pin.length) {
		rv = C_Login(session, CKU_USER, pin.ptr, pin.length);
		pkcs11_check_return_value(rv, "log in");
	}
}

void  pkcs11_logout (CK_SESSION_HANDLE session) nothrow {
	CK_RV rv;
	rv = C_Logout(session);
	if (rv != CKR_USER_NOT_LOGGED_IN) {
		pkcs11_check_return_value(rv, "log out");
	}
}

void  pkcs11_end_session (CK_SESSION_HANDLE session) nothrow {
	CK_RV rv;
	rv = C_CloseSession(session);
	pkcs11_check_return_value(rv, "close session");
}

