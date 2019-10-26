/*
 * cardctl.h: card_ctl command numbers
 *
 * Copyright (C) 2003  Olaf Kirch <okir@lse.de>
 * Copyright (C) 2016-  for the binding: Carsten Blüggel <bluecars@posteo.eu>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/*
Written in the D programming language.
For git maintenance (ensure at least one congruent line with originating C header):
#define _OPENSC_CARDCTL_H

Content covered by this file is SOME! of header C/libopensc/card_ctl.h (everything card-specific is stripped

NO extern(C) functions are declared/exported from "libopensc.so|opensc.dll" binary
*/

module libopensc.cardctl;

import libopensc.types : FreeEnumMembers;


//uint _CTL_PREFIX()(char a, char b, char c)  { return a << 24 | b << 16 | c << 8; }

enum SC_CARDCTL : uint {
	/*
	 * Generic card_ctl calls
	 */
	SC_CARDCTL_GENERIC_BASE = 0x0000_0000,
	SC_CARDCTL_ERASE_CARD,                // cmd 1
	SC_CARDCTL_GET_DEFAULT_KEY,           // cmd 2
	SC_CARDCTL_LIFECYCLE_GET,             // cmd 3
	SC_CARDCTL_LIFECYCLE_SET,             // cmd 4
	SC_CARDCTL_GET_SERIALNR,              // cmd 5 // data: sc_serial_number*
	SC_CARDCTL_GET_SE_INFO,               // cmd 6
	SC_CARDCTL_GET_CHV_REFERENCE_IN_SE,   // cmd 7
	SC_CARDCTL_PKCS11_INIT_TOKEN,         // cmd 8 (C_InitToken)
	SC_CARDCTL_PKCS11_INIT_PIN,           // cmd 9 (C_InitPIN)
}

mixin FreeEnumMembers!SC_CARDCTL;


enum
	SC_CARDCTRL_LIFECYCLE {

	SC_CARDCTRL_LIFECYCLE_ADMIN,
	SC_CARDCTRL_LIFECYCLE_USER,
	SC_CARDCTRL_LIFECYCLE_OTHER,
}
mixin FreeEnumMembers!SC_CARDCTRL_LIFECYCLE;

/*
 * Generic cardctl - check if the required key is a default
 * key (such as the GPK "TEST KEYTEST KEY" key, or the Cryptoflex AAK)
 */
struct sc_cardctl_default_key {
	int     method;    /* SC_AC_XXX */
	int     key_ref;   /* key reference */
	size_t  len;       /* in: max size, out: actual size */
	ubyte*  key_data;  /* out: key data */
}

/*
 * Generic cardctl - initialize token using PKCS#11 style
 */
struct sc_cardctl_pkcs11_init_token {
	const(ubyte)*  so_pin;
	size_t         so_pin_len;
	const(char)*   label;
}
//	alias sc_cardctl_pkcs11_init_token_t = sc_cardctl_pkcs11_init_token;

/*
 * Generic cardctl - set pin using PKCS#11 style
 */
struct sc_cardctl_pkcs11_init_pin {
	const(ubyte)*  pin;
	size_t         pin_len;
}
//	alias sc_cardctl_pkcs11_init_pin_t = sc_cardctl_pkcs11_init_pin;

