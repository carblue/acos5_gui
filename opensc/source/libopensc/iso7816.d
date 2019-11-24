/*
 * iso7816.h: ISO-7816 defines
 */

// No function exported from "libopensc.*"

module libopensc.iso7816;

import libopensc.types : FreeEnumMembers;

enum : ubyte {
	ISO7816_FILE_TYPE_TRANSPARENT_EF = 0x01,
	ISO7816_FILE_TYPE_DF             = 0x38,
}

enum ubyte ISO7816_TAG_FCI         = 0x6F;

enum /*ISO7816_TAG_FCP_*/ : ubyte {
	ISO7816_TAG_FCP            = 0x62,  /* ACOS5: For file creation only; get response will supply ISO7816_TAG_FCI */
	ISO7816_TAG_FCP_SIZE       = 0x80,  /* L:2,    V: Number of data bytes in the file, excluding structural information. Applies to: Transparent EFs */
	ISO7816_TAG_FCP_SIZE_FULL  = 0x81,  /* L:2,    V: Number of data bytes in the file, including structural information if any. Applies to: Any file;   not used by ACOS5 */
	ISO7816_TAG_FCP_TYPE       = 0x82,  /* L:1-4,  V: File descriptor byte, optionally more. Applies to: Any file;   ACOS5 uses up to 6 bytes */
	ISO7816_TAG_FCP_FID        = 0x83,  /* L:2,    V: File identifier. Applies to: Any file */
	ISO7816_TAG_FCP_DF_NAME    = 0x84,  /* L:1-16, V: DF name. Applies to: DFs */
	ISO7816_TAG_FCP_PROP_INFO  = 0x85,  /* L:var., V: Proprietary information. Applies to: Any file;   not used by ACOS5 */
	ISO7816_TAG_FCP_ACLS       = 0x86,  /* L:var., V: Security attributes (coding outside the scope of this part of ISO/IEC 7816). Applies to: Any file;   not used by ACOS5 */
//  ISO7816_TAG_FCP_EXTEF      = 0x87,  /* L:2,    V: Identifier of an EF containing an extension of the FCI. Applies to: Any file;   not used by ACOS5 */
	/*                           0x88  to
	                             0x9E  :   RFU Reserved Future Use */
	ISO7816_TAG_FCP_LCS        = 0x8A,  /* L:1,    V: Life Cycle Status Integer (LCSI). Applies to: Any file */
}
//mixin FreeEnumMembers!ISO7816_TAG_FCP_;

enum : ubyte {
	/* ISO7816 interindustry data tags */
	ISO7816_II_CATEGORY_TLV     = 0x80,
	ISO7816_II_CATEGORY_NOT_TLV = 0x00,
}

enum : ushort {
	ISO7816_TAG_II_CARD_SERVICE        = 0x43,
	ISO7816_TAG_II_INITIAL_ACCESS_DATA = 0x44,
	ISO7816_TAG_II_CARD_ISSUER_DATA    = 0x45,
	ISO7816_TAG_II_PRE_ISSUING         = 0x46,
	ISO7816_TAG_II_CARD_CAPABILITIES   = 0x47,
	ISO7816_TAG_II_AID                 = 0x4F,
	ISO7816_TAG_II_ALLOCATION_SCHEME   = 0x78,
	ISO7816_TAG_II_STATUS_LCS          = 0x81,
	ISO7816_TAG_II_STATUS_SW           = 0x82,
	ISO7816_TAG_II_STATUS_LCS_SW       = 0x83,
	ISO7816_TAG_II_EXTENDED_LENGTH     = 0x7F66,
}

enum : ubyte {
	ISO7816_CAP_CHAINING               = 0x80,
	ISO7816_CAP_EXTENDED_LENGTH        = 0x40,
	ISO7816_CAP_EXTENDED_LENGTH_INFO   = 0x20,
}

/* Other interindustry data tags */
//	enum IASECC_TAG_II_IO_BUFFER_SIZES     = 0xE0;

