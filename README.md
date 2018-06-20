# acos5_64_gui
An Administration tool (and more) for ACS ACOS5-64 (v2: Smart Card/CryptoMate64 or v3: Smart Card/CryptoMate Nano in mode Non-FIPS/64K), based on driver acos5_64 (called by opensc).

The Linux acos5_64 driver/SM binary libacos5_64.so included is bound to a specific opensc version and depends on specific shared object(s) phobos and druntime of a D compiler suite (currently supported is DMD 2.080.0: https://dlang.org/download.html).<br>
Other "systemDependencies" are listed in dub.json.<br>

![alt text](Screenshot_20180620_acos5_64_gui.png)

OpenSC supports a subset of PKCS#15 v1.1 + CommonKeyAttributes.algReference from ISO 7816-15.
The support by this tool is reflected in file PKCS15.asn, which is OpenSC's support stripped down for:
  IC card case<br>
  capabilities of ACOS5-64<br>
  supported by libtasn1<br>
IMPORTANT: Make sure, that Your PKCS#15 files only use what is covered by included ASN.1 module file PKCS15.asn. In case of doubt, check with tool asn1Decoding from package libtasn1-bin.
Checkable types are e.g. PKCS15.DIRRecord (EF.DIR 2F00), PKCS15.PrivateRSAKeyObject (for entries in EF.PrKDF (not for the whole file if there is more than 1 entry)), PKCS15.PublicRSAKeyObject (for entries in EF.PuKDF) etc.:<br>
E.g.: asn1Decoding  PKCS15.asn  file_with_hex_content_of_2F00  PKCS15.DIRRecord

This is [WIP] work in progress

Features planned/about to be implemented:

- [ ] i18n via gettext. Basically, that's implemented, though not yet activated; it's to early to extract strings from source code to the .pot file for translation<br>
- [x] View Cryptoki/Slot/Token-Info.<br>
- [ ] View (, manipulate) the opensc configuration file opensc.conf.<br>
- [ ] View (, manipulate) /usr/share/opensc/acos5_64.profile.<br>
- [x] View (, manipulate) the filesystem in a tree- and other views (with some obvious restrictions, e.g. resizing files is impossible with this card type).<br>
- [ ] RSA keys/PrKDF/PuKDF handling.<br>
- [ ] Sym keys/SKDF handling.<br>
- [ ] Pin/AOD handling.<br>
- [ ] Certificate/CDF handling.<br>
- [ ] Dump card contents (encrypted) for backup storage. Somehow integrate placeholders for files that will never be dumped like PINs, secret keys, RSA private keys (anything that is or should be: Read_Never).<br>
- [ ] Thus have an import facility for non-dumpable files.<br>
- [ ] Initialize card.<br>
- [ ] Import files (certificates etc.).<br>
- [ ] (Re-)setting TDES keys for internal and external authentication (in opensc.conf and on card/token, application-specific).<br>
- [ ] More to be specified, currently covered by opensc's tools, more intuitively usable by this gui tool.<br>
- [ ] <br>
- [ ] Last but not least: Fill the gap of ACOS5-64 card/token specific features/settings that currently are not covered/being possible to set by opensc tools.<br>
- [ ] Centralized access to instructions, howtos and useful links, help in general.<br>
- [ ] Access to an extensive filesystem sanity check (PKCS#15 compliance, recommended access rights etc.). There is a kind of pre-stage already by analyzing/ASN.1-decoding PKCS#15 relevant files<br>
- [ ] Perhaps integrate some opensc-debug.log analysis; zeroize opensc-debug.log.<br>
- [ ] Perhaps integrate gscriptor functionality (send any APDU(s) to card/token).<br>

Summarized, I want this to be THE one-stop tool for my ACOS5-64 (cards/)tokens CryptoMate64 and CryptoMate Nano.<br>

In order to show meaningful content in tabs 'Cryptoki/Slot/Token-Info' and 'filesystem', a lot of file reading takes place during start-up: That takes some seconds.

Tab filesystem is readonly currently: Click on a tree's node to see contents (if applicable). The ComboBox will (just) show possible actions, and if Read is among them, it will be executed automatically.<br>
Transparent files: If it has ASN.1 content, that will be shown (thanks to the excellent package asn1 available since recently), or for RSA public files, the openssh-formatted content.<br>
There are symbol images next to the file identifier: Either (1) a bullet, or (2) a sheet of paper, blank, or (3) a sheet of paper, filled, or (4) no symbol image at all.<br>
The meaning is:<br>
(4) The file type is one of acos's internal EF that are most important for acos in any DF, max 1 of those types existing in each DF and at least the SecurityEnvironmentFile mandatory, depending on SecurityEnvironmentFile contents, the files Pin or SymKeys may be required as well. They don't need to be known to PKCS#15 by file id, as acos (implicitely) knows how to find them in a DF and knows file's meaning by file descriptor byte. Thus no symbol shown.<br>
(3) These are 'working EF' files with transparent structure and ASN1.content detected, which have specific administrative roles for the PKCS#15 file structure: E.g. an existing EF.DIR is expected to be exactly file 0x2F00 within MF and it was inspected to have a valid content structure according to the ASN.1 module for: directory (DIR) file: Optional elementary file containing a list of applications supported by the card and optional related data elements. A validation of contents is done only with regard to extracting pathes and if a path pointed to doesn't lead to an existing EF/DF, then the invalid content state is indirectly observable by "missing to be expected" sheet of paper symbols; otherwise, the "pointer dereferencing" continues as long as required.<br>
(2) These are the leafs in the PKCS#15 file structure, which contain specific objects like cerfificate, public RSA key file etc. As long as they are readable, they get inspected/detected as well and show a text suffix stating what their content is, except for private RSA key files: As they recommendedly are not readable, their text suffix "EF.RSA_PRIV" is the only uninspected one, just relying on EF.PrKD.<br>
(1) The files remaining after the processing discussed above are not known to the PKCS#15 file structure and thus will not be processed e.g. by OpenSC's PKCS#11 module. They didn' get inspected and may be kindof superfluous or have a meaning known only to the card holder, except:<br>
(a) iEF transparent files are known to acos to be RSA_Key_EF<br>
(b) The ACS client kit software may know some file(s) merely by file ID, but that's undocumented, not publicly disclosed. Probably file 0x4129 is such a dude installed by ACS client kit.<br>

PKCS#15 specials with acos5_64_gui:
Deviating from PKCS#15, if an EF.SKDF is present, it doesn't expect the file path, but the path of the DF that contains the secret key file (analogous as prescribed by PKCS#15 for the Pin describing file EF.AODF)<br>
Though the PKCS#15 detection code is working for me, it may not yet be as robust as required to cover the diversity possible (probably/possibly I'm going to switch to the opensc implementation available). If it fails, then change in module util_opensc source code:  doCheckPKCS15 = true -> doCheckPKCS15 = false
