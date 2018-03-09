# acos5_64_gui
An administration tool (and more) for driver acos5_64.

This is [WIP] work in progress

I'm not yet finally decided about the GUI framework, whether to (probably) stick to IUP or switch to Qt (thanks to QtE5; Qt arguably looks a little bit nicer, but takes much more time to develop with).<br>

Features planned/about to be implemented:

- i18n via gettext, thus if Your language is not provided, You can translate the GUI interface strings (e.g. poedit) and hopefully recontribute it.<br>
- View (, manipulate) Cryptoki/Slot/Token-Info.<br>
- View (, manipulate) the opensc configuration file opensc.conf.<br>
- View, manipulate the filesystem in a tree- and other views (with some obvious restrictions, e.g. resizing files is impossible with this card type).<br>
- Dump card contents (encrypted) for backup storage. Somehow integrate placeholders for files that will never be dumped like PINs, secret keys, RSA private keys (anything that is or should be: Read_Never).<br>
- Thus have an import facility for non-dumpable files.<br>
- Initialize card.<br>
- Import files (certificates etc.).<br>
- (Re-)setting TDES keys for internal and external authentication (in opensc.conf and on card/token, application-specific).<br>
- More to be specified, currently covered by opensc's tools, more intuitively usable by this gui tool.<br>
- <br>
- Last but not least: Fill the gap of ACOS5-64 card/token specific features/settings that currently are not covered/being possible to set by opensc tools.<br>
- Centralized access to instructions, howtos and useful links, help in general.<br>
- Access to an extensive filesystem sanity check (PKCS#15 compliance, recommended access rights etc.) .<br>
- Perhaps integrate some opensc-debug.log analysis; zeroize opensc-debug.log.<br>
- Perhaps integrate gscriptor functionality (send any APDU(s) to card/token).<br>
- Perhaps manipulate the file dub.json of project driver acos5_64 (version identifiers) for (re-)building the driver binary with specific features/settings.<br>
- Summarized, I want this to be THE one-stop tool for my ACOS5-64 (cards/)tokens CryptoMate64 and CryptoMate Nano.<br>
