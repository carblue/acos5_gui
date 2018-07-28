# acos5_64_gui
An Administration tool for ACS ACOS5-64 (v2: Smart Card/CryptoMate64 or v3: Smart Card/CryptoMate Nano in mode Non-FIPS/64K), based on driver acos5_64 for OpenSC.

The Linux acos5_64 driver/SM binary libacos5_64.so included is bound to a specific opensc version and depends on specific shared object(s) phobos and druntime of a D compiler suite (currently supported: DMD 2.081.1, LDC 2.080.1 (LDC 1.10.0), GDC 2.076, https://dlang.org/download.html).<br>
Other "systemDependencies" are listed in dub.json.<br>

![alt text](Screenshot_20180620_acos5_64_gui.png)

This is [WIP] work in progress

Features planned/about to be implemented:

- [x] View Cryptoki/Slot/Token-Info.<br>
- [x] View (, manipulate) the filesystem in a tree- and other views (with some obvious restrictions, e.g. resizing files is impossible with this card type).<br>
- [x] RSA keys/PrKDF/PuKDF handling.<br>
- [x] Sym keys/SKDF handling. (No new SKDF entries written currently, work in progress)<br>
- [ ] Pin/AOD handling.<br>
- [ ] Certificate/CDF handling<br>
- [ ] Export/Import file system<br>
- [ ] Initialize card<br>
...
