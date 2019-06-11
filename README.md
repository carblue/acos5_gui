# acos5_64_gui
An Administration tool for ACS ACOS5-64 (v2: Smart Card/CryptoMate64 and v3: Smart Card/CryptoMate Nano), based on driver acos5_64 for OpenSC.

The repo is in transit to be based on a new driver implementation [acos5_64](https://github.com/carblue/acos5_64 "https://github.com/carblue/acos5_64") (since release v0.0.7);<br>
(this repo's release tagged v0.0.6 is the last one based on the old driver (acos5_64 with releases tagged < v0.0.6);<br>

During transit, not all - what worked already - is still available; since next release, the gap should be caught up.

The repo will always be closely related to the driver acos5_64 and acos5_64_pkcs15init development. Make sure to have the latest releases installed.

![alt text](Screenshot_20180620_acos5_64_gui.png)

This is [WIP] work in progress

Features planned/about to be implemented:

- [x] View Cryptoki/Slot/Token-Info.<br>
- [x] View (, manipulate) the filesystem in a tree- and other views (with some obvious restrictions, e.g. resizing files is impossible with this card type).<br>
- [x] RSA keys/PrKDF/PuKDF handling.<br>
- [x] Sym keys/SKDF handling.<br>
- [ ] Pin/AOD handling.<br>
- [ ] Certificate/CDF handling<br>
- [ ] Export/Import file system<br>
- [ ] Initialize card<br>
...
