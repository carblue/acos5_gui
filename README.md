# acos5_64_gui
An Administration tool for ACS ACOS5-64 (v2: Smart Card/CryptoMate64 and v3: Smart Card/CryptoMate Nano), based on driver acos5_64 and acos5_64_pkcs15init for OpenSC.

The repo is now based on a new driver implementation [acos5_64](https://github.com/carblue/acos5_64 "https://github.com/carblue/acos5_64") (since release v0.0.7);<br>
(repo's release tagged v0.0.6 is the last one based on the old driver (D language acos5_64 with releases tagged <= v0.0.5);<br>

Next to libraries required according to dub.json, both of the following libraries are prerequisites being installed and OpenSC (opensc.conf) configured to use them:
[acos5_64](https://github.com/carblue/acos5_64 "https://github.com/carblue/acos5_64") and
[acos5_64_pkcs15init](https://github.com/carblue/acos5_64_pkcs15init "https://github.com/carblue/acos5_64_pkcs15init").<br>
**The repo will always be closely related to the driver acos5_64 and acos5_64_pkcs15init development. Make sure to have the latest releases installed.**

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

For block cipher CBC deciphering the driver must compensate for a cos5 bug (V2; not yet tested with V3), which boils down to resetting a correct IV vector for n-1 invocations of "7.4.3.7. Symmetric Key Decrypt".<br>
Passing IV with `sc_set_security_env` will be possible beginning from OpenSC v0.20.0.

Since OpenSC version v0.18.0 (libgio-2.0 usage introduced, showing card events like card is accessible now...), sporadic crashes do occure rigth in the beginning within libgio-2.0 when IUP entered it's main loop (gtk based; on Linux). I assume it's a bug that must be fixed in some of the dependents. Either it happens during start-up before any user interaction or we can forget about it. Just retry<br>
`acos5_64_gui` takes some time for start-up: A lot of card interaction occurs right in the beginning. Once the initial work is done and the GUI is reactive, there is only one other action, that takes remarkable time (freezing the GUI): RSA key generation with high bit sizes. CryptoMate64 takes about 3-5 minutes for a 4096 bit key pair generation and occasionally, the generation even fails. Just retry until that succeeds. The generation in existing files is available, but currently it's not possible to generate into RSA key pair files not yet existing.<br>
There is no permanent connection to the card from `acos5_64_gui`, just on demand, but don't mix usages of `acos5_64_gui` (while it's accessing the card) with other card/token usages (that access the card), e.g. by Thunderbird, ssh or alike: I didn't yet investigate how the PKCS#11 library opensc-pkcs11 and the driver behave concerning multi-threading.<br>
With an USB token, card access is visible, but there are also "false" LED messages indicating card access: I assume something isn't perfect within the pcsc-lite layer, because sometimes, when I know the card access from `acos5_64_gui` is finished and the LED entered to a blinking state, it may continue to light up permanently without a sensible reason.
I'm used to stop that by invoking gscriptor from pcsc-tools, connect, disconnect and quit, possibly repeating that.<br>
The regular case should be, that after about 1 minute of inactivity with `acos5_64_gui`, the USB LED should stop blinking, signaling it's unpowered state.<br>
While being inactive with `acos5_64_gui` (or only actions that don't access the card), any other app may be used that connects to the card. After closing that app, work with `acos5_64_gui` may be resumed.<br>
If You access a repo, e.g. GitHub via [ssh](https://help.github.com/en/articles/changing-a-remotes-url#switching-remote-urls-from-https-to-ssh "https://help.github.com/en/articles/changing-a-remotes-url#switching-remote-urls-from-https-to-ssh"), it may happen, that git starts to issue Cryptoki calls which ends in accessing the card periodically: That's a strange issue with respect to `git-upload-pack`. Somehow I managed to stop that.<br>
Also, don't plug-in more than 1 ACOS5-64 token simultaneously, or unplug or change the token while `acos5_64_gui` is running: `acos5_64_gui` is not yet designed to handle that (e.g. it memoizes the file system, assuming it's th same when resuming).<br>
The error handling is not complete at this stage: The problem with that is: The coding isn't easily done already and massive error handling code would currently obscure where the real action takes place. If You encounter any such situation, please report to issues.
