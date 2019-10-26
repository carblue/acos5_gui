# Build state

[![Build Status](https://travis-ci.org/carblue/opensc.svg)](https://travis-ci.org/carblue/opensc)
[![Build status](https://ci.appveyor.com/api/projects/status/k8gwg8a512fifkrj?svg=true)](https://ci.appveyor.com/project/carblue/opensc)

# Overview

D language: Deimos-like binding to headers of libopensc.so/opensc.dll, supporting the current 2 last/rolling OpenSC releases (i.e. version OpenSC-0.20.0-rc1, released Sept. 5, 2019, and the previous version 0.19.0, released Sept. 13, 2018.
https://github.com/OpenSC/OpenSC

The OpenSC framework allows for providing e.g. a Smart Card Driver (and/or Secure Messaging/PKCS#15 module) as external shared object/DLL(s), if opensc.conf is configured accordingly.<br>
This binding allows to implement in the D programming language.

category: Development Library | D language binding | Deimos header only binding  (dub configuration "deimos")<br>
category: Development Library | Development support library (with the difference to "deimos", that it must be compiled to make use of some additional toString methods; dub configuration "toString")

Not all OpenSC header content is covered, but what is required/useful for external modules and at least what is accessible from libopensc.so/opensc.dll.<br>

There are a few general extensions/deviations, e.g. some enums are typed in the D binding in order to enable final switch usage, there are a few templates added like FreeEnumMembers in types.d, the templated enum log! in log.d (, a few template functions replaced the  #defined-functions). Thus at it's heart it is no pure deimos binding any more but very close to it and still doesn't require compilation in dub configuration "deimos".

There is a tight dependency on how OpenSC's libopensc binary was build, thus reading info/options is recommended !

There are multiple reasons why code using this binding has to tell at compile time, to which exact libopensc binary version it's going to be linked/call at runtime. The version issue is managed by Dlang version identifier OPENSC_VERSION_LATEST, that has to be removed from dub.json, if not linking against the latest libopensc.so/.dll.<br>
More about OPENSC_VERSION_LATEST and other version identifiers in info/options, but this info ahead:<br>
v0.15.7 up to v0.15.13: OPENSC_VERSION_LATEST refers to OpenSC release v0.16.0, the only other one usable (omitting OPENSC_VERSION_LATEST) is  opensc v0.15.0.<br>
v0.15.14 up to v0.15.16: OPENSC_VERSION_LATEST refers to OpenSC release v0.17.0,<br>
v0.18.0: OPENSC_VERSION_LATEST refers to OpenSC release v0.18.0.<br>
v0.19.0: OPENSC_VERSION_LATEST refers to OpenSC release v0.19.0.<br>
Also, file C/release_version states, what is OPENSC_VERSION_LATEST refering to, the OpenSC release, where the headers came from to be "translated".<br>

The operating system support is limited to those OS I have/know and can test (64 bit CPU: Linux/Windows), but may work for others too.<br>

Last but not least my curiosity:
In consideration of the fact, that this is a very specialized binding topic useful only for implementation of a driver etc., I had quite a lot of downloads via dub so far.
Are You all happy, or have suggestions for enhancements? What are You doing with this binding?
I didn't get any feedback/PR/issue so far; I would like to get some.
