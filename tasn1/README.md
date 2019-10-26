[![Build Status](https://travis-ci.org/carblue/tasn1.svg?branch=master)](https://travis-ci.org/carblue/tasn1)
[![Build status](https://ci.appveyor.com/api/projects/status/iupjwvvh62twk104/branch/master?svg=true)](https://ci.appveyor.com/project/carblue/tasn1/branch/master)



# tasn1

Twofold binding to GNU Libtasn1, a library for Abstract Syntax Notation One (ASN.1) and Distinguished Encoding Rules (DER) manipulation.

subPackage 'deimos':  The "import-only" C header's declarations.<br>
subPackage 'wrapper': 'deimos' + some 'D-friendly' stuff (overloaded functions and unittests).

The dependency name is either  tasn1:deimos  or  tasn1:wrapper,<br>
the import is either import deimos.libtasn1; or import wrapper.libtasn1;

Binds to libtasn1 source code version 4.14, released 2019-07-21.

[libtasn1](https://www.gnu.org/software/libtasn1/ "https://www.gnu.org/software/libtasn1/")<br>
[libtasn1 manual](https://www.gnu.org/software/libtasn1/manual/ "https://www.gnu.org/software/libtasn1/manual/")

Example<br>(assumes rdmd installed and usable on Linux, otherwise adapt examples/cmdfile (rdmd options): the tasn1 library to link. Also the first line of CertificateExample.d (shebang) has to be adapted for non-Linux OS.
The next line is for invocation on Linux: changes directory to examples, grant executable access right for CertificateExample.d and runs CertificateExample.d):

`cd examples && chmod +x CertificateExample.d && ./CertificateExample.d`

Sadly the cited manual isn't as good as it should be for a quick start, thus some notes here:

Usage of libtasn1 is based on having the ASN1 module *.asn of the topic interested in (e.g. pkix.asn in examples), or constructing that first.
Classes, parametrized types are not supported, but may be worked around by 'unrolling'.

Given any *.asn, these 2 interesting questions are solved by libtasn1:
Further given DER-endoded data 'ubyte[] der' which are known to be the encoding of "something defined in ASN1 module *.asn": Which are the concrete field values of that "something"?
And conversely, how does that "something" with assumed changed field values translate back to a new 'ubyte[] der'?

How does libtasn1 solve that, while not being an asn1 compiler? Well, it constructs it's proprietary representation of ASN1 module *.asn; for brevity I'll call that IRdef (tree-like Intermediate Representation of definitions).
IRdef may be produced either during each app invocation on the fly by function 'asn1_parser2tree' or once in a preprocessing step by function 'asn1_parser2array' followed in each app invocation by calling function 'asn1_array2tree'.

I didn't do benchmarks concerning these 2 options (just using asn1_parser2tree for now while often changing .asn), but it's assumed that the other option which involves preprocessing will have performance benefits, at least it avoids asn file access and processing:
Use libtasn1 utility 'asn1Parser' which internally employs function 'asn1_parser2array' and generates a file based array-IRdef, translate that from C to D to be imported later (containing const(asn1_static_node)[] array) and use function 'asn1_array2tree' to transform array-IRdef to tree-IRdef.<br>
For a HowTo see wrapper's doc of function asn1_array2tree.<br>
That's what was done for the example CertificateExample.d.
Function 'asn1_parser2array' doesn't make sense in a D-binding and got excluded.

asn1_node is the data type of IRdef; the manual always refers to that as 'definitions' (or 'declarations') and that's exactly what IRdef is for: Only for describing the data stucture(s), their data types, optional or not etc.: It's NOT about concrete values.

The next (I call it IRconcrete) may be confusing, as it has type asn1_node too: It's called 'structure' throughout the manual and denotes something like IRdef or a specific section of IRdef filled with concrete values for the fields.

Keeping asn1_node IRdef strictly separated in mind from asn1_node IRconcrete is the key point in better understanding the manual.

In order to emphasize that, I changed parameter names in the wrapper binding where required for unambiguity.

The link between IRdef and IRconcrete is this: Create an empty/default IRconcrete from IRdef with function 'asn1_create_element' and then optionally fill IRconcrete with values from an 'ubyte[] der' with function 'asn1_der_decoding'.
Now from IRconcrete values may be read by function asn1_read_value or written to by asn1_write_value. These functions - as their name implies - refer to single (field) values.
Writing DER-encoded structured data (hierarchy) is as easy as calling 'function asn1_der_coding' with an IRconcrete parameter and sufficiently sized preallocated memory for receiving the DER-data.
Many functions employ a name parameter (deimos: const char*, wrapper: string) to specify, what "something" refers to (based on the names defined in .asn).

The unittests of subPackage 'wrapper' exemplify a lot of that and are Work In Progress, aiming at touching all corner cases.
