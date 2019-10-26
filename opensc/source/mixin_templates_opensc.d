module mixin_templates_opensc;

/*
Look at these for special solutions (pointers, arrays, unions or combinations):
scconf.d:     scconf_item  union's content depending on type field
pkcs15init.d: sc_profile   array of char*
pkcs15.d:     sc_pkcs15_object
*/

version(ENABLE_TOSTRING) {

// from sc_card_driver
const char[] head_foreach_Pointer = `
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1]; // peel off const(payload) to get payload
					string value_rep = format("%s", member);
					bool isDereferencable     =  (unqual_type[$-1]=='*' && unqual_type[0..$-1]!="void") && value_rep!="null";
					bool isDereferencableVoid =  (unqual_type[$-1]=='*' && unqual_type[0..$-1]=="void") && value_rep!="null";
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");

					if (isDereferencable || isDereferencableVoid)
						sink("0x");
					sink.formatValue(member, fmt);
`;
//mixin(head_foreach_Pointer);

const char[] head_foreach_Pointer_noSinkMember = `
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1]; // peel off const(payload) to get payload
					string value_rep = format("%s", member);
					bool isDereferencable     =  (unqual_type[$-1]=='*' && unqual_type[0..$-1]!="void") && value_rep!="null";
					bool isDereferencableVoid =  (unqual_type[$-1]=='*' && unqual_type[0..$-1]=="void") && value_rep!="null";
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
`;
//mixin(head_foreach_Pointer_noSinkMember);

const char[] head_foreach_noPointer_noSinkMember = `
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1]; // peel off const(payload) to get payload
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");
`;
//mixin(head_foreach_noPointer_noSinkMember);

// from types, void toString of struct sc_version
const char[] frame_noPointer_noArray_noUnion = `
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1];
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");

					sink.formatValue(member, fmt);

					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
`;
//mixin(frame_noPointer_noArray_noUnion);

/+

+/

// from types, void toString of struct sc_serial_number
template frame_noPointer_OneArrayFormatx_noUnion(string NameArray, string NameArrayLen, string ArrayLenMax)
{ //  if (name_member=="`~NameArray~`") // sink(format("  [%(%#x, %)]", member[0..clamp(`~NameArrayLen~`,0,`~ArrayLenMax~`)]));
	const char[] frame_noPointer_OneArrayFormatx_noUnion = `
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1];
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");

					if (name_member=="`~NameArray~`")
						sink(format("  [%(%#x, %)]", `~NameArray~`[0..clamp(`~NameArrayLen~`,0,`~ArrayLenMax~`)]));
					else
						sink.formatValue(member, fmt);

					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
`;
}
//mixin(frame_noPointer_OneArrayFormatx_noUnion!("value", "len", "SC_MAX_PATH_SIZE"));

// from types, void toString of struct sc_lv_data
template frame_OnePointerFormatx_noArray_noUnion(string NamePointer, string NamePointerLen, string PointerLenMax)
{
	const char[] frame_OnePointerFormatx_noArray_noUnion = `
			string[] pointersOfInterest = ["`~NamePointer~`"];
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1];
					string value_rep = format("%s", member);
					bool isDereferencable = (unqual_type[$-1]=='*' && unqual_type[0..$-1]!="void") && value_rep!="null";
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");

					if (isDereferencable)
						sink("0x");
					sink.formatValue(member, fmt);

//					sink(";  ");
//					sink(isDereferencable ? "YES": "NO");
					if (isDereferencable && canFind(pointersOfInterest, name_member)) {
						if (name_member=="`~NamePointer~`")
							sink(format("  [%(%#x, %)]", `~NamePointer~`[0..clamp(`~NamePointerLen~`,0,`~PointerLenMax~`)]));
					}

					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
`;
}
//mixin(frame_OnePointerFormatx_noArray_noUnion!("value", "len", "99"));


// from types, void toString of struct sc_lv_data
template frame_OneCstringPointerFormats_noArray_noUnion(string NamePointer)
{
	const char[] frame_OneCstringPointerFormats_noArray_noUnion = `
			string[] pointersOfInterest = ["`~NamePointer~`"];
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1];
					string value_rep = format("%s", member);
					bool isDereferencable = (unqual_type[$-1]=='*' && unqual_type[0..$-1]!="void") && value_rep!="null";
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");

					if (isDereferencable)
						sink("0x");
					sink.formatValue(member, fmt);

//					sink(";  ");
//					sink(isDereferencable ? "YES": "NO");
					if (isDereferencable && canFind(pointersOfInterest, name_member)) {
						if (name_member=="`~NamePointer~`")
							sink(format("  %s", fromStringz(`~NamePointer~`)));
					}

					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
`;
}
//mixin(frame_OneCstringPointerFormats_noArray_noUnion!("label"));

template frame_Pointers_noArray_noUnion(string pointersOfInterest)
{ //  if (name_member=="`~NameArray~`") // sink(format("  [%(%#x, %)]", member[0..clamp(`~NameArrayLen~`,0,`~ArrayLenMax~`)]));
const char[] frame_Pointers_noArray_noUnion = `
			string[] pointersOfInterest = [`~pointersOfInterest~`];
			try {
				sink("\n{\n");
				foreach (i, ref member; this.tupleof) {
					string name_member = typeof(this).tupleof[i].stringof;
					string unqual_type = typeof(member).stringof[6..$-1];
					string value_rep = format("%s", member);
					bool isDereferencable = (unqual_type[$-1]=='*' && unqual_type[0..$-1]!="void") && value_rep!="null";
					sink("  " ~ name_member ~ "  (" ~ unqual_type ~ ") : ");

					if (isDereferencable)
						sink("0x");
					sink.formatValue(member, fmt);

//					sink(";  ");
//					sink(isDereferencable ? "YES": "NO");
					if (isDereferencable && canFind(pointersOfInterest, name_member))
						sink.formatValue(*member, fmt);

					sink("\n");
				}
				sink("}\n");
			}
			catch (Exception e) { /* todo: handle exception */ }
`;
}
//mixin(frame_Pointers_noArray_noUnion!(`"pointer1", "pointer2"`));

} //  version(ENABLE_TOSTRING)
