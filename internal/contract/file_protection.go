package contract

// FileProtectionScope classifies the app-level file protection resource and
// manages the corresponding template operations.
var FileProtectionScope = []Classification{
	{
		Method:       "GET",
		Path:         "/waf/apps/{ep_id}/file_protection",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_file_protection",
		ClientMethod: "GetWAFModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/apps/{ep_id}/file_protection",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_file_protection",
		ClientMethod: "PutWAFModule",
	},
	{
		Method:       "GET",
		Path:         "/waf/template/{template_id}/file_protection",
		Disposition:  DispositionResourceRead,
		Owner:        "fortiappseccloud_waf_template_file_protection",
		ClientMethod: "GetWAFTemplateModule",
	},
	{
		Method:       "PUT",
		Path:         "/waf/template/{template_id}/file_protection",
		Disposition:  DispositionResourceWrite,
		Owner:        "fortiappseccloud_waf_template_file_protection",
		ClientMethod: "PutWAFTemplateModule",
	},
}

// FileProtectionResource records the implemented twentieth generated resource.
// It pairs a required status boolean (default false) with a required action
// string enum (default alert_deny), three required booleans (trojan, av_scan,
// json_file_support, all default false), an optional sandbox boolean (default
// false), an optional file_action string enum (default Allow), an optional
// file_size integer (default 0, range 0..102400), an optional url string (max
// 255, default /), and two optional json_* strings (max 63).
// Two object-item collections use indexed item schemas: file_types (unbounded,
// FileType item: optional type string enum and optional tid string with the
// ^\d{5}$ pattern, wire-only idx default 1) and custom_file_types (max 12,
// CustomFileType item: required name string max 52 and required file_extension
// string max 63, a nested file_content_match_rule SubItemArray max 256, and a
// wire-only idx default 0). The file_content_match_rule sub-item
// (CustomFileTypeFileContentMatchRule) carries a wire-only idx default 0,
// required data_value string max 127, and optional offset_from/operation/
// data_type/concatenate_type string enums and an offset integer range 0..4096.
//
// This resource introduces one scoped, reviewed generator exemption: the pinned
// idx default 0 on custom_file_types items and file_content_match_rule
// sub-items. Every other reviewed item schema pins idx default 1 (or no
// default for GraphQL). The exemption is source-schema-only: the generated
// runtime always writes one-based indices and rejects non-positive idx on
// read, so the pinned zero default does not affect wire behavior.
var FileProtectionResource = ReviewedCandidate{
	TerraformName:       "fortiappseccloud_waf_file_protection",
	GoName:              "FileProtection",
	TypeNameSuffix:      "waf_file_protection",
	OperationName:       "file protection",
	Path:                "/waf/apps/{ep_id}/file_protection",
	ExpectedMethods:     []string{"GET", "PUT"},
	ImplementationState: ImplementationStateImplemented,
	Refs: CandidateSchemaRefs{
		GetResponse: "#/components/schemas/GetFileProtection",
		PutRequest:  "#/components/schemas/PutFileProtection",
		Configs:     "#/components/schemas/FileProtection",
	},
	Schema: CandidateSchemaContract{
		ConfigFields: []CandidateFieldConstraint{
			{Name: "action", Kind: "string", Required: true, HasDefault: true, Default: "alert_deny", Enum: []string{"alert", "alert_deny", "deny_no_log"}},
			{Name: "av_scan", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "file_action", Kind: "string", Required: false, HasDefault: true, Default: "Allow", Enum: []string{"Allow", "Block"}},
			{Name: "file_size", Kind: "integer", Required: false, HasDefault: true, Default: 0, Minimum: ptrFloat(0), Maximum: ptrFloat(102400)},
			{Name: "json_file_support", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "json_key_field", Kind: "string", Required: false, HasDefault: false, MaxLength: 63},
			{Name: "json_key_for_filename", Kind: "string", Required: false, HasDefault: false, MaxLength: 63},
			{Name: "sandbox", Kind: "boolean", Required: false, HasDefault: true, Default: false},
			{Name: "status", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "trojan", Kind: "boolean", Required: true, HasDefault: true, Default: false},
			{Name: "url", Kind: "string", Required: false, HasDefault: true, Default: "/", MaxLength: 255},
		},
		Collections: []CandidateCollectionConstraint{
			{Name: "file_types", MaxItems: 0, Unindexed: false},
			{Name: "custom_file_types", MaxItems: 12, Unindexed: false},
		},
		CollectionItemFields: map[string][]CandidateFieldConstraint{
			"file_types": {
				{Name: "idx", Kind: "integer", Required: false, HasDefault: true, Default: 1},
				{Name: "tid", Kind: "string", Required: false, HasDefault: false, Pattern: `^\d{5}$`},
				{Name: "type", Kind: "string", Required: false, HasDefault: false, Enum: fileTypeEnum()},
			},
			"custom_file_types": {
				{Name: "match_rules", Kind: "array", Required: false, HasDefault: false, SubItemArray: &CandidateSubItemArrayConstraint{
					Name:     "match_rules",
					MaxItems: 256,
					ItemName: "CustomFileTypeFileContentMatchRule",
					ItemFields: []CandidateFieldConstraint{
						{Name: "concatenate_type", Kind: "string", Required: false, HasDefault: true, Default: "AND", Enum: []string{"AND", "OR"}},
						{Name: "data_type", Kind: "string", Required: false, HasDefault: true, Default: "string", Enum: []string{"hex_array", "string"}},
						{Name: "data_value", Kind: "string", Required: true, HasDefault: false, MaxLength: 127},
						{Name: "offset", Kind: "integer", Required: false, HasDefault: true, Default: 0, Minimum: ptrFloat(0), Maximum: ptrFloat(4096)},
						{Name: "offset_from", Kind: "string", Required: false, HasDefault: true, Default: "beginning", Enum: []string{"beginning", "end_of_last_match"}},
						{Name: "operation", Kind: "string", Required: false, HasDefault: true, Default: "equal", Enum: []string{"equal", "regex", "search"}},
					},
				}},
				{Name: "file_extension", Kind: "string", Required: true, HasDefault: false, MaxLength: 63},
				{Name: "idx", Kind: "integer", Required: false, HasDefault: true, Default: 0},
				{Name: "name", Kind: "string", Required: true, HasDefault: false, MaxLength: 52},
			},
		},
	},
	Provenance: "Implemented as the twentieth reviewed generated app-module resource and the file-protection shape: " +
		"a required status boolean (default false), a required action string enum (default alert_deny), " +
		"three required booleans (trojan, av_scan, json_file_support, all default false), an optional sandbox boolean (default false), " +
		"an optional file_action string enum (default Allow), an optional file_size integer (default 0, range 0..102400), " +
		"an optional url string (max 64, ^/.*$ pattern, default /), two optional json_key_for_filename and json_key_field strings (max 63), " +
		"and two object-item collections with indexed item schemas. " +
		"file_types (unbounded) uses the FileType item schema: optional type string enum and optional tid string (^\\d{5}$ pattern), plus the wire-only positional idx (default 1). " +
		"custom_file_types (max 12) uses the CustomFileType item schema: required name string (max 52) and required file_extension string (max 63), a nested file_content_match_rule SubItemArray (max 256), and the wire-only positional idx (default 0). " +
		"The file_content_match_rule sub-item (CustomFileTypeFileContentMatchRule) carries the wire-only idx (default 0), required data_value string (max 127), optional offset integer (default 0, range 0..4096), and optional offset_from/operation/data_type/concatenate_type string enums (defaults beginning/equal/string/AND). " +
		"This resource introduces one scoped, reviewed generator exemption: the pinned idx default 0 on custom_file_types items and file_content_match_rule sub-items. Every other reviewed item schema pins idx default 1 (or no default for GraphQL). The exemption is source-schema-only: the generated runtime always writes one-based indices and rejects non-positive idx on read, so the pinned zero default does not affect wire behavior. " +
		"The pinned public GET/PUT operations share the required configs/template envelope and use the descriptor-driven WAF module runtime. " +
		"The action/file_action enums, every config default, the file_size 0..102400 and offset 0..4096 integer bounds, the url 64-character maximum and ^/.*$ pattern, the json_key_for_filename/json_key_field 63-character maximums, the unbounded file_types bound, the 12-item custom_file_types and 256-item file_content_match_rule bounds, the FileType type enum and tid pattern, the CustomFileType name/file_extension maximums, the file_content_match_rule enums and data_value 127-character maximum, and the idx defaults are pinned from OpenAPI 26.3.a. " +
		"Destroy remains unverified forget behavior because no DELETE operation exists and status=false disable semantics have not been live-verified; " +
		"lifecycle behavior is locally tested rather than live-verified.",
}

// fileTypeEnum returns the reviewed FileType.type enum pinned from OpenAPI
// 26.3.a, sorted lexicographically to match the
// generator's enum comparison.
func fileTypeEnum() []string {
	return []string{
		"3GPP", "7-ZIP", "7-ZIP(.7z)", "AIN Archive Data(.ain)",
		"ASP(.asp)", "ASPX(.aspx)", "AVI", "Adobe encapsulated PostScript file(.EPS)",
		"Apple CoreAudio(.caf)", "Apple Lossless Audio(.m4a)", "BMP", "BMP(.bmp)",
		"BZIP2 Archive(.bz2)", "CHM", "CSV(.csv)", "Cascading Style Sheets(.css)",
		"Corel Draw Picture", "DVD Video Movie File(.vob)", "Debian Package", "Debian Package(.pkg)",
		"Digital Speech Standard(.dss)", "EXE", "EXE(.exe)", "Electronic Publication(.epub)",
		"Excel Add-In(.xlam)", "Excel Macro-Enabled Template(.xltm)", "Excel Macro-Enabled(.xlsm)", "Excel Template(.xltx)",
		"Excel(.xlsx)", "GIF", "GIF(.gif)", "Gzipped Tape Archive(.tgz)",
		"Gzipped Tape Archive(TGZ)", "Hancom Office Hanword(.hwp)", "Installshield Cabinet Archive Data", "JPEG-2000 Image File Format(.jp2)",
		"JPG", "JPG(.jpg)", "JSP(.jsp)", "Java Archive(.jar)",
		"Lotus 1-2-3 spreadsheet(.WK)", "Lotus WordPro document(.LWP)", "MIDI", "MKV",
		"MP3", "MPEG v4", "MSG(.msg)", "Macromedia Flash",
		"Microsoft Access Database(.MDB)", "Microsoft Advanced Streaming(.asf)", "Microsoft Cabinet File", "Microsoft Document Image(.mdi)",
		"Microsoft Office Excel(.xls)", "Microsoft Office PowerPoint(.ppt)", "Microsoft Office Word(.doc)", "Multipage PCX Bitmap File(.dcx)",
		"Nero CD Compilation(.NRI)", "OpenDocument Spreadsheet(.ods)", "OpenDocument Text(.odt)", "PDF",
		"PDF(.pdf)", "PHP(.php)", "PHP3(.php3)", "PHTML(.phtml)",
		"PNG", "PNG(.png)", "PPT Add-In(.ppam)", "PPT Macro-Enabled Show(.ppsm)",
		"PPT Macro-Enabled Template(.potm)", "PPT Macro-Enabled(.pptm)", "PPT Show(.ppsx)", "PPT Template(.potx)",
		"PPT(.pptx)", "Photoshop Image File(.psd)", "Privacy-Enhanced Mail(.pem)", "Quark Express Document(.qxd)",
		"RAR", "RTF", "Real Audio File(.ra)", "Real Media File(.rm)",
		"RedHat Package Manager file(.RPM)", "Rich Text Format(.rtf)", "SPSS Data(.SAV)", "SQL Server 2000 Database(.mdf)",
		"SQL(.sql)", "Scalable Vector Graphics(.svg)", "SkinCrafter skin file(.skf)", "TAR",
		"TIFF/TIF", "TXT", "TXT(.txt)", "Unix Archiver File(.ar)",
		"VMware Virtual Disk File(.vmdk)", "Visio Drawing(.vsdx)", "Visio Macro-Enabled Drawing(.vsdm)", "Visio Macro-Enabled Stencil(.vssm)",
		"Visio Macro-Enabled Template(.vstm)", "Visio Stencil(.vssx)", "Visio Template(.vstx)", "WAVE",
		"WinZIP ZIPX Archive(ZIPx)", "Windows Animated Cursor", "Windows Enhanced Metafile(.emf)", "Windows Help File(.hlp)",
		"Windows Icon", "Windows Icon(.icon)", "Windows MS Info File(.mof)", "Windows Metafile Format(.wmf)",
		"Windows Mobile Note(.pwi)", "Windows Printer Spool File(.shd)", "Windows Registry Text(.reg)", "Windows Shortcut File(.lnk)",
		"Word Macro-Enabled Template(.dotm)", "Word Macro-Enabled(.docm)", "Word Template(.dotx)", "Word(.docx)",
		"Workflow File(.workflow)", "XML", "XML(.xml)", "XPS",
		"ZIP", "ZIP(.zip)",
	}
}
