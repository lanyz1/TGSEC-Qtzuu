let byte_view = new Uint8Array(8);

let data_view = new DataView(byte_view.buffer);

function bytes(...input) {
    if (input.length == 1 && typeof input[0] == "array") input = input[0];
    if (input.length == 1 && typeof input[0] == "string") {
        let len = input[0].length;
        let view = new Uint8Array(len);
        for (let i = 0; i < len; i++) view[i] = input[0].charCodeAt(i);
        return view.buffer;
    }
    let view = new Uint8Array(input.length);
    for (let i = 0; i < input.length; i++) {
        let val = input[i];
        if (typeof val == "string") {
            if (val.length != 1) {
                throw new Error("string inputs must have length 1");
            }
            val = val.charCodeAt(0);
        }
        view[i] = val | 0;
    }
    return view.buffer;
}

var kWasmH0 = 0;

var kWasmH1 = 97;

var kWasmH2 = 115;

var kWasmH3 = 109;

var kWasmV0 = 1;

var kWasmV1 = 0;

var kWasmV2 = 0;

var kWasmV3 = 0;

var kHeaderSize = 8;

var kPageSize = 65536;

var kSpecMaxPages = 65536;

var kMaxVarInt32Size = 5;

var kMaxVarInt64Size = 10;

var kSpecMaxFunctionParams = 1e3;

let kDeclNoLocals = 0;

let kUnknownSectionCode = 0;

let kTypeSectionCode = 1;

let kImportSectionCode = 2;

let kFunctionSectionCode = 3;

let kTableSectionCode = 4;

let kMemorySectionCode = 5;

let kGlobalSectionCode = 6;

let kExportSectionCode = 7;

let kStartSectionCode = 8;

let kElementSectionCode = 9;

let kCodeSectionCode = 10;

let kDataSectionCode = 11;

let kDataCountSectionCode = 12;

let kTagSectionCode = 13;

let kStringRefSectionCode = 14;

let kLastKnownSectionCode = 14;

let kModuleNameCode = 0;

let kFunctionNamesCode = 1;

let kLocalNamesCode = 2;

let kWasmSharedTypeForm = 101;

let kWasmFunctionTypeForm = 96;

let kWasmStructTypeForm = 95;

let kWasmArrayTypeForm = 94;

let kWasmSubtypeForm = 80;

let kWasmSubtypeFinalForm = 79;

let kWasmRecursiveTypeGroupForm = 78;

let kWasmDescriptorTypeForm = 77;

let kWasmDescribesTypeForm = 76;

let kNoSuperType = 4294967295;

let kLimitsNoMaximum = 0;

let kLimitsWithMaximum = 1;

let kLimitsSharedNoMaximum = 2;

let kLimitsSharedWithMaximum = 3;

let kLimitsMemory64NoMaximum = 4;

let kLimitsMemory64WithMaximum = 5;

let kLimitsMemory64SharedNoMaximum = 6;

let kLimitsMemory64SharedWithMaximum = 7;

let kActiveNoIndex = 0;

let kPassive = 1;

let kActiveWithIndex = 2;

let kDeclarative = 3;

let kPassiveWithElements = 5;

let kDeclarativeWithElements = 7;

let kDeclFunctionName = 1;

let kDeclFunctionImport = 2;

let kDeclFunctionLocals = 4;

let kDeclFunctionExport = 8;

let kWasmVoid = 64;

let kWasmI32 = 127;

let kWasmI64 = 126;

let kWasmF32 = 125;

let kWasmF64 = 124;

let kWasmS128 = 123;

let kWasmI8 = 120;

let kWasmI16 = 119;

let kWasmF16 = 118;

let kWasmNullFuncRef = -13;

let kWasmNullExternRef = -14;

let kWasmNullRef = -15;

let kWasmFuncRef = -16;

let kWasmAnyFunc = kWasmFuncRef;

let kWasmExternRef = -17;

let kWasmAnyRef = -18;

let kWasmEqRef = -19;

let kWasmI31Ref = -20;

let kWasmStructRef = -21;

let kWasmArrayRef = -22;

let kWasmExnRef = -23;

let kWasmNullExnRef = -12;

let kWasmStringRef = -25;

let kWasmStringViewWtf8 = -26;

let kWasmStringViewWtf16 = -32;

let kWasmStringViewIter = -31;

const kWasmContRef = -24;

const kWasmNullContRef = -11;

let kLeb128Mask = 127;

let kFuncRefCode = kWasmFuncRef & kLeb128Mask;

let kAnyFuncCode = kFuncRefCode;

let kExternRefCode = kWasmExternRef & kLeb128Mask;

let kAnyRefCode = kWasmAnyRef & kLeb128Mask;

let kEqRefCode = kWasmEqRef & kLeb128Mask;

let kI31RefCode = kWasmI31Ref & kLeb128Mask;

let kNullExternRefCode = kWasmNullExternRef & kLeb128Mask;

let kNullFuncRefCode = kWasmNullFuncRef & kLeb128Mask;

let kStructRefCode = kWasmStructRef & kLeb128Mask;

let kArrayRefCode = kWasmArrayRef & kLeb128Mask;

let kExnRefCode = kWasmExnRef & kLeb128Mask;

let kNullExnRefCode = kWasmNullExnRef & kLeb128Mask;

let kNullRefCode = kWasmNullRef & kLeb128Mask;

let kStringRefCode = kWasmStringRef & kLeb128Mask;

let kStringViewWtf8Code = kWasmStringViewWtf8 & kLeb128Mask;

let kStringViewWtf16Code = kWasmStringViewWtf16 & kLeb128Mask;

let kStringViewIterCode = kWasmStringViewIter & kLeb128Mask;

const kContRefCode = kWasmContRef & kLeb128Mask;

const kNullContRefCode = kWasmNullContRef & kLeb128Mask;

let kWasmRefNull = 99;

let kWasmRef = 100;

let kWasmExact = 98;

class RefTypeBuilder {
    constructor(opcode, heap_type) {
        this.opcode = opcode;
        this.heap_type = heap_type;
        this.is_shared = false;
        this.is_exact = false;
    }
    nullable() {
        this.opcode = kWasmRefNull;
        return this;
    }
    shared() {
        this.is_shared = true;
        return this;
    }
    exact() {
        this.is_exact = true;
        return this;
    }
}

function wasmRefNullType(heap_type) {
    return new RefTypeBuilder(kWasmRefNull, heap_type);
}

function wasmRefType(heap_type) {
    return new RefTypeBuilder(kWasmRef, heap_type);
}

let kExternalFunction = 0;

let kExternalTable = 1;

let kExternalMemory = 2;

let kExternalGlobal = 3;

let kExternalTag = 4;

let kTableZero = 0;

let kMemoryZero = 0;

let kSegmentZero = 0;

let kExceptionAttribute = 0;

const kAtomicSeqCst = 0;

const kAtomicAcqRel = 1;

let kSig_i_i = makeSig([ kWasmI32 ], [ kWasmI32 ]);

let kSig_l_l = makeSig([ kWasmI64 ], [ kWasmI64 ]);

let kSig_i_l = makeSig([ kWasmI64 ], [ kWasmI32 ]);

let kSig_i_ii = makeSig([ kWasmI32, kWasmI32 ], [ kWasmI32 ]);

let kSig_i_iii = makeSig([ kWasmI32, kWasmI32, kWasmI32 ], [ kWasmI32 ]);

let kSig_i_iiii = makeSig([ kWasmI32, kWasmI32, kWasmI32, kWasmI32 ], [ kWasmI32 ]);

let kSig_v_iiii = makeSig([ kWasmI32, kWasmI32, kWasmI32, kWasmI32 ], []);

let kSig_l_iiii = makeSig([ kWasmI32, kWasmI32, kWasmI32, kWasmI32 ], [ kWasmI64 ]);

let kSig_l_i = makeSig([ kWasmI32 ], [ kWasmI64 ]);

let kSig_f_i = makeSig([ kWasmI32 ], [ kWasmF32 ]);

let kSig_i_f = makeSig([ kWasmF32 ], [ kWasmI32 ]);

let kSig_i_ff = makeSig([ kWasmF32, kWasmF32 ], [ kWasmI32 ]);

let kSig_f_ff = makeSig([ kWasmF32, kWasmF32 ], [ kWasmF32 ]);

let kSig_f_ffff = makeSig([ kWasmF32, kWasmF32, kWasmF32, kWasmF32 ], [ kWasmF32 ]);

let kSig_d_dd = makeSig([ kWasmF64, kWasmF64 ], [ kWasmF64 ]);

let kSig_d_dddd = makeSig([ kWasmF64, kWasmF64, kWasmF64, kWasmF64 ], [ kWasmF64 ]);

let kSig_l_ll = makeSig([ kWasmI64, kWasmI64 ], [ kWasmI64 ]);

let kSig_l_llll = makeSig([ kWasmI64, kWasmI64, kWasmI64, kWasmI64 ], [ kWasmI64 ]);

let kSig_i_dd = makeSig([ kWasmF64, kWasmF64 ], [ kWasmI32 ]);

let kSig_v_v = makeSig([], []);

let kSig_i_v = makeSig([], [ kWasmI32 ]);

let kSig_l_v = makeSig([], [ kWasmI64 ]);

let kSig_f_v = makeSig([], [ kWasmF32 ]);

let kSig_d_v = makeSig([], [ kWasmF64 ]);

let kSig_v_i = makeSig([ kWasmI32 ], []);

let kSig_v_ii = makeSig([ kWasmI32, kWasmI32 ], []);

let kSig_v_iii = makeSig([ kWasmI32, kWasmI32, kWasmI32 ], []);

let kSig_v_l = makeSig([ kWasmI64 ], []);

let kSig_v_li = makeSig([ kWasmI64, kWasmI32 ], []);

let kSig_v_lii = makeSig([ kWasmI64, kWasmI32, kWasmI32 ], []);

let kSig_v_d = makeSig([ kWasmF64 ], []);

let kSig_v_dd = makeSig([ kWasmF64, kWasmF64 ], []);

let kSig_v_ddi = makeSig([ kWasmF64, kWasmF64, kWasmI32 ], []);

let kSig_ii_v = makeSig([], [ kWasmI32, kWasmI32 ]);

let kSig_iii_v = makeSig([], [ kWasmI32, kWasmI32, kWasmI32 ]);

let kSig_ii_i = makeSig([ kWasmI32 ], [ kWasmI32, kWasmI32 ]);

let kSig_iii_i = makeSig([ kWasmI32 ], [ kWasmI32, kWasmI32, kWasmI32 ]);

let kSig_ii_ii = makeSig([ kWasmI32, kWasmI32 ], [ kWasmI32, kWasmI32 ]);

let kSig_iii_ii = makeSig([ kWasmI32, kWasmI32 ], [ kWasmI32, kWasmI32, kWasmI32 ]);

let kSig_v_f = makeSig([ kWasmF32 ], []);

let kSig_f_f = makeSig([ kWasmF32 ], [ kWasmF32 ]);

let kSig_f_d = makeSig([ kWasmF64 ], [ kWasmF32 ]);

let kSig_d_d = makeSig([ kWasmF64 ], [ kWasmF64 ]);

let kSig_d_f = makeSig([ kWasmF32 ], [ kWasmF64 ]);

let kSig_d_i = makeSig([ kWasmI32 ], [ kWasmF64 ]);

let kSig_r_r = makeSig([ kWasmExternRef ], [ kWasmExternRef ]);

let kSig_a_a = makeSig([ kWasmAnyFunc ], [ kWasmAnyFunc ]);

let kSig_i_r = makeSig([ kWasmExternRef ], [ kWasmI32 ]);

let kSig_v_r = makeSig([ kWasmExternRef ], []);

let kSig_v_a = makeSig([ kWasmAnyFunc ], []);

let kSig_v_rr = makeSig([ kWasmExternRef, kWasmExternRef ], []);

let kSig_v_aa = makeSig([ kWasmAnyFunc, kWasmAnyFunc ], []);

let kSig_r_v = makeSig([], [ kWasmExternRef ]);

let kSig_a_v = makeSig([], [ kWasmAnyFunc ]);

let kSig_a_i = makeSig([ kWasmI32 ], [ kWasmAnyFunc ]);

let kSig_s_i = makeSig([ kWasmI32 ], [ kWasmS128 ]);

let kSig_i_s = makeSig([ kWasmS128 ], [ kWasmI32 ]);

function makeSig(params, results) {
    return {
        params: params,
        results: results
    };
}

function makeSig_v_x(x) {
    return makeSig([ x ], []);
}

function makeSig_x_v(x) {
    return makeSig([], [ x ]);
}

function makeSig_v_xx(x) {
    return makeSig([ x, x ], []);
}

function makeSig_r_v(r) {
    return makeSig([], [ r ]);
}

function makeSig_r_x(r, x) {
    return makeSig([ x ], [ r ]);
}

function makeSig_r_xx(r, x) {
    return makeSig([ x, x ], [ r ]);
}

const kWasmOpcodes = {
    Unreachable: 0,
    Nop: 1,
    Block: 2,
    Loop: 3,
    If: 4,
    Else: 5,
    Try: 6,
    TryTable: 31,
    ThrowRef: 10,
    Catch: 7,
    Throw: 8,
    Rethrow: 9,
    CatchAll: 25,
    End: 11,
    Br: 12,
    BrIf: 13,
    BrTable: 14,
    Return: 15,
    CallFunction: 16,
    CallIndirect: 17,
    ReturnCall: 18,
    ReturnCallIndirect: 19,
    CallRef: 20,
    ReturnCallRef: 21,
    NopForTestingUnsupportedInLiftoff: 22,
    Delegate: 24,
    Drop: 26,
    Select: 27,
    SelectWithType: 28,
    LocalGet: 32,
    LocalSet: 33,
    LocalTee: 34,
    GlobalGet: 35,
    GlobalSet: 36,
    TableGet: 37,
    TableSet: 38,
    I32LoadMem: 40,
    I64LoadMem: 41,
    F32LoadMem: 42,
    F64LoadMem: 43,
    I32LoadMem8S: 44,
    I32LoadMem8U: 45,
    I32LoadMem16S: 46,
    I32LoadMem16U: 47,
    I64LoadMem8S: 48,
    I64LoadMem8U: 49,
    I64LoadMem16S: 50,
    I64LoadMem16U: 51,
    I64LoadMem32S: 52,
    I64LoadMem32U: 53,
    I32StoreMem: 54,
    I64StoreMem: 55,
    F32StoreMem: 56,
    F64StoreMem: 57,
    I32StoreMem8: 58,
    I32StoreMem16: 59,
    I64StoreMem8: 60,
    I64StoreMem16: 61,
    I64StoreMem32: 62,
    MemorySize: 63,
    MemoryGrow: 64,
    I32Const: 65,
    I64Const: 66,
    F32Const: 67,
    F64Const: 68,
    I32Eqz: 69,
    I32Eq: 70,
    I32Ne: 71,
    I32LtS: 72,
    I32LtU: 73,
    I32GtS: 74,
    I32GtU: 75,
    I32LeS: 76,
    I32LeU: 77,
    I32GeS: 78,
    I32GeU: 79,
    I64Eqz: 80,
    I64Eq: 81,
    I64Ne: 82,
    I64LtS: 83,
    I64LtU: 84,
    I64GtS: 85,
    I64GtU: 86,
    I64LeS: 87,
    I64LeU: 88,
    I64GeS: 89,
    I64GeU: 90,
    F32Eq: 91,
    F32Ne: 92,
    F32Lt: 93,
    F32Gt: 94,
    F32Le: 95,
    F32Ge: 96,
    F64Eq: 97,
    F64Ne: 98,
    F64Lt: 99,
    F64Gt: 100,
    F64Le: 101,
    F64Ge: 102,
    I32Clz: 103,
    I32Ctz: 104,
    I32Popcnt: 105,
    I32Add: 106,
    I32Sub: 107,
    I32Mul: 108,
    I32DivS: 109,
    I32DivU: 110,
    I32RemS: 111,
    I32RemU: 112,
    I32And: 113,
    I32Ior: 114,
    I32Xor: 115,
    I32Shl: 116,
    I32ShrS: 117,
    I32ShrU: 118,
    I32Rol: 119,
    I32Ror: 120,
    I64Clz: 121,
    I64Ctz: 122,
    I64Popcnt: 123,
    I64Add: 124,
    I64Sub: 125,
    I64Mul: 126,
    I64DivS: 127,
    I64DivU: 128,
    I64RemS: 129,
    I64RemU: 130,
    I64And: 131,
    I64Ior: 132,
    I64Xor: 133,
    I64Shl: 134,
    I64ShrS: 135,
    I64ShrU: 136,
    I64Rol: 137,
    I64Ror: 138,
    F32Abs: 139,
    F32Neg: 140,
    F32Ceil: 141,
    F32Floor: 142,
    F32Trunc: 143,
    F32NearestInt: 144,
    F32Sqrt: 145,
    F32Add: 146,
    F32Sub: 147,
    F32Mul: 148,
    F32Div: 149,
    F32Min: 150,
    F32Max: 151,
    F32CopySign: 152,
    F64Abs: 153,
    F64Neg: 154,
    F64Ceil: 155,
    F64Floor: 156,
    F64Trunc: 157,
    F64NearestInt: 158,
    F64Sqrt: 159,
    F64Add: 160,
    F64Sub: 161,
    F64Mul: 162,
    F64Div: 163,
    F64Min: 164,
    F64Max: 165,
    F64CopySign: 166,
    I32ConvertI64: 167,
    I32SConvertF32: 168,
    I32UConvertF32: 169,
    I32SConvertF64: 170,
    I32UConvertF64: 171,
    I64SConvertI32: 172,
    I64UConvertI32: 173,
    I64SConvertF32: 174,
    I64UConvertF32: 175,
    I64SConvertF64: 176,
    I64UConvertF64: 177,
    F32SConvertI32: 178,
    F32UConvertI32: 179,
    F32SConvertI64: 180,
    F32UConvertI64: 181,
    F32ConvertF64: 182,
    F64SConvertI32: 183,
    F64UConvertI32: 184,
    F64SConvertI64: 185,
    F64UConvertI64: 186,
    F64ConvertF32: 187,
    I32ReinterpretF32: 188,
    I64ReinterpretF64: 189,
    F32ReinterpretI32: 190,
    F64ReinterpretI64: 191,
    I32SExtendI8: 192,
    I32SExtendI16: 193,
    I64SExtendI8: 194,
    I64SExtendI16: 195,
    I64SExtendI32: 196,
    RefNull: 208,
    RefIsNull: 209,
    RefFunc: 210,
    RefEq: 211,
    RefAsNonNull: 212,
    BrOnNull: 213,
    BrOnNonNull: 214
};

function defineWasmOpcode(name, value) {
    if (globalThis.kWasmOpcodeNames === undefined) {
        globalThis.kWasmOpcodeNames = {};
    }
    Object.defineProperty(globalThis, name, {
        value: value
    });
    if (globalThis.kWasmOpcodeNames[value] !== undefined) {
        throw new Error(`Duplicate wasm opcode: ${value}. Previous name: ${globalThis.kWasmOpcodeNames[value]}, new name: ${name}`);
    }
    globalThis.kWasmOpcodeNames[value] = name;
}

for (let name in kWasmOpcodes) {
    defineWasmOpcode(`kExpr${name}`, kWasmOpcodes[name]);
}

const kPrefixOpcodes = {
    GC: 251,
    Numeric: 252,
    Simd: 253,
    Atomic: 254
};

for (let prefix in kPrefixOpcodes) {
    defineWasmOpcode(`k${prefix}Prefix`, kPrefixOpcodes[prefix]);
}

function SimdInstr(opcode) {
    if (opcode <= 127) return [ kSimdPrefix, opcode ];
    return [ kSimdPrefix, 128 | opcode & 127, opcode >> 7 ];
}

function GCInstr(opcode) {
    if (opcode <= 127) return [ kGCPrefix, opcode ];
    return [ kGCPrefix, 128 | opcode & 127, opcode >> 7 ];
}

let kExprStructNew = 0;

let kExprStructNewDefault = 1;

let kExprStructGet = 2;

let kExprStructGetS = 3;

let kExprStructGetU = 4;

let kExprStructSet = 5;

let kExprArrayNew = 6;

let kExprArrayNewDefault = 7;

let kExprArrayNewFixed = 8;

let kExprArrayNewData = 9;

let kExprArrayNewElem = 10;

let kExprArrayGet = 11;

let kExprArrayGetS = 12;

let kExprArrayGetU = 13;

let kExprArraySet = 14;

let kExprArrayLen = 15;

let kExprArrayFill = 16;

let kExprArrayCopy = 17;

let kExprArrayInitData = 18;

let kExprArrayInitElem = 19;

let kExprRefTest = 20;

let kExprRefTestNull = 21;

let kExprRefCast = 22;

let kExprRefCastNull = 23;

let kExprBrOnCast = 24;

let kExprBrOnCastFail = 25;

let kExprAnyConvertExtern = 26;

let kExprExternConvertAny = 27;

let kExprRefI31 = 28;

let kExprI31GetS = 29;

let kExprI31GetU = 30;

let kExprRefI31Shared = 31;

let kExprRefGetDesc = 34;

let kExprRefCastDesc = 35;

let kExprRefCastDescNull = 36;

let kExprBrOnCastDesc = 37;

let kExprBrOnCastDescFail = 38;

let kExprRefCastNop = 76;

let kExprStringNewUtf8 = 128;

let kExprStringNewWtf16 = 129;

let kExprStringConst = 130;

let kExprStringMeasureUtf8 = 131;

let kExprStringMeasureWtf8 = 132;

let kExprStringMeasureWtf16 = 133;

let kExprStringEncodeUtf8 = 134;

let kExprStringEncodeWtf16 = 135;

let kExprStringConcat = 136;

let kExprStringEq = 137;

let kExprStringIsUsvSequence = 138;

let kExprStringNewLossyUtf8 = 139;

let kExprStringNewWtf8 = 140;

let kExprStringEncodeLossyUtf8 = 141;

let kExprStringEncodeWtf8 = 142;

let kExprStringNewUtf8Try = 143;

let kExprStringAsWtf8 = 144;

let kExprStringViewWtf8Advance = 145;

let kExprStringViewWtf8EncodeUtf8 = 146;

let kExprStringViewWtf8Slice = 147;

let kExprStringViewWtf8EncodeLossyUtf8 = 148;

let kExprStringViewWtf8EncodeWtf8 = 149;

let kExprStringAsWtf16 = 152;

let kExprStringViewWtf16Length = 153;

let kExprStringViewWtf16GetCodeunit = 154;

let kExprStringViewWtf16Encode = 155;

let kExprStringViewWtf16Slice = 156;

let kExprStringAsIter = 160;

let kExprStringViewIterNext = 161;

let kExprStringViewIterAdvance = 162;

let kExprStringViewIterRewind = 163;

let kExprStringViewIterSlice = 164;

let kExprStringCompare = 168;

let kExprStringFromCodePoint = 169;

let kExprStringHash = 170;

let kExprStringNewUtf8Array = 176;

let kExprStringNewWtf16Array = 177;

let kExprStringEncodeUtf8Array = 178;

let kExprStringEncodeWtf16Array = 179;

let kExprStringNewLossyUtf8Array = 180;

let kExprStringNewWtf8Array = 181;

let kExprStringEncodeLossyUtf8Array = 182;

let kExprStringEncodeWtf8Array = 183;

let kExprStringNewUtf8ArrayTry = 184;

let kExprI32SConvertSatF32 = 0;

let kExprI32UConvertSatF32 = 1;

let kExprI32SConvertSatF64 = 2;

let kExprI32UConvertSatF64 = 3;

let kExprI64SConvertSatF32 = 4;

let kExprI64UConvertSatF32 = 5;

let kExprI64SConvertSatF64 = 6;

let kExprI64UConvertSatF64 = 7;

let kExprMemoryInit = 8;

let kExprDataDrop = 9;

let kExprMemoryCopy = 10;

let kExprMemoryFill = 11;

let kExprTableInit = 12;

let kExprElemDrop = 13;

let kExprTableCopy = 14;

let kExprTableGrow = 15;

let kExprTableSize = 16;

let kExprTableFill = 17;

let kExprAtomicNotify = 0;

let kExprI32AtomicWait = 1;

let kExprI64AtomicWait = 2;

let kExprAtomicFence = 3;

let kExprI32AtomicLoad = 16;

let kExprI32AtomicLoad8U = 18;

let kExprI32AtomicLoad16U = 19;

let kExprI32AtomicStore = 23;

let kExprI32AtomicStore8U = 25;

let kExprI32AtomicStore16U = 26;

let kExprI32AtomicAdd = 30;

let kExprI32AtomicAdd8U = 32;

let kExprI32AtomicAdd16U = 33;

let kExprI32AtomicSub = 37;

let kExprI32AtomicSub8U = 39;

let kExprI32AtomicSub16U = 40;

let kExprI32AtomicAnd = 44;

let kExprI32AtomicAnd8U = 46;

let kExprI32AtomicAnd16U = 47;

let kExprI32AtomicOr = 51;

let kExprI32AtomicOr8U = 53;

let kExprI32AtomicOr16U = 54;

let kExprI32AtomicXor = 58;

let kExprI32AtomicXor8U = 60;

let kExprI32AtomicXor16U = 61;

let kExprI32AtomicExchange = 65;

let kExprI32AtomicExchange8U = 67;

let kExprI32AtomicExchange16U = 68;

let kExprI32AtomicCompareExchange = 72;

let kExprI32AtomicCompareExchange8U = 74;

let kExprI32AtomicCompareExchange16U = 75;

let kExprI64AtomicLoad = 17;

let kExprI64AtomicLoad8U = 20;

let kExprI64AtomicLoad16U = 21;

let kExprI64AtomicLoad32U = 22;

let kExprI64AtomicStore = 24;

let kExprI64AtomicStore8U = 27;

let kExprI64AtomicStore16U = 28;

let kExprI64AtomicStore32U = 29;

let kExprI64AtomicAdd = 31;

let kExprI64AtomicAdd8U = 34;

let kExprI64AtomicAdd16U = 35;

let kExprI64AtomicAdd32U = 36;

let kExprI64AtomicSub = 38;

let kExprI64AtomicSub8U = 41;

let kExprI64AtomicSub16U = 42;

let kExprI64AtomicSub32U = 43;

let kExprI64AtomicAnd = 45;

let kExprI64AtomicAnd8U = 48;

let kExprI64AtomicAnd16U = 49;

let kExprI64AtomicAnd32U = 50;

let kExprI64AtomicOr = 52;

let kExprI64AtomicOr8U = 55;

let kExprI64AtomicOr16U = 56;

let kExprI64AtomicOr32U = 57;

let kExprI64AtomicXor = 59;

let kExprI64AtomicXor8U = 62;

let kExprI64AtomicXor16U = 63;

let kExprI64AtomicXor32U = 64;

let kExprI64AtomicExchange = 66;

let kExprI64AtomicExchange8U = 69;

let kExprI64AtomicExchange16U = 70;

let kExprI64AtomicExchange32U = 71;

let kExprI64AtomicCompareExchange = 73;

let kExprI64AtomicCompareExchange8U = 76;

let kExprI64AtomicCompareExchange16U = 77;

let kExprI64AtomicCompareExchange32U = 78;

const kExprStructAtomicGet = 92;

const kExprStructAtomicGetS = 93;

const kExprStructAtomicGetU = 94;

const kExprStructAtomicSet = 95;

const kExprStructAtomicAdd = 96;

const kExprStructAtomicSub = 97;

const kExprStructAtomicAnd = 98;

const kExprStructAtomicOr = 99;

const kExprStructAtomicXor = 100;

const kExprArrayAtomicGet = 103;

const kExprArrayAtomicGetS = 104;

const kExprArrayAtomicGetU = 105;

const kExprArrayAtomicSet = 106;

const kExprArrayAtomicAdd = 107;

const kExprArrayAtomicSub = 108;

const kExprArrayAtomicAnd = 109;

const kExprArrayAtomicOr = 110;

const kExprArrayAtomicXor = 111;

let kExprS128LoadMem = 0;

let kExprS128Load8x8S = 1;

let kExprS128Load8x8U = 2;

let kExprS128Load16x4S = 3;

let kExprS128Load16x4U = 4;

let kExprS128Load32x2S = 5;

let kExprS128Load32x2U = 6;

let kExprS128Load8Splat = 7;

let kExprS128Load16Splat = 8;

let kExprS128Load32Splat = 9;

let kExprS128Load64Splat = 10;

let kExprS128StoreMem = 11;

let kExprS128Const = 12;

let kExprI8x16Shuffle = 13;

let kExprI8x16Swizzle = 14;

let kExprI8x16Splat = 15;

let kExprI16x8Splat = 16;

let kExprI32x4Splat = 17;

let kExprI64x2Splat = 18;

let kExprF32x4Splat = 19;

let kExprF64x2Splat = 20;

let kExprI8x16ExtractLaneS = 21;

let kExprI8x16ExtractLaneU = 22;

let kExprI8x16ReplaceLane = 23;

let kExprI16x8ExtractLaneS = 24;

let kExprI16x8ExtractLaneU = 25;

let kExprI16x8ReplaceLane = 26;

let kExprI32x4ExtractLane = 27;

let kExprI32x4ReplaceLane = 28;

let kExprI64x2ExtractLane = 29;

let kExprI64x2ReplaceLane = 30;

let kExprF32x4ExtractLane = 31;

let kExprF32x4ReplaceLane = 32;

let kExprF64x2ExtractLane = 33;

let kExprF64x2ReplaceLane = 34;

let kExprI8x16Eq = 35;

let kExprI8x16Ne = 36;

let kExprI8x16LtS = 37;

let kExprI8x16LtU = 38;

let kExprI8x16GtS = 39;

let kExprI8x16GtU = 40;

let kExprI8x16LeS = 41;

let kExprI8x16LeU = 42;

let kExprI8x16GeS = 43;

let kExprI8x16GeU = 44;

let kExprI16x8Eq = 45;

let kExprI16x8Ne = 46;

let kExprI16x8LtS = 47;

let kExprI16x8LtU = 48;

let kExprI16x8GtS = 49;

let kExprI16x8GtU = 50;

let kExprI16x8LeS = 51;

let kExprI16x8LeU = 52;

let kExprI16x8GeS = 53;

let kExprI16x8GeU = 54;

let kExprI32x4Eq = 55;

let kExprI32x4Ne = 56;

let kExprI32x4LtS = 57;

let kExprI32x4LtU = 58;

let kExprI32x4GtS = 59;

let kExprI32x4GtU = 60;

let kExprI32x4LeS = 61;

let kExprI32x4LeU = 62;

let kExprI32x4GeS = 63;

let kExprI32x4GeU = 64;

let kExprF32x4Eq = 65;

let kExprF32x4Ne = 66;

let kExprF32x4Lt = 67;

let kExprF32x4Gt = 68;

let kExprF32x4Le = 69;

let kExprF32x4Ge = 70;

let kExprF64x2Eq = 71;

let kExprF64x2Ne = 72;

let kExprF64x2Lt = 73;

let kExprF64x2Gt = 74;

let kExprF64x2Le = 75;

let kExprF64x2Ge = 76;

let kExprS128Not = 77;

let kExprS128And = 78;

let kExprS128AndNot = 79;

let kExprS128Or = 80;

let kExprS128Xor = 81;

let kExprS128Select = 82;

let kExprV128AnyTrue = 83;

let kExprS128Load8Lane = 84;

let kExprS128Load16Lane = 85;

let kExprS128Load32Lane = 86;

let kExprS128Load64Lane = 87;

let kExprS128Store8Lane = 88;

let kExprS128Store16Lane = 89;

let kExprS128Store32Lane = 90;

let kExprS128Store64Lane = 91;

let kExprS128Load32Zero = 92;

let kExprS128Load64Zero = 93;

let kExprF32x4DemoteF64x2Zero = 94;

let kExprF64x2PromoteLowF32x4 = 95;

let kExprI8x16Abs = 96;

let kExprI8x16Neg = 97;

let kExprI8x16Popcnt = 98;

let kExprI8x16AllTrue = 99;

let kExprI8x16BitMask = 100;

let kExprI8x16SConvertI16x8 = 101;

let kExprI8x16UConvertI16x8 = 102;

let kExprF32x4Ceil = 103;

let kExprF32x4Floor = 104;

let kExprF32x4Trunc = 105;

let kExprF32x4NearestInt = 106;

let kExprI8x16Shl = 107;

let kExprI8x16ShrS = 108;

let kExprI8x16ShrU = 109;

let kExprI8x16Add = 110;

let kExprI8x16AddSatS = 111;

let kExprI8x16AddSatU = 112;

let kExprI8x16Sub = 113;

let kExprI8x16SubSatS = 114;

let kExprI8x16SubSatU = 115;

let kExprF64x2Ceil = 116;

let kExprF64x2Floor = 117;

let kExprI8x16MinS = 118;

let kExprI8x16MinU = 119;

let kExprI8x16MaxS = 120;

let kExprI8x16MaxU = 121;

let kExprF64x2Trunc = 122;

let kExprI8x16RoundingAverageU = 123;

let kExprI16x8ExtAddPairwiseI8x16S = 124;

let kExprI16x8ExtAddPairwiseI8x16U = 125;

let kExprI32x4ExtAddPairwiseI16x8S = 126;

let kExprI32x4ExtAddPairwiseI16x8U = 127;

let kExprI16x8Abs = 128;

let kExprI16x8Neg = 129;

let kExprI16x8Q15MulRSatS = 130;

let kExprI16x8AllTrue = 131;

let kExprI16x8BitMask = 132;

let kExprI16x8SConvertI32x4 = 133;

let kExprI16x8UConvertI32x4 = 134;

let kExprI16x8SConvertI8x16Low = 135;

let kExprI16x8SConvertI8x16High = 136;

let kExprI16x8UConvertI8x16Low = 137;

let kExprI16x8UConvertI8x16High = 138;

let kExprI16x8Shl = 139;

let kExprI16x8ShrS = 140;

let kExprI16x8ShrU = 141;

let kExprI16x8Add = 142;

let kExprI16x8AddSatS = 143;

let kExprI16x8AddSatU = 144;

let kExprI16x8Sub = 145;

let kExprI16x8SubSatS = 146;

let kExprI16x8SubSatU = 147;

let kExprF64x2NearestInt = 148;

let kExprI16x8Mul = 149;

let kExprI16x8MinS = 150;

let kExprI16x8MinU = 151;

let kExprI16x8MaxS = 152;

let kExprI16x8MaxU = 153;

let kExprI16x8RoundingAverageU = 155;

let kExprI16x8ExtMulLowI8x16S = 156;

let kExprI16x8ExtMulHighI8x16S = 157;

let kExprI16x8ExtMulLowI8x16U = 158;

let kExprI16x8ExtMulHighI8x16U = 159;

let kExprI32x4Abs = 160;

let kExprI32x4Neg = 161;

let kExprI32x4AllTrue = 163;

let kExprI32x4BitMask = 164;

let kExprI32x4SConvertI16x8Low = 167;

let kExprI32x4SConvertI16x8High = 168;

let kExprI32x4UConvertI16x8Low = 169;

let kExprI32x4UConvertI16x8High = 170;

let kExprI32x4Shl = 171;

let kExprI32x4ShrS = 172;

let kExprI32x4ShrU = 173;

let kExprI32x4Add = 174;

let kExprI32x4Sub = 177;

let kExprI32x4Mul = 181;

let kExprI32x4MinS = 182;

let kExprI32x4MinU = 183;

let kExprI32x4MaxS = 184;

let kExprI32x4MaxU = 185;

let kExprI32x4DotI16x8S = 186;

let kExprI32x4ExtMulLowI16x8S = 188;

let kExprI32x4ExtMulHighI16x8S = 189;

let kExprI32x4ExtMulLowI16x8U = 190;

let kExprI32x4ExtMulHighI16x8U = 191;

let kExprI64x2Abs = 192;

let kExprI64x2Neg = 193;

let kExprI64x2AllTrue = 195;

let kExprI64x2BitMask = 196;

let kExprI64x2SConvertI32x4Low = 199;

let kExprI64x2SConvertI32x4High = 200;

let kExprI64x2UConvertI32x4Low = 201;

let kExprI64x2UConvertI32x4High = 202;

let kExprI64x2Shl = 203;

let kExprI64x2ShrS = 204;

let kExprI64x2ShrU = 205;

let kExprI64x2Add = 206;

let kExprI64x2Sub = 209;

let kExprI64x2Mul = 213;

let kExprI64x2Eq = 214;

let kExprI64x2Ne = 215;

let kExprI64x2LtS = 216;

let kExprI64x2GtS = 217;

let kExprI64x2LeS = 218;

let kExprI64x2GeS = 219;

let kExprI64x2ExtMulLowI32x4S = 220;

let kExprI64x2ExtMulHighI32x4S = 221;

let kExprI64x2ExtMulLowI32x4U = 222;

let kExprI64x2ExtMulHighI32x4U = 223;

let kExprF32x4Abs = 224;

let kExprF32x4Neg = 225;

let kExprF32x4Sqrt = 227;

let kExprF32x4Add = 228;

let kExprF32x4Sub = 229;

let kExprF32x4Mul = 230;

let kExprF32x4Div = 231;

let kExprF32x4Min = 232;

let kExprF32x4Max = 233;

let kExprF32x4Pmin = 234;

let kExprF32x4Pmax = 235;

let kExprF64x2Abs = 236;

let kExprF64x2Neg = 237;

let kExprF64x2Sqrt = 239;

let kExprF64x2Add = 240;

let kExprF64x2Sub = 241;

let kExprF64x2Mul = 242;

let kExprF64x2Div = 243;

let kExprF64x2Min = 244;

let kExprF64x2Max = 245;

let kExprF64x2Pmin = 246;

let kExprF64x2Pmax = 247;

let kExprI32x4SConvertF32x4 = 248;

let kExprI32x4UConvertF32x4 = 249;

let kExprF32x4SConvertI32x4 = 250;

let kExprF32x4UConvertI32x4 = 251;

let kExprI32x4TruncSatF64x2SZero = 252;

let kExprI32x4TruncSatF64x2UZero = 253;

let kExprF64x2ConvertLowI32x4S = 254;

let kExprF64x2ConvertLowI32x4U = 255;

let kExprI8x16RelaxedSwizzle = wasmSignedLeb(256);

let kExprI32x4RelaxedTruncF32x4S = wasmSignedLeb(257);

let kExprI32x4RelaxedTruncF32x4U = wasmSignedLeb(258);

let kExprI32x4RelaxedTruncF64x2SZero = wasmSignedLeb(259);

let kExprI32x4RelaxedTruncF64x2UZero = wasmSignedLeb(260);

let kExprF32x4Qfma = wasmSignedLeb(261);

let kExprF32x4Qfms = wasmSignedLeb(262);

let kExprF64x2Qfma = wasmSignedLeb(263);

let kExprF64x2Qfms = wasmSignedLeb(264);

let kExprI8x16RelaxedLaneSelect = wasmSignedLeb(265);

let kExprI16x8RelaxedLaneSelect = wasmSignedLeb(266);

let kExprI32x4RelaxedLaneSelect = wasmSignedLeb(267);

let kExprI64x2RelaxedLaneSelect = wasmSignedLeb(268);

let kExprF32x4RelaxedMin = wasmSignedLeb(269);

let kExprF32x4RelaxedMax = wasmSignedLeb(270);

let kExprF64x2RelaxedMin = wasmSignedLeb(271);

let kExprF64x2RelaxedMax = wasmSignedLeb(272);

let kExprI16x8RelaxedQ15MulRS = wasmSignedLeb(273);

let kExprI16x8DotI8x16I7x16S = wasmSignedLeb(274);

let kExprI32x4DotI8x16I7x16AddS = wasmSignedLeb(275);

let kExprF16x8Splat = wasmSignedLeb(288);

let kExprF16x8ExtractLane = wasmSignedLeb(289);

let kExprF16x8ReplaceLane = wasmSignedLeb(290);

let kExprF16x8Abs = wasmSignedLeb(304);

let kExprF16x8Neg = wasmSignedLeb(305);

let kExprF16x8Sqrt = wasmSignedLeb(306);

let kExprF16x8Ceil = wasmSignedLeb(307);

let kExprF16x8Floor = wasmSignedLeb(308);

let kExprF16x8Trunc = wasmSignedLeb(309);

let kExprF16x8NearestInt = wasmSignedLeb(310);

let kExprF16x8Eq = wasmSignedLeb(311);

let kExprF16x8Ne = wasmSignedLeb(312);

let kExprF16x8Lt = wasmSignedLeb(313);

let kExprF16x8Gt = wasmSignedLeb(314);

let kExprF16x8Le = wasmSignedLeb(315);

let kExprF16x8Ge = wasmSignedLeb(316);

let kExprF16x8Add = wasmSignedLeb(317);

let kExprF16x8Sub = wasmSignedLeb(318);

let kExprF16x8Mul = wasmSignedLeb(319);

let kExprF16x8Div = wasmSignedLeb(320);

let kExprF16x8Min = wasmSignedLeb(321);

let kExprF16x8Max = wasmSignedLeb(322);

let kExprF16x8Pmin = wasmSignedLeb(323);

let kExprF16x8Pmax = wasmSignedLeb(324);

let kExprI16x8SConvertF16x8 = wasmSignedLeb(325);

let kExprI16x8UConvertF16x8 = wasmSignedLeb(326);

let kExprF16x8SConvertI16x8 = wasmSignedLeb(327);

let kExprF16x8UConvertI16x8 = wasmSignedLeb(328);

let kExprF16x8DemoteF32x4Zero = wasmSignedLeb(329);

let kExprF16x8DemoteF64x2Zero = wasmSignedLeb(330);

let kExprF32x4PromoteLowF16x8 = wasmSignedLeb(331);

let kExprF16x8Qfma = wasmSignedLeb(334);

let kExprF16x8Qfms = wasmSignedLeb(335);

let kCompilationHintStrategyDefault = 0;

let kCompilationHintStrategyLazy = 1;

let kCompilationHintStrategyEager = 2;

let kCompilationHintStrategyLazyBaselineEagerTopTier = 3;

let kCompilationHintTierDefault = 0;

let kCompilationHintTierBaseline = 1;

let kCompilationHintTierOptimized = 2;

let kTrapUnreachable = 0;

let kTrapMemOutOfBounds = 1;

let kTrapDivByZero = 2;

let kTrapDivUnrepresentable = 3;

let kTrapRemByZero = 4;

let kTrapFloatUnrepresentable = 5;

let kTrapTableOutOfBounds = 6;

let kTrapFuncSigMismatch = 7;

let kTrapUnalignedAccess = 8;

let kTrapDataSegmentOutOfBounds = 9;

let kTrapElementSegmentOutOfBounds = 10;

let kTrapRethrowNull = 11;

let kTrapArrayTooLarge = 12;

let kTrapArrayOutOfBounds = 13;

let kTrapNullDereference = 14;

let kTrapIllegalCast = 15;

let kAtomicWaitOk = 0;

let kAtomicWaitNotEqual = 1;

let kAtomicWaitTimedOut = 2;

let kCatchNoRef = 0;

let kCatchRef = 1;

let kCatchAllNoRef = 2;

let kCatchAllRef = 3;

let kTrapMsgs = [ "unreachable", "memory access out of bounds", "divide by zero", "divide result unrepresentable", "remainder by zero", "float unrepresentable in integer range", "table index is out of bounds", "null function or function signature mismatch", "operation does not support unaligned accesses", "data segment out of bounds", "element segment out of bounds", "rethrowing null value", "requested new array is too large", "array element access out of bounds", "dereferencing a null pointer", "illegal cast" ];

function assertTraps(trap, code) {
    assertThrows(code, WebAssembly.RuntimeError, new RegExp(kTrapMsgs[trap]));
}

function assertTrapsOneOf(traps, code) {
    const errorChecker = new RegExp("(" + traps.map(trap => kTrapMsgs[trap]).join("|") + ")");
    assertThrows(code, WebAssembly.RuntimeError, errorChecker);
}

class Binary {
    constructor() {
        this.length = 0;
        this.buffer = new Uint8Array(8192);
    }
    ensure_space(needed) {
        if (this.buffer.length - this.length >= needed) return;
        let new_capacity = this.buffer.length * 2;
        while (new_capacity - this.length < needed) new_capacity *= 2;
        let new_buffer = new Uint8Array(new_capacity);
        new_buffer.set(this.buffer);
        this.buffer = new_buffer;
    }
    trunc_buffer() {
        return new Uint8Array(this.buffer.buffer, 0, this.length);
    }
    reset() {
        this.length = 0;
    }
    emit_u8(val) {
        this.ensure_space(1);
        this.buffer[this.length++] = val;
    }
    emit_u16(val) {
        this.ensure_space(2);
        this.buffer[this.length++] = val;
        this.buffer[this.length++] = val >> 8;
    }
    emit_u32(val) {
        this.ensure_space(4);
        this.buffer[this.length++] = val;
        this.buffer[this.length++] = val >> 8;
        this.buffer[this.length++] = val >> 16;
        this.buffer[this.length++] = val >> 24;
    }
    emit_leb_u(val, max_len) {
        this.ensure_space(max_len);
        for (let i = 0; i < max_len; ++i) {
            let v = val & 255;
            val = val >>> 7;
            if (val == 0) {
                this.buffer[this.length++] = v;
                return;
            }
            this.buffer[this.length++] = v | 128;
        }
        throw new Error("Leb value exceeds maximum length of " + max_len);
    }
    emit_u32v(val) {
        this.emit_leb_u(val, kMaxVarInt32Size);
    }
    emit_u64v(val) {
        this.emit_leb_u(val, kMaxVarInt64Size);
    }
    emit_bytes(data) {
        this.ensure_space(data.length);
        this.buffer.set(data, this.length);
        this.length += data.length;
    }
    emit_string(string) {
        if (string instanceof Array) {
            this.emit_u32v(string.length);
            this.emit_bytes(string);
            return;
        }
        let string_utf8 = unescape(encodeURIComponent(string));
        this.emit_u32v(string_utf8.length);
        for (let i = 0; i < string_utf8.length; i++) {
            this.emit_u8(string_utf8.charCodeAt(i));
        }
    }
    emit_heap_type(heap_type) {
        this.emit_bytes(wasmSignedLeb(heap_type, kMaxVarInt32Size));
    }
    emit_type(type) {
        if (typeof type == "number") {
            this.emit_u8(type >= 0 ? type : type & kLeb128Mask);
        } else {
            this.emit_u8(type.opcode);
            if (type.is_shared) this.emit_u8(kWasmSharedTypeForm);
            if (type.is_exact) this.emit_u8(kWasmExact);
            this.emit_heap_type(type.heap_type);
        }
    }
    emit_init_expr(expr) {
        this.emit_bytes(expr);
        this.emit_u8(kExprEnd);
    }
    emit_header() {
        this.emit_bytes([ kWasmH0, kWasmH1, kWasmH2, kWasmH3, kWasmV0, kWasmV1, kWasmV2, kWasmV3 ]);
    }
    emit_section(section_code, content_generator) {
        this.emit_u8(section_code);
        const section = new Binary;
        content_generator(section);
        this.emit_u32v(section.length);
        this.emit_bytes(section.trunc_buffer());
    }
}

class WasmFunctionBuilder {
    constructor(module, name, type_index, arg_names) {
        this.module = module;
        this.name = name;
        this.type_index = type_index;
        this.body = [];
        this.locals = [];
        this.local_names = arg_names;
        this.body_offset = undefined;
    }
    numLocalNames() {
        let num_local_names = 0;
        for (let loc_name of this.local_names) {
            if (typeof loc_name == "string") ++num_local_names;
        }
        return num_local_names;
    }
    exportAs(name) {
        this.module.addExport(name, this.index);
        return this;
    }
    exportFunc() {
        this.exportAs(this.name);
        return this;
    }
    setCompilationHint(strategy, baselineTier, topTier) {
        this.module.setCompilationHint(strategy, baselineTier, topTier, this.index);
        return this;
    }
    addBody(body) {
        checkExpr(body);
        this.body = body.concat([ kExprEnd ]);
        return this;
    }
    addBodyWithEnd(body) {
        this.body = body;
        return this;
    }
    getNumLocals() {
        let total_locals = 0;
        for (let l of this.locals) {
            total_locals += l.count;
        }
        return total_locals;
    }
    addLocals(type, count, names) {
        this.locals.push({
            type: type,
            count: count
        });
        names = names || [];
        if (names.length > count) throw new Error("too many locals names given");
        this.local_names.push(...names);
        if (count > names.length) this.local_names.push(count - names.length);
        return this;
    }
    end() {
        return this.module;
    }
}

class WasmGlobalBuilder {
    constructor(module, type, mutable, shared, init) {
        this.module = module;
        this.type = type;
        this.mutable = mutable;
        this.shared = shared;
        this.init = init;
    }
    exportAs(name) {
        this.module.exports.push({
            name: name,
            kind: kExternalGlobal,
            index: this.index
        });
        return this;
    }
}

function checkExpr(expr) {
    for (let b of expr) {
        if (typeof b !== "number" || (b & ~255) !== 0) {
            throw new Error("invalid body (entries must be 8 bit numbers): " + expr);
        }
    }
}

class WasmTableBuilder {
    constructor(module, type, initial_size, max_size, init_expr, is_shared, is_table64) {
        this.module = module;
        this.type = type;
        this.initial_size = initial_size;
        this.has_max = max_size !== undefined;
        this.max_size = max_size;
        this.init_expr = init_expr;
        this.has_init = init_expr !== undefined;
        this.is_shared = is_shared;
        this.is_table64 = is_table64;
    }
    exportAs(name) {
        this.module.exports.push({
            name: name,
            kind: kExternalTable,
            index: this.index
        });
        return this;
    }
}

function makeField(type, mutability) {
    if (typeof mutability != "boolean") {
        throw new Error("field mutability must be boolean");
    }
    return {
        type: type,
        mutability: mutability
    };
}

function MustBeNumber(x, name) {
    if (typeof x !== "undefined" && typeof x !== "number") {
        throw new Error(`${name} must be a number, was ${x}`);
    }
    return x;
}

class WasmStruct {
    constructor(fields, is_final, is_shared, supertype_idx) {
        let descriptor = undefined;
        let describes = undefined;
        if (Array.isArray(fields)) {} else if (fields.constructor === Object) {
            is_final = fields.is_final ?? fields.final ?? false;
            is_shared = fields.is_shared ?? fields.shared ?? false;
            supertype_idx = MustBeNumber(fields.supertype_idx ?? fields.supertype ?? kNoSuperType, "supertype");
            descriptor = MustBeNumber(fields.descriptor, "'descriptor'");
            describes = MustBeNumber(fields.describes, "'describes'");
            fields = fields.fields ?? [];
        } else {
            throw new Error("struct fields must be an array");
        }
        this.fields = fields;
        this.type_form = kWasmStructTypeForm;
        this.is_final = is_final;
        this.is_shared = is_shared;
        this.supertype = supertype_idx;
        this.descriptor = descriptor;
        this.describes = describes;
    }
}

class WasmArray {
    constructor(type, mutability, is_final, is_shared, supertype_idx) {
        this.type = type;
        this.mutability = mutability;
        this.type_form = kWasmArrayTypeForm;
        this.is_final = is_final;
        this.is_shared = is_shared;
        this.supertype = supertype_idx;
    }
}

class WasmElemSegment {
    constructor(table, offset, type, elements, is_decl, is_shared) {
        this.table = table;
        this.offset = offset;
        this.type = type;
        this.elements = elements;
        this.is_decl = is_decl;
        this.is_shared = is_shared;
        if (table === undefined != (offset === undefined)) {
            throw new Error("invalid element segment");
        }
        for (let elem of elements) {
            if (typeof elem == "number" != (type === undefined)) {
                throw new Error("invalid element");
            }
        }
    }
    is_active() {
        return this.table !== undefined;
    }
    is_passive() {
        return this.table === undefined && !this.is_decl;
    }
    is_declarative() {
        return this.table === undefined && this.is_decl;
    }
    expressions_as_elements() {
        return this.type !== undefined;
    }
}

class WasmModuleBuilder {
    constructor() {
        this.types = [];
        this.imports = [];
        this.exports = [];
        this.stringrefs = [];
        this.globals = [];
        this.tables = [];
        this.tags = [];
        this.memories = [];
        this.functions = [];
        this.compilation_hints = [];
        this.element_segments = [];
        this.data_segments = [];
        this.explicit = [];
        this.rec_groups = [];
        this.num_imported_funcs = 0;
        this.num_imported_globals = 0;
        this.num_imported_tables = 0;
        this.num_imported_tags = 0;
        return this;
    }
    addStart(start_index) {
        this.start_index = start_index;
        return this;
    }
    addMemory(min, max, shared) {
        const imported_memories = this.imports.filter(i => i.kind == kExternalMemory).length;
        const mem_index = imported_memories + this.memories.length;
        this.memories.push({
            min: min,
            max: max,
            shared: shared || false,
            is_memory64: false
        });
        return mem_index;
    }
    addMemory64(min, max, shared) {
        const imported_memories = this.imports.filter(i => i.kind == kExternalMemory).length;
        const mem_index = imported_memories + this.memories.length;
        this.memories.push({
            min: min,
            max: max,
            shared: shared || false,
            is_memory64: true
        });
        return mem_index;
    }
    addExplicitSection(bytes) {
        this.explicit.push(bytes);
        return this;
    }
    stringToBytes(name) {
        var result = new Binary;
        result.emit_u32v(name.length);
        for (var i = 0; i < name.length; i++) {
            result.emit_u8(name.charCodeAt(i));
        }
        return result.trunc_buffer();
    }
    createCustomSection(name, bytes) {
        name = this.stringToBytes(name);
        var section = new Binary;
        section.emit_u8(0);
        section.emit_u32v(name.length + bytes.length);
        section.emit_bytes(name);
        section.emit_bytes(bytes);
        return section.trunc_buffer();
    }
    addCustomSection(name, bytes) {
        this.explicit.push(this.createCustomSection(name, bytes));
    }
    addType(type, supertype_idx = kNoSuperType, is_final = true, is_shared = false) {
        var pl = type.params.length;
        var rl = type.results.length;
        var type_copy = {
            params: type.params,
            results: type.results,
            is_final: is_final,
            is_shared: is_shared,
            supertype: supertype_idx
        };
        this.types.push(type_copy);
        return this.types.length - 1;
    }
    addLiteralStringRef(str) {
        this.stringrefs.push(str);
        return this.stringrefs.length - 1;
    }
    addStruct(fields, supertype_idx = kNoSuperType, is_final = false, is_shared = false) {
        this.types.push(new WasmStruct(fields, is_final, is_shared, supertype_idx));
        return this.types.length - 1;
    }
    addArray(type, mutability, supertype_idx = kNoSuperType, is_final = false, is_shared = false) {
        this.types.push(new WasmArray(type, mutability, is_final, is_shared, supertype_idx));
        return this.types.length - 1;
    }
    nextTypeIndex() {
        return this.types.length;
    }
    static defaultFor(type) {
        switch (type) {
          case kWasmI32:
            return wasmI32Const(0);

          case kWasmI64:
            return wasmI64Const(0);

          case kWasmF32:
            return wasmF32Const(0);

          case kWasmF64:
            return wasmF64Const(0);

          case kWasmS128:
            return [ kSimdPrefix, kExprS128Const, ...new Array(16).fill(0) ];

          case kWasmStringViewIter:
          case kWasmStringViewWtf8:
          case kWasmStringViewWtf16:
            throw new Error("String views are non-defaultable");

          default:
            if (typeof type != "number" && type.opcode != kWasmRefNull) {
                throw new Error("Non-defaultable type");
            }
            let heap_type = typeof type == "number" ? type : type.heap_type;
            return [ kExprRefNull, ...wasmSignedLeb(heap_type, kMaxVarInt32Size) ];
        }
    }
    addGlobal(type, mutable, shared, init) {
        if (init === undefined) init = WasmModuleBuilder.defaultFor(type);
        checkExpr(init);
        let glob = new WasmGlobalBuilder(this, type, mutable, shared, init);
        glob.index = this.globals.length + this.num_imported_globals;
        this.globals.push(glob);
        return glob;
    }
    addTable(type, initial_size, max_size = undefined, init_expr = undefined, is_shared = false, is_table64 = false) {
        if (type == kWasmI32 || type == kWasmI64 || type == kWasmF32 || type == kWasmF64 || type == kWasmS128 || type == kWasmVoid) {
            throw new Error("Tables must be of a reference type");
        }
        if (init_expr != undefined) checkExpr(init_expr);
        let table = new WasmTableBuilder(this, type, initial_size, max_size, init_expr, is_shared, is_table64);
        table.index = this.tables.length + this.num_imported_tables;
        this.tables.push(table);
        return table;
    }
    addTable64(type, initial_size, max_size = undefined, init_expr = undefined, is_shared = false) {
        return this.addTable(type, initial_size, max_size, init_expr, is_shared, true);
    }
    addTag(type) {
        let type_index = typeof type == "number" ? type : this.addType(type);
        let tag_index = this.tags.length + this.num_imported_tags;
        this.tags.push(type_index);
        return tag_index;
    }
    addFunction(name, type, arg_names) {
        arg_names = arg_names || [];
        let type_index = typeof type == "number" ? type : this.addType(type);
        let num_args = this.types[type_index].params.length;
        if (num_args < arg_names.length) throw new Error("too many arg names provided");
        if (num_args > arg_names.length) arg_names.push(num_args - arg_names.length);
        let func = new WasmFunctionBuilder(this, name, type_index, arg_names);
        func.index = this.functions.length + this.num_imported_funcs;
        this.functions.push(func);
        return func;
    }
    addImport(module, name, type) {
        if (this.functions.length != 0) {
            throw new Error("Imported functions must be declared before local ones");
        }
        let type_index = typeof type == "number" ? type : this.addType(type);
        this.imports.push({
            module: module,
            name: name,
            kind: kExternalFunction,
            type_index: type_index
        });
        return this.num_imported_funcs++;
    }
    addImportedGlobal(module, name, type, mutable = false, shared = false) {
        if (this.globals.length != 0) {
            throw new Error("Imported globals must be declared before local ones");
        }
        let o = {
            module: module,
            name: name,
            kind: kExternalGlobal,
            type: type,
            mutable: mutable,
            shared: shared
        };
        this.imports.push(o);
        return this.num_imported_globals++;
    }
    addImportedMemory(module, name, initial = 0, maximum, shared, is_memory64) {
        if (this.memories.length !== 0) {
            throw new Error("Add imported memories before declared memories to avoid messing " + "up the indexes");
        }
        let mem_index = this.imports.filter(i => i.kind == kExternalMemory).length;
        let o = {
            module: module,
            name: name,
            kind: kExternalMemory,
            initial: initial,
            maximum: maximum,
            shared: !!shared,
            is_memory64: !!is_memory64
        };
        this.imports.push(o);
        return mem_index;
    }
    addImportedTable(module, name, initial, maximum, type = kWasmFuncRef, shared = false, is_table64 = false) {
        if (this.tables.length != 0) {
            throw new Error("Imported tables must be declared before local ones");
        }
        let o = {
            module: module,
            name: name,
            kind: kExternalTable,
            initial: initial,
            maximum: maximum,
            type: type,
            shared: !!shared,
            is_table64: !!is_table64
        };
        this.imports.push(o);
        return this.num_imported_tables++;
    }
    addImportedTag(module, name, type) {
        if (this.tags.length != 0) {
            throw new Error("Imported tags must be declared before local ones");
        }
        let type_index = typeof type == "number" ? type : this.addType(type);
        let o = {
            module: module,
            name: name,
            kind: kExternalTag,
            type_index: type_index
        };
        this.imports.push(o);
        return this.num_imported_tags++;
    }
    addExport(name, index) {
        this.exports.push({
            name: name,
            kind: kExternalFunction,
            index: index
        });
        return this;
    }
    addExportOfKind(name, kind, index) {
        if (index === undefined && kind != kExternalTable && kind != kExternalMemory) {
            throw new Error("Index for exports other than tables/memories must be provided");
        }
        if (index !== undefined && typeof index != "number") {
            throw new Error("Index for exports must be a number");
        }
        this.exports.push({
            name: name,
            kind: kind,
            index: index
        });
        return this;
    }
    setCompilationHint(strategy, baselineTier, topTier, index) {
        this.compilation_hints[index] = {
            strategy: strategy,
            baselineTier: baselineTier,
            topTier: topTier
        };
        return this;
    }
    addActiveDataSegment(memory_index, offset, data, is_shared = false) {
        checkExpr(offset);
        this.data_segments.push({
            is_active: true,
            is_shared: is_shared,
            mem_index: memory_index,
            offset: offset,
            data: data
        });
        return this.data_segments.length - 1;
    }
    addPassiveDataSegment(data, is_shared = false) {
        this.data_segments.push({
            is_active: false,
            is_shared: is_shared,
            data: data
        });
        return this.data_segments.length - 1;
    }
    exportMemoryAs(name, memory_index) {
        if (memory_index === undefined) {
            const num_memories = this.memories.length + this.imports.filter(i => i.kind == kExternalMemory).length;
            if (num_memories !== 1) {
                throw new Error("Pass memory index to 'exportMemoryAs' if there is not exactly " + "one memory imported or declared.");
            }
            memory_index = 0;
        }
        this.exports.push({
            name: name,
            kind: kExternalMemory,
            index: memory_index
        });
    }
    addActiveElementSegment(table, offset, elements, type, is_shared = false) {
        checkExpr(offset);
        if (type != undefined) {
            for (let element of elements) checkExpr(element);
        }
        this.element_segments.push(new WasmElemSegment(table, offset, type, elements, false, is_shared));
        return this.element_segments.length - 1;
    }
    addPassiveElementSegment(elements, type, is_shared = false) {
        if (type != undefined) {
            for (let element of elements) checkExpr(element);
        }
        this.element_segments.push(new WasmElemSegment(undefined, undefined, type, elements, false, is_shared));
        return this.element_segments.length - 1;
    }
    addDeclarativeElementSegment(elements, type, is_shared = false) {
        if (type != undefined) {
            for (let element of elements) checkExpr(element);
        }
        this.element_segments.push(new WasmElemSegment(undefined, undefined, type, elements, true, is_shared));
        return this.element_segments.length - 1;
    }
    appendToTable(array) {
        for (let n of array) {
            if (typeof n != "number") throw new Error("invalid table (entries have to be numbers): " + array);
        }
        if (this.tables.length == 0) {
            this.addTable(kWasmAnyFunc, 0);
        }
        let table = this.tables[0];
        const base = table.initial_size;
        const table_size = base + array.length;
        table.initial_size = table_size;
        if (table.has_max && table_size > table.max_size) {
            table.max_size = table_size;
        }
        return this.addActiveElementSegment(0, wasmI32Const(base), array);
    }
    setTableBounds(min, max = undefined) {
        if (this.tables.length != 0) {
            throw new Error("The table bounds of table '0' have already been set.");
        }
        this.addTable(kWasmAnyFunc, min, max);
        return this;
    }
    startRecGroup() {
        this.rec_groups.push({
            start: this.types.length,
            size: 0
        });
    }
    endRecGroup() {
        if (this.rec_groups.length == 0) {
            throw new Error("Did not start a recursive group before ending one");
        }
        let last_element = this.rec_groups[this.rec_groups.length - 1];
        if (last_element.size != 0) {
            throw new Error("Did not start a recursive group before ending one");
        }
        last_element.size = this.types.length - last_element.start;
    }
    setName(name) {
        this.name = name;
        return this;
    }
    toBuffer(debug = false) {
        let binary = new Binary;
        let wasm = this;
        binary.emit_header();
        if (wasm.types.length > 0) {
            if (debug) print("emitting types @ " + binary.length);
            binary.emit_section(kTypeSectionCode, section => {
                let length_with_groups = wasm.types.length;
                for (let group of wasm.rec_groups) {
                    length_with_groups -= group.size - 1;
                }
                section.emit_u32v(length_with_groups);
                let rec_group_index = 0;
                for (let i = 0; i < wasm.types.length; i++) {
                    if (rec_group_index < wasm.rec_groups.length && wasm.rec_groups[rec_group_index].start == i) {
                        section.emit_u8(kWasmRecursiveTypeGroupForm);
                        section.emit_u32v(wasm.rec_groups[rec_group_index].size);
                        rec_group_index++;
                    }
                    let type = wasm.types[i];
                    if (type.supertype != kNoSuperType) {
                        section.emit_u8(type.is_final ? kWasmSubtypeFinalForm : kWasmSubtypeForm);
                        section.emit_u8(1);
                        section.emit_u32v(type.supertype);
                    } else if (!type.is_final) {
                        section.emit_u8(kWasmSubtypeForm);
                        section.emit_u8(0);
                    }
                    if (type.is_shared) section.emit_u8(kWasmSharedTypeForm);
                    if (type.describes !== undefined) {
                        section.emit_u8(kWasmDescribesTypeForm);
                        section.emit_u32v(type.describes);
                    }
                    if (type.descriptor !== undefined) {
                        section.emit_u8(kWasmDescriptorTypeForm);
                        section.emit_u32v(type.descriptor);
                    }
                    if (type instanceof WasmStruct) {
                        section.emit_u8(kWasmStructTypeForm);
                        section.emit_u32v(type.fields.length);
                        for (let field of type.fields) {
                            section.emit_type(field.type);
                            section.emit_u8(field.mutability ? 1 : 0);
                        }
                    } else if (type instanceof WasmArray) {
                        section.emit_u8(kWasmArrayTypeForm);
                        section.emit_type(type.type);
                        section.emit_u8(type.mutability ? 1 : 0);
                    } else {
                        section.emit_u8(kWasmFunctionTypeForm);
                        section.emit_u32v(type.params.length);
                        for (let param of type.params) {
                            section.emit_type(param);
                        }
                        section.emit_u32v(type.results.length);
                        for (let result of type.results) {
                            section.emit_type(result);
                        }
                    }
                }
            });
        }
        if (wasm.imports.length > 0) {
            if (debug) print("emitting imports @ " + binary.length);
            binary.emit_section(kImportSectionCode, section => {
                section.emit_u32v(wasm.imports.length);
                for (let imp of wasm.imports) {
                    section.emit_string(imp.module);
                    section.emit_string(imp.name || "");
                    section.emit_u8(imp.kind);
                    if (imp.kind == kExternalFunction) {
                        section.emit_u32v(imp.type_index);
                    } else if (imp.kind == kExternalGlobal) {
                        section.emit_type(imp.type);
                        let flags = (imp.mutable ? 1 : 0) | (imp.shared ? 2 : 0);
                        section.emit_u8(flags);
                    } else if (imp.kind == kExternalMemory) {
                        const has_max = imp.maximum !== undefined;
                        const is_shared = !!imp.shared;
                        const is_memory64 = !!imp.is_memory64;
                        let limits_byte = (is_memory64 ? 4 : 0) | (is_shared ? 2 : 0) | (has_max ? 1 : 0);
                        section.emit_u8(limits_byte);
                        let emit = val => is_memory64 ? section.emit_u64v(val) : section.emit_u32v(val);
                        emit(imp.initial);
                        if (has_max) emit(imp.maximum);
                    } else if (imp.kind == kExternalTable) {
                        section.emit_type(imp.type);
                        const has_max = typeof imp.maximum != "undefined";
                        const is_shared = !!imp.shared;
                        const is_table64 = !!imp.is_table64;
                        let limits_byte = (is_table64 ? 4 : 0) | (is_shared ? 2 : 0) | (has_max ? 1 : 0);
                        section.emit_u8(limits_byte);
                        section.emit_u32v(imp.initial);
                        if (has_max) section.emit_u32v(imp.maximum);
                    } else if (imp.kind == kExternalTag) {
                        section.emit_u32v(kExceptionAttribute);
                        section.emit_u32v(imp.type_index);
                    } else {
                        throw new Error("unknown/unsupported import kind " + imp.kind);
                    }
                }
            });
        }
        if (wasm.functions.length > 0) {
            if (debug) print("emitting function decls @ " + binary.length);
            binary.emit_section(kFunctionSectionCode, section => {
                section.emit_u32v(wasm.functions.length);
                for (let func of wasm.functions) {
                    section.emit_u32v(func.type_index);
                }
            });
        }
        if (wasm.tables.length > 0) {
            if (debug) print("emitting tables @ " + binary.length);
            binary.emit_section(kTableSectionCode, section => {
                section.emit_u32v(wasm.tables.length);
                for (let table of wasm.tables) {
                    if (table.has_init) {
                        section.emit_u8(64);
                        section.emit_u8(0);
                    }
                    section.emit_type(table.type);
                    let limits_byte = (table.is_table64 ? 4 : 0) | (table.is_shared ? 2 : 0) | (table.has_max ? 1 : 0);
                    section.emit_u8(limits_byte);
                    let emit = val => table.is_table64 ? section.emit_u64v(val) : section.emit_u32v(val);
                    emit(table.initial_size);
                    if (table.has_max) emit(table.max_size);
                    if (table.has_init) section.emit_init_expr(table.init_expr);
                }
            });
        }
        if (wasm.memories.length > 0) {
            if (debug) print("emitting memories @ " + binary.length);
            binary.emit_section(kMemorySectionCode, section => {
                section.emit_u32v(wasm.memories.length);
                for (let memory of wasm.memories) {
                    const has_max = memory.max !== undefined;
                    const is_shared = !!memory.shared;
                    const is_memory64 = !!memory.is_memory64;
                    let limits_byte = (is_memory64 ? 4 : 0) | (is_shared ? 2 : 0) | (has_max ? 1 : 0);
                    section.emit_u8(limits_byte);
                    let emit = val => is_memory64 ? section.emit_u64v(val) : section.emit_u32v(val);
                    emit(memory.min);
                    if (has_max) emit(memory.max);
                }
            });
        }
        if (wasm.tags.length > 0) {
            if (debug) print("emitting tags @ " + binary.length);
            binary.emit_section(kTagSectionCode, section => {
                section.emit_u32v(wasm.tags.length);
                for (let type_index of wasm.tags) {
                    section.emit_u32v(kExceptionAttribute);
                    section.emit_u32v(type_index);
                }
            });
        }
        if (wasm.stringrefs.length > 0) {
            if (debug) print("emitting stringrefs @ " + binary.length);
            binary.emit_section(kStringRefSectionCode, section => {
                section.emit_u32v(0);
                section.emit_u32v(wasm.stringrefs.length);
                for (let str of wasm.stringrefs) {
                    section.emit_string(str);
                }
            });
        }
        if (wasm.globals.length > 0) {
            if (debug) print("emitting globals @ " + binary.length);
            binary.emit_section(kGlobalSectionCode, section => {
                section.emit_u32v(wasm.globals.length);
                for (let global of wasm.globals) {
                    section.emit_type(global.type);
                    section.emit_u8((global.mutable ? 1 : 0) | (global.shared ? 2 : 0));
                    section.emit_init_expr(global.init);
                }
            });
        }
        var exports_count = wasm.exports.length;
        if (exports_count > 0) {
            if (debug) print("emitting exports @ " + binary.length);
            binary.emit_section(kExportSectionCode, section => {
                section.emit_u32v(exports_count);
                for (let exp of wasm.exports) {
                    section.emit_string(exp.name);
                    section.emit_u8(exp.kind);
                    section.emit_u32v(exp.index);
                }
            });
        }
        if (wasm.start_index !== undefined) {
            if (debug) print("emitting start function @ " + binary.length);
            binary.emit_section(kStartSectionCode, section => {
                section.emit_u32v(wasm.start_index);
            });
        }
        if (wasm.element_segments.length > 0) {
            if (debug) print("emitting element segments @ " + binary.length);
            binary.emit_section(kElementSectionCode, section => {
                var segments = wasm.element_segments;
                section.emit_u32v(segments.length);
                for (let segment of segments) {
                    let shared_flag = segment.is_shared ? 8 : 0;
                    if (segment.is_active()) {
                        if (segment.table == 0 && segment.type === undefined) {
                            if (segment.expressions_as_elements()) {
                                section.emit_u8(4 | shared_flag);
                                section.emit_init_expr(segment.offset);
                            } else {
                                section.emit_u8(0 | shared_flag);
                                section.emit_init_expr(segment.offset);
                            }
                        } else {
                            if (segment.expressions_as_elements()) {
                                section.emit_u8(6 | shared_flag);
                                section.emit_u32v(segment.table);
                                section.emit_init_expr(segment.offset);
                                section.emit_type(segment.type);
                            } else {
                                section.emit_u8(2 | shared_flag);
                                section.emit_u32v(segment.table);
                                section.emit_init_expr(segment.offset);
                                section.emit_u8(kExternalFunction);
                            }
                        }
                    } else {
                        if (segment.expressions_as_elements()) {
                            if (segment.is_passive()) {
                                section.emit_u8(5 | shared_flag);
                            } else {
                                section.emit_u8(7 | shared_flag);
                            }
                            section.emit_type(segment.type);
                        } else {
                            if (segment.is_passive()) {
                                section.emit_u8(1 | shared_flag);
                            } else {
                                section.emit_u8(3 | shared_flag);
                            }
                            section.emit_u8(kExternalFunction);
                        }
                    }
                    section.emit_u32v(segment.elements.length);
                    for (let element of segment.elements) {
                        if (segment.expressions_as_elements()) {
                            section.emit_init_expr(element);
                        } else {
                            section.emit_u32v(element);
                        }
                    }
                }
            });
        }
        if (wasm.data_segments.some(seg => !seg.is_active)) {
            binary.emit_section(kDataCountSectionCode, section => {
                section.emit_u32v(wasm.data_segments.length);
            });
        }
        if (wasm.compilation_hints.length > 0) {
            if (debug) print("emitting compilation hints @ " + binary.length);
            let payloadBinary = new Binary;
            let implicit_compilation_hints_count = wasm.functions.length;
            payloadBinary.emit_u32v(implicit_compilation_hints_count);
            let defaultHintByte = kCompilationHintStrategyDefault | kCompilationHintTierDefault << 2 | kCompilationHintTierDefault << 4;
            for (let i = 0; i < implicit_compilation_hints_count; i++) {
                let index = wasm.num_imported_funcs + i;
                var hintByte;
                if (index in wasm.compilation_hints) {
                    let hint = wasm.compilation_hints[index];
                    hintByte = hint.strategy | hint.baselineTier << 2 | hint.topTier << 4;
                } else {
                    hintByte = defaultHintByte;
                }
                payloadBinary.emit_u8(hintByte);
            }
            let name = "compilationHints";
            let bytes = this.createCustomSection(name, payloadBinary.trunc_buffer());
            binary.emit_bytes(bytes);
        }
        if (wasm.functions.length > 0) {
            if (debug) print("emitting code @ " + binary.length);
            let section_length = 0;
            binary.emit_section(kCodeSectionCode, section => {
                section.emit_u32v(wasm.functions.length);
                let header;
                for (let func of wasm.functions) {
                    if (func.locals.length == 0) {
                        section.emit_u32v(func.body.length + 1);
                        section.emit_u8(0);
                    } else {
                        if (!header) header = new Binary;
                        header.reset();
                        header.emit_u32v(func.locals.length);
                        for (let decl of func.locals) {
                            header.emit_u32v(decl.count);
                            header.emit_type(decl.type);
                        }
                        section.emit_u32v(header.length + func.body.length);
                        section.emit_bytes(header.trunc_buffer());
                    }
                    func.body_offset = section.length;
                    section.emit_bytes(func.body);
                }
                section_length = section.length;
            });
            for (let func of wasm.functions) {
                func.body_offset += binary.length - section_length;
            }
        }
        if (wasm.data_segments.length > 0) {
            if (debug) print("emitting data segments @ " + binary.length);
            binary.emit_section(kDataSectionCode, section => {
                section.emit_u32v(wasm.data_segments.length);
                for (let seg of wasm.data_segments) {
                    let shared_flag = seg.is_shared ? 8 : 0;
                    if (seg.is_active) {
                        if (seg.mem_index == 0) {
                            section.emit_u8(kActiveNoIndex | shared_flag);
                        } else {
                            section.emit_u8(kActiveWithIndex | shared_flag);
                            section.emit_u32v(seg.mem_index);
                        }
                        section.emit_init_expr(seg.offset);
                    } else {
                        section.emit_u8(kPassive | shared_flag);
                    }
                    section.emit_u32v(seg.data.length);
                    section.emit_bytes(seg.data);
                }
            });
        }
        for (let exp of wasm.explicit) {
            if (debug) print("emitting explicit @ " + binary.length);
            binary.emit_bytes(exp);
        }
        let num_function_names = 0;
        let num_functions_with_local_names = 0;
        for (let func of wasm.functions) {
            if (func.name !== undefined) ++num_function_names;
            if (func.numLocalNames() > 0) ++num_functions_with_local_names;
        }
        if (num_function_names > 0 || num_functions_with_local_names > 0 || wasm.name !== undefined) {
            if (debug) print("emitting names @ " + binary.length);
            binary.emit_section(kUnknownSectionCode, section => {
                section.emit_string("name");
                if (wasm.name !== undefined) {
                    section.emit_section(kModuleNameCode, name_section => {
                        name_section.emit_string(wasm.name);
                    });
                }
                if (num_function_names > 0) {
                    section.emit_section(kFunctionNamesCode, name_section => {
                        name_section.emit_u32v(num_function_names);
                        for (let func of wasm.functions) {
                            if (func.name === undefined) continue;
                            name_section.emit_u32v(func.index);
                            name_section.emit_string(func.name);
                        }
                    });
                }
                if (num_functions_with_local_names > 0) {
                    section.emit_section(kLocalNamesCode, name_section => {
                        name_section.emit_u32v(num_functions_with_local_names);
                        for (let func of wasm.functions) {
                            if (func.numLocalNames() == 0) continue;
                            name_section.emit_u32v(func.index);
                            name_section.emit_u32v(func.numLocalNames());
                            let name_index = 0;
                            for (let i = 0; i < func.local_names.length; ++i) {
                                if (typeof func.local_names[i] == "string") {
                                    name_section.emit_u32v(name_index);
                                    name_section.emit_string(func.local_names[i]);
                                    name_index++;
                                } else {
                                    name_index += func.local_names[i];
                                }
                            }
                        }
                    });
                }
            });
        }
        return binary.trunc_buffer();
    }
    toArray(debug = false) {
        return Array.from(this.toBuffer(debug));
    }
    instantiate(ffi, options) {
        let module = this.toModule(options);
        let instance = new WebAssembly.Instance(module, ffi);
        return instance;
    }
    asyncInstantiate(ffi) {
        return WebAssembly.instantiate(this.toBuffer(), ffi).then(({module: module, instance: instance}) => instance);
    }
    toModule(options, debug = false) {
        return new WebAssembly.Module(this.toBuffer(debug), options);
    }
}

function wasmSignedLeb(val, max_len = 5) {
    if (val == null) throw new Error("Leb value may not be null/undefined");
    let res = [];
    for (let i = 0; i < max_len; ++i) {
        let v = val & 127;
        if (v << 25 >> 25 == val) {
            res.push(v);
            return res;
        }
        res.push(v | 128);
        val = val >> 7;
    }
    throw new Error("Leb value <" + val + "> exceeds maximum length of " + max_len);
}

function wasmSignedLeb64(val, max_len = 10) {
    if (val == null) throw new Error("Leb value may not be null/undefined");
    if (typeof val != "bigint") {
        if (val < Math.pow(2, 31)) {
            return wasmSignedLeb(val, max_len);
        }
        val = BigInt(val);
    }
    let res = [];
    for (let i = 0; i < max_len; ++i) {
        let v = val & 0x7fn;
        if (BigInt.asIntN(7, v) == val) {
            res.push(Number(v));
            return res;
        }
        res.push(Number(v) | 128);
        val = val >> 7n;
    }
    throw new Error("Leb value <" + val + "> exceeds maximum length of " + max_len);
}

function wasmUnsignedLeb(val, max_len = 5) {
    if (val == null) throw new Error("Leb value many not be null/undefined");
    let res = [];
    for (let i = 0; i < max_len; ++i) {
        let v = val & 127;
        if (v == val) {
            res.push(v);
            return res;
        }
        res.push(v | 128);
        val = val >>> 7;
    }
    throw new Error("Leb value <" + val + "> exceeds maximum length of " + max_len);
}

function wasmI32Const(val) {
    return [ kExprI32Const, ...wasmSignedLeb(val, 5) ];
}

function wasmI64Const(val) {
    return [ kExprI64Const, ...wasmSignedLeb64(val, 10) ];
}

function wasmF32Const(f) {
    data_view.setFloat32(0, f, true);
    return [ kExprF32Const, byte_view[0], byte_view[1], byte_view[2], byte_view[3] ];
}

function wasmF64Const(f) {
    data_view.setFloat64(0, f, true);
    return [ kExprF64Const, byte_view[0], byte_view[1], byte_view[2], byte_view[3], byte_view[4], byte_view[5], byte_view[6], byte_view[7] ];
}

function wasmS128Const(f) {
    if (Array.isArray(f)) {
        if (f.length != 16) throw new Error("S128Const needs 16 bytes");
        return [ kSimdPrefix, kExprS128Const, ...f ];
    }
    let result = [ kSimdPrefix, kExprS128Const ];
    if (arguments.length === 2) {
        for (let j = 0; j < 2; j++) {
            data_view.setFloat64(0, arguments[j], true);
            for (let i = 0; i < 8; i++) result.push(byte_view[i]);
        }
    } else if (arguments.length === 4) {
        for (let j = 0; j < 4; j++) {
            data_view.setFloat32(0, arguments[j], true);
            for (let i = 0; i < 4; i++) result.push(byte_view[i]);
        }
    } else {
        throw new Error("S128Const needs an array of bytes, or two f64 values, " + "or four f32 values");
    }
    return result;
}

let wasmEncodeHeapType = function(type) {
    let result = wasmSignedLeb(type.heap_type, kMaxVarInt32Size);
    if (type.is_shared) {
        result = [ kWasmSharedTypeForm ].concat(result);
    }
    if (type.is_exact) {
        result = [ kWasmExact ].concat(result);
    }
    return result;
};

let [wasmBrOnCast, wasmBrOnCastFail, wasmBrOnCastDesc, wasmBrOnCastDescFail] = function() {
    return [ (labelIdx, sourceType, targetType) => wasmBrOnCastImpl(labelIdx, sourceType, targetType, kExprBrOnCast), (labelIdx, sourceType, targetType) => wasmBrOnCastImpl(labelIdx, sourceType, targetType, kExprBrOnCastFail), (labelIdx, sourceType, targetType) => wasmBrOnCastImpl(labelIdx, sourceType, targetType, kExprBrOnCastDesc), (labelIdx, sourceType, targetType) => wasmBrOnCastImpl(labelIdx, sourceType, targetType, kExprBrOnCastDescFail) ];
    function wasmBrOnCastImpl(labelIdx, sourceType, targetType, opcode) {
        labelIdx = wasmUnsignedLeb(labelIdx, kMaxVarInt32Size);
        let srcIsNullable = sourceType.opcode == kWasmRefNull;
        let tgtIsNullable = targetType.opcode == kWasmRefNull;
        flags = (tgtIsNullable << 1) + srcIsNullable;
        return [ kGCPrefix, opcode, flags, ...labelIdx, ...wasmEncodeHeapType(sourceType), ...wasmEncodeHeapType(targetType) ];
    }
}();

function getOpcodeName(opcode) {
    return globalThis.kWasmOpcodeNames?.[opcode] ?? "unknown";
}

function wasmF32ConstSignalingNaN() {
    return [ kExprF32Const, 185, 161, 167, 127 ];
}

function wasmF64ConstSignalingNaN() {
    return [ kExprF64Const, 0, 0, 0, 0, 0, 0, 244, 127 ];
}