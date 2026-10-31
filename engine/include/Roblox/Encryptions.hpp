// Vesper -- Luau field obfuscation layer.
//
// Roblox stores a subset of Luau object fields in a transformed form. Which
// transform applies to which field is build data, not code. This header maps a
// *stable field identity* to the *runtime-selected transform*, so the same
// compiled VM adapts to any build whose transform map is present in the offset
// table.
//
// Scheme ids match the offset table's `enc.*` entries:
//   0 plain          Storage
//   1 subtract-self  Storage - this
//   2 self-subtract  this - Storage
//   3 xor-self       this ^ Storage
//   4 add-self       this + Storage
#pragma once

#include <cstdint>

namespace vesper::abi {

enum EncScheme : std::uint8_t {
    kEncPlain = 0,
    kEncSubSelf = 1,
    kEncSelfSub = 2,
    kEncXorSelf = 3,
    kEncAddSelf = 4,
};

enum EncField : int {
    kEncNone = 0,
    kEncProtoLineInfo = 1,
    kEncProtoAbsLineInfo = 2,
    kEncProtoLocVars = 3,
    kEncProtoUpvalues = 4,
    kEncProtoSource = 5,
    kEncProtoDebugInsn = 6,
    kEncProtoDebugName = 7,
    kEncProtoTypeInfo = 8,
    kEncProtoUserdata = 9,
    kEncLStateStackSize = 10,
    kEncClosureCont = 11,
    kEncClosureDebugName = 12,
    kEncUdataMeta = 13,
    kEncTStringHash = 14,
    kEncFieldCount = 15,
};

// Populated from the offset table during `bind()`. Defaults are the values the
// public executor scene has observed on recent builds; every one of them can be
// overridden per build and the engine verifies the ones it can probe.
inline std::uint8_t g_scheme[kEncFieldCount] = {
    kEncPlain,
    kEncSelfSub,   // proto.line_info
    kEncXorSelf,   // proto.abs_line_info
    kEncAddSelf,   // proto.loc_vars
    kEncXorSelf,   // proto.upvalues
    kEncAddSelf,   // proto.source
    kEncSelfSub,   // proto.debug_insn
    kEncSubSelf,   // proto.debug_name
    kEncSelfSub,   // proto.type_info
    kEncXorSelf,   // proto.userdata
    kEncSelfSub,   // lstate.stack_size
    kEncXorSelf,   // closure.cont
    kEncAddSelf,   // closure.debug_name
    kEncXorSelf,   // userdata.meta
    kEncXorSelf,   // tstring.hash
};

inline std::uint8_t scheme(int field) {
    if (field <= 0 || field >= kEncFieldCount) return kEncPlain;
    return g_scheme[field];
}

inline void set_scheme(int field, std::uint8_t value) {
    if (field <= 0 || field >= kEncFieldCount) return;
    if (value > kEncAddSelf) return;
    g_scheme[field] = value;
}

}  // namespace vesper::abi

// Fixed-form templates, kept for tooling and for code that needs the exact
// transform spelled out rather than looked up.
template <typename T>
struct VMValue0 {
    T Storage;
    operator T() const { return Storage; }
    void operator=(const T& v) { Storage = v; }
    T Get() const { return Storage; }
    void Set(const T& v) { Storage = v; }
};

template <typename T>
struct VMValue1 {
    T Storage;
    operator T() const { return (T)((std::uintptr_t)Storage - (std::uintptr_t)this); }
    void operator=(const T& v) { Storage = (T)((std::uintptr_t)v + (std::uintptr_t)this); }
    T Get() const { return operator T(); }
    void Set(const T& v) { operator=(v); }
};

template <typename T>
struct VMValue2 {
    T Storage;
    operator T() const { return (T)((std::uintptr_t)this - (std::uintptr_t)Storage); }
    void operator=(const T& v) { Storage = (T)((std::uintptr_t)this - (std::uintptr_t)v); }
    T Get() const { return operator T(); }
    void Set(const T& v) { operator=(v); }
};

template <typename T>
struct VMValue3 {
    T Storage;
    operator T() const { return (T)((std::uintptr_t)this ^ (std::uintptr_t)Storage); }
    void operator=(const T& v) { Storage = (T)((std::uintptr_t)v ^ (std::uintptr_t)this); }
    T Get() const { return operator T(); }
    void Set(const T& v) { operator=(v); }
};

template <typename T>
struct VMValue4 {
    T Storage;
    operator T() const { return (T)((std::uintptr_t)this + (std::uintptr_t)Storage); }
    void operator=(const T& v) { Storage = (T)((std::uintptr_t)v - (std::uintptr_t)this); }
    T Get() const { return operator T(); }
    void Set(const T& v) { operator=(v); }
};

// Runtime-scheme field. Layout is exactly `sizeof(T)` so struct offsets are
// unaffected by which transform a build happens to use.
template <typename T, int Field>
struct EncField {
    T Storage;

    operator T() const {
        const std::uintptr_t self = (std::uintptr_t)this;
        const std::uintptr_t raw = (std::uintptr_t)Storage;
        switch (vesper::abi::scheme(Field)) {
            case vesper::abi::kEncSubSelf: return (T)(raw - self);
            case vesper::abi::kEncSelfSub: return (T)(self - raw);
            case vesper::abi::kEncXorSelf: return (T)(self ^ raw);
            case vesper::abi::kEncAddSelf: return (T)(self + raw);
            default: return (T)raw;
        }
    }

    void operator=(const T& value) {
        const std::uintptr_t self = (std::uintptr_t)this;
        const std::uintptr_t raw = (std::uintptr_t)value;
        switch (vesper::abi::scheme(Field)) {
            case vesper::abi::kEncSubSelf: Storage = (T)(raw + self); break;
            case vesper::abi::kEncSelfSub: Storage = (T)(self - raw); break;
            case vesper::abi::kEncXorSelf: Storage = (T)(raw ^ self); break;
            case vesper::abi::kEncAddSelf: Storage = (T)(raw - self); break;
            default: Storage = (T)raw; break;
        }
    }

    const T operator->() const { return operator T(); }
    T Get() const { return operator T(); }
    void Set(const T& value) { operator=(value); }
};

// Alias templates, not derived classes: a derived class would declare an
// implicit copy-assignment operator that hides EncField::operator=.
#define VESPER_ENC_FIELD(alias, field) \
    template <typename T> using alias = EncField<T, field>

VESPER_ENC_FIELD(enc_proto_line_info, vesper::abi::kEncProtoLineInfo);
VESPER_ENC_FIELD(enc_proto_abs_line_info, vesper::abi::kEncProtoAbsLineInfo);
VESPER_ENC_FIELD(enc_proto_loc_vars, vesper::abi::kEncProtoLocVars);
VESPER_ENC_FIELD(enc_proto_upvalues, vesper::abi::kEncProtoUpvalues);
VESPER_ENC_FIELD(enc_proto_source, vesper::abi::kEncProtoSource);
VESPER_ENC_FIELD(enc_proto_debug_insn, vesper::abi::kEncProtoDebugInsn);
VESPER_ENC_FIELD(enc_proto_debug_name, vesper::abi::kEncProtoDebugName);
VESPER_ENC_FIELD(enc_proto_type_info, vesper::abi::kEncProtoTypeInfo);
VESPER_ENC_FIELD(enc_proto_userdata, vesper::abi::kEncProtoUserdata);
VESPER_ENC_FIELD(enc_lstate_stack_size, vesper::abi::kEncLStateStackSize);
VESPER_ENC_FIELD(enc_closure_cont, vesper::abi::kEncClosureCont);
VESPER_ENC_FIELD(enc_closure_debug_name, vesper::abi::kEncClosureDebugName);
VESPER_ENC_FIELD(enc_udata_meta, vesper::abi::kEncUdataMeta);
VESPER_ENC_FIELD(enc_tstring_hash, vesper::abi::kEncTStringHash);

#undef VESPER_ENC_FIELD

#define PROTO_LINEINFO_ENC enc_proto_line_info
#define PROTO_ABSLINEINFO_ENC enc_proto_abs_line_info
#define PROTO_LOCVARS_ENC enc_proto_loc_vars
#define PROTO_UPVALUES_ENC enc_proto_upvalues
#define PROTO_SOURCE_ENC enc_proto_source
#define PROTO_DEBUGINSN_ENC enc_proto_debug_insn
#define PROTO_DEBUGNAME_ENC enc_proto_debug_name
#define PROTO_TYPEINFO_ENC enc_proto_type_info
#define PROTO_USERDATA_ENC enc_proto_userdata
#define LSTATE_STACKSIZE_ENC enc_lstate_stack_size
#define CLOSURE_CONT_ENC enc_closure_cont
#define CLOSURE_DEBUGNAME_ENC enc_closure_debug_name
#define UDATA_META_ENC enc_udata_meta
#define TSTRING_HASH_ENC enc_tstring_hash
