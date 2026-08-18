#pragma once

#include <binobf/core/types.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace binobf {

struct TransformationRecord {
    TransformId transform;
    EntityId source;
    std::string passName;

    auto operator==(const TransformationRecord&) const -> bool = default;
};

struct TransformationLineage {
    std::vector<TransformationRecord> parents;

    auto operator==(const TransformationLineage&) const -> bool = default;
};

struct ObjectMetadata {
    std::uint8_t osAbi{0};
    std::uint8_t abiVersion{0};
    std::uint64_t formatFlags{0};
    std::uint32_t characteristics{0};
    bool coffBigObj{false};
    bool elfExtendedSectionCount{false};
    bool elfExtendedSectionNameIndex{false};

    auto operator==(const ObjectMetadata&) const -> bool = default;
};

enum class SectionKind : std::uint8_t {
    Code,
    InitializedData,
    UninitializedData,
    Debug,
    StringTable,
    SymbolTable,
    Relocation,
    Metadata,
    Unknown,
};

struct Section {
    EntityId id;
    std::uint32_t formatIndex{0};
    std::uint64_t formatType{0};
    std::uint64_t formatFlags{0};
    std::uint32_t formatLink{0};
    std::uint32_t formatInfo{0};
    std::uint64_t formatEntrySize{0};
    bool isSectionNameTable{false};
    std::string name;
    SectionKind kind{SectionKind::Unknown};
    BinaryAddress address;
    std::uint64_t logicalSize{0};
    std::uint64_t alignment{1};
    bool readable{false};
    bool writable{false};
    bool executable{false};
    std::vector<std::byte> contents;
    TransformationLineage lineage;

    auto operator==(const Section&) const -> bool = default;
};

enum class SectionAssociationKind : std::uint8_t {
    Ordinary,
    CoffComdat,
    CoffAssociativeComdat,
    ElfGroup,
};

enum class CoffComdatSelection : std::uint8_t {
    None,
    NoDuplicates,
    Any,
    SameSize,
    ExactMatch,
    Associative,
    Largest,
    Newest,
};

struct SectionAssociation {
    EntityId section;
    SectionAssociationKind kind{SectionAssociationKind::Ordinary};
    CoffComdatSelection coffSelection{CoffComdatSelection::None};
    std::optional<EntityId> signatureSymbol;
    std::optional<EntityId> parentSection;
    std::vector<EntityId> members;

    auto operator==(const SectionAssociation&) const -> bool = default;
};

struct Segment {
    EntityId id;
    std::string name;
    BinaryAddress address;
    std::uint64_t fileSize{0};
    std::uint64_t memorySize{0};
    bool readable{false};
    bool writable{false};
    bool executable{false};
    TransformationLineage lineage;

    auto operator==(const Segment&) const -> bool = default;
};

enum class SymbolVisibility : std::uint8_t {
    Local,
    Hidden,
    External,
    Unknown,
};

enum class SymbolKind : std::uint8_t {
    Function,
    Object,
    Section,
    File,
    Tls,
    Unknown,
};

enum class SymbolDefinitionKind : std::uint8_t {
    Undefined,
    SectionRelative,
    Absolute,
    Common,
};

enum class TlsModel : std::uint8_t {
    Unknown,
    None,
    GeneralDynamic,
    LocalDynamic,
    InitialExec,
    LocalExec,
    CoffStatic,
};

struct Symbol {
    EntityId id;
    std::uint32_t formatIndex{0};
    std::uint32_t formatTableIndex{0};
    std::uint32_t formatType{0};
    std::uint8_t formatStorage{0};
    std::uint8_t formatOther{0};
    std::int32_t formatSectionIndex{0};
    std::vector<std::byte> auxiliaryData;
    std::string name;
    std::optional<EntityId> section;
    BinaryAddress address;
    std::uint64_t size{0};
    SymbolKind kind{SymbolKind::Unknown};
    SymbolVisibility visibility{SymbolVisibility::Unknown};
    bool defined{false};
    std::optional<SymbolDefinitionKind> definition;
    std::uint64_t commonAlignment{0};
    TlsModel tlsModel{TlsModel::Unknown};
    TransformationLineage lineage;

    auto operator==(const Symbol&) const -> bool = default;
};

struct ExtendedSectionIndex {
    EntityId symbol;
    EntityId indexSection;
    EntityId section;
    std::uint32_t rawSectionIndex{0};

    auto operator==(const ExtendedSectionIndex&) const -> bool = default;
};

struct Import {
    EntityId id;
    std::string library;
    std::string name;
    std::optional<std::uint32_t> ordinal;
    TransformationLineage lineage;

    auto operator==(const Import&) const -> bool = default;
};

struct Export {
    EntityId id;
    std::string name;
    BinaryAddress address;
    std::optional<std::uint32_t> ordinal;
    TransformationLineage lineage;

    auto operator==(const Export&) const -> bool = default;
};

enum class RelocationKind : std::uint8_t {
    Absolute,
    PcRelative,
    ImageRelative,
    ArchitectureSpecific,
    Unknown,
};

struct Relocation {
    EntityId id;
    std::uint32_t formatIndex{0};
    std::uint32_t formatTableIndex{0};
    EntityId section;
    std::uint64_t offset{0};
    RelocationKind kind{RelocationKind::Unknown};
    std::uint64_t rawType{0};
    std::optional<EntityId> targetSymbol;
    std::int64_t addend{0};
    TransformationLineage lineage;

    auto operator==(const Relocation&) const -> bool = default;
};

struct RelocationTableEncoding {
    EntityId section;
    bool coffOverflow{false};
    std::uint64_t declaredCount{0};

    auto operator==(const RelocationTableEncoding&) const -> bool = default;
};

struct CoffSafeSehEntry {
    EntityId section;
    EntityId symbol;
    std::uint32_t formatIndex{0};

    auto operator==(const CoffSafeSehEntry&) const -> bool = default;
};

enum class InstructionKind : std::uint8_t {
    Normal,
    DirectBranch,
    ConditionalBranch,
    DirectCall,
    IndirectBranch,
    IndirectCall,
    Return,
    Trap,
    Opaque,
};

struct RegisterAccess {
    std::uint32_t id{0};
    std::string name;

    auto operator==(const RegisterAccess&) const -> bool = default;
};

enum class InstructionReferenceKind : std::uint8_t {
    BranchTarget,
    CallTarget,
    Data,
    Relocation,
};

struct InstructionReference {
    InstructionReferenceKind kind{InstructionReferenceKind::Data};
    std::optional<BinaryAddress> address;
    std::optional<EntityId> relocation;
    std::optional<EntityId> symbol;

    auto operator==(const InstructionReference&) const -> bool = default;
};

struct Instruction {
    EntityId id;
    EntityId section;
    std::uint64_t sectionOffset{0};
    BinaryAddress address;
    std::vector<std::byte> encoding;
    std::string mnemonic;
    std::string operands;
    InstructionKind kind{InstructionKind::Opaque};
    std::optional<BinaryAddress> directTarget;
    bool hasFallthrough{false};
    std::vector<RegisterAccess> registersRead;
    std::vector<RegisterAccess> registersWritten;
    std::vector<InstructionReference> references;
    TransformationLineage lineage;

    auto operator==(const Instruction&) const -> bool = default;
};

enum class ControlFlowEdgeKind : std::uint8_t {
    Fallthrough,
    BranchTaken,
    DirectBranch,
    DirectCall,
    UnresolvedIndirect,
};

struct ControlFlowEdge {
    ControlFlowEdgeKind kind{ControlFlowEdgeKind::Fallthrough};
    std::optional<EntityId> targetBlock;
    std::optional<BinaryAddress> targetAddress;

    auto operator==(const ControlFlowEdge&) const -> bool = default;
};

struct BasicBlock {
    EntityId id;
    EntityId function;
    EntityId section;
    std::uint64_t sectionOffset{0};
    BinaryAddress address;
    std::vector<EntityId> instructions;
    std::vector<EntityId> successors;
    std::vector<ControlFlowEdge> edges;
    std::vector<RegisterAccess> liveIn;
    std::vector<RegisterAccess> liveOut;
    bool hasUnresolvedSuccessor{false};
    TransformationLineage lineage;

    auto operator==(const BasicBlock&) const -> bool = default;
};

enum class FunctionDiscovery : std::uint8_t {
    Symbol,
    EntryPoint,
    Relocation,
    Export,
    Unwind,
};

struct Function {
    EntityId id;
    std::string name;
    EntityId section;
    std::optional<EntityId> symbol;
    BinaryAddress address;
    std::uint64_t size{0};
    FunctionDiscovery discovery{FunctionDiscovery::Symbol};
    std::vector<EntityId> instructions;
    std::vector<EntityId> basicBlocks;
    std::optional<EntityId> entryBlock;
    bool externallyVisible{false};
    bool complete{false};
    TransformationLineage lineage;

    auto operator==(const Function&) const -> bool = default;
};

struct DataObject {
    EntityId id;
    std::string name;
    BinaryAddress address;
    std::vector<std::byte> bytes;
    TransformationLineage lineage;

    auto operator==(const DataObject&) const -> bool = default;
};

enum class UnwindFormat : std::uint8_t {
    Unknown,
    WindowsI386,
    DwarfCfi32,
    WindowsARM64,
    DwarfCfi64,
};

enum class UnwindRewriteState : std::uint8_t {
    Unchanged,
    Adjusted,
    Regenerated,
    Opaque,
};

struct UnwindInfo {
    EntityId id;
    EntityId function;
    std::vector<std::byte> encoded;
    EntityId section;
    std::uint64_t sectionOffset{0};
    std::uint64_t codeOffset{0};
    std::uint64_t codeSize{0};
    UnwindFormat format{UnwindFormat::Unknown};
    std::vector<EntityId> relocations;
    UnwindRewriteState rewriteState{UnwindRewriteState::Opaque};
    TransformationLineage lineage;

    auto operator==(const UnwindInfo&) const -> bool = default;
};

struct DebugInfo {
    EntityId id;
    std::string format;
    std::optional<SourceLocation> source;
    TransformationLineage lineage;

    auto operator==(const DebugInfo&) const -> bool = default;
};

struct Resource {
    EntityId id;
    std::string type;
    std::string name;
    std::vector<std::byte> bytes;
    TransformationLineage lineage;

    auto operator==(const Resource&) const -> bool = default;
};

struct BinaryImage {
    BinaryFormat format{BinaryFormat::Unknown};
    BinaryType type{BinaryType::Unknown};
    Architecture architecture{Architecture::Unknown};
    ObjectMetadata objectMetadata;
    std::optional<BinaryAddress> entryPoint;
    std::vector<Section> sections;
    std::vector<SectionAssociation> sectionAssociations;
    std::vector<Segment> segments;
    std::vector<Symbol> symbols;
    std::vector<ExtendedSectionIndex> extendedSectionIndices;
    std::vector<Import> imports;
    std::vector<Export> exports;
    std::vector<Relocation> relocations;
    std::vector<RelocationTableEncoding> relocationTableEncodings;
    std::vector<CoffSafeSehEntry> coffSafeSehEntries;
    std::vector<Instruction> instructions;
    std::vector<BasicBlock> basicBlocks;
    std::vector<Function> functions;
    std::vector<DataObject> dataObjects;
    std::vector<UnwindInfo> unwindInfo;
    std::vector<DebugInfo> debugInfo;
    std::vector<Resource> resources;

    auto operator==(const BinaryImage&) const -> bool = default;
};

} // namespace binobf
