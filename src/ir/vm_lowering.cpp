#include <binobf/ir/vm_lowering.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace binobf::ir {
namespace {

auto failure(std::string code, std::string message) -> Result<VmLoweringReport, Diagnostic> {
    return Result<VmLoweringReport, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error, std::move(code), std::move(message)});
}

auto compatibility_failure(std::string_view node, EntityId source)
    -> Result<std::size_t, Diagnostic> {
    return Result<std::size_t, Diagnostic>::failure(Diagnostic{
        DiagnosticSeverity::Error,
        "vm.unsupported_native_ir",
        "VM lowering does not support " + std::string{node} +
            " at source instruction " + std::to_string(source.value()),
    });
}

auto instruction_source(const IrInstruction& instruction) -> EntityId {
    return std::visit(
        [](const auto& item) { return item.sourceInstruction; }, instruction);
}

auto instruction_name(const IrInstruction& instruction) -> std::string_view {
    return std::visit([](const auto& item) -> std::string_view {
        using T = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<T, IrMove>) return "IrMove";
        else if constexpr (std::is_same_v<T, IrBinaryOperation>) return "IrBinaryOperation";
        else if constexpr (std::is_same_v<T, IrUnaryOperation>) return "IrUnaryOperation";
        else if constexpr (std::is_same_v<T, IrCompare>) return "IrCompare";
        else if constexpr (std::is_same_v<T, IrTest>) return "IrTest";
        else if constexpr (std::is_same_v<T, IrJump>) return "IrJump";
        else if constexpr (std::is_same_v<T, IrConditionalJump>) return "IrConditionalJump";
        else if constexpr (std::is_same_v<T, IrSwitch>) return "IrSwitch";
        else if constexpr (std::is_same_v<T, IrIndirectJump>) return "IrIndirectJump";
        else if constexpr (std::is_same_v<T, IrInternalCall>) return "IrInternalCall";
        else if constexpr (std::is_same_v<T, IrExternalCall>) return "IrExternalCall";
        else if constexpr (std::is_same_v<T, IrTailCall>) return "IrTailCall";
        else if constexpr (std::is_same_v<T, IrLoad>) return "IrLoad";
        else if constexpr (std::is_same_v<T, IrStore>) return "IrStore";
        else if constexpr (std::is_same_v<T, IrAddressOf>) return "IrAddressOf";
        else if constexpr (std::is_same_v<T, IrPointerOffset>) return "IrPointerOffset";
        else if constexpr (std::is_same_v<T, IrCast>) return "IrCast";
        else if constexpr (std::is_same_v<T, IrReturn>) return "IrReturn";
        else return "IrFallback";
    }, instruction);
}

auto instruction_vm_compatible(const IrInstruction& instruction, bool moduleLowering)
    -> bool {
    return std::visit([moduleLowering](const auto& item) {
        using T = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<T, IrMove> ||
                      std::is_same_v<T, IrBinaryOperation> ||
                      std::is_same_v<T, IrUnaryOperation> ||
                      std::is_same_v<T, IrCompare> ||
                      std::is_same_v<T, IrTest> ||
                      std::is_same_v<T, IrReturn>) {
            return integer_width(item.type).has_value();
        } else if constexpr (std::is_same_v<T, IrJump> ||
                             std::is_same_v<T, IrConditionalJump>) {
            return true;
        } else if constexpr (std::is_same_v<T, IrInternalCall>) {
            return moduleLowering && integer_width(item.resultType).has_value();
        } else {
            return false;
        }
    }, instruction);
}

auto validate_vm_compatibility(const IrFunction& function, bool moduleLowering)
    -> Result<std::size_t, Diagnostic> {
    if (!function.unwindRegions.empty()) {
        return compatibility_failure("IrUnwindRegion", function.sourceFunction);
    }
    for (const auto& block : function.blocks) {
        for (const auto& instruction : block.instructions) {
            if (!instruction_vm_compatible(instruction, moduleLowering)) {
                if (!moduleLowering && std::holds_alternative<IrInternalCall>(instruction)) {
                    return Result<std::size_t, Diagnostic>::failure(Diagnostic{
                        DiagnosticSeverity::Error,
                        "ir.internal_call_requires_module",
                        "IR internal calls require module VM lowering",
                    });
                }
                return compatibility_failure(
                    instruction_name(instruction), instruction_source(instruction));
            }
        }
    }
    return Result<std::size_t, Diagnostic>::success(0U);
}

auto vm_width(const IrType& type) -> vm::VmWidth {
    switch (type.bits) {
    case 8U: return vm::VmWidth::U8;
    case 16U: return vm::VmWidth::U16;
    case 32U: return vm::VmWidth::U32;
    case 64U: return vm::VmWidth::U64;
    default: break;
    }
    return vm::VmWidth::U64;
}

auto vm_binary(IrBinaryOpcode opcode) -> vm::VmBinaryOpcode {
    switch (opcode) {
    case IrBinaryOpcode::Add: return vm::VmBinaryOpcode::Add;
    case IrBinaryOpcode::Subtract: return vm::VmBinaryOpcode::Subtract;
    case IrBinaryOpcode::Multiply: return vm::VmBinaryOpcode::Multiply;
    case IrBinaryOpcode::Divide: return vm::VmBinaryOpcode::Divide;
    case IrBinaryOpcode::And: return vm::VmBinaryOpcode::And;
    case IrBinaryOpcode::Or: return vm::VmBinaryOpcode::Or;
    case IrBinaryOpcode::Xor: return vm::VmBinaryOpcode::Xor;
    case IrBinaryOpcode::ShiftLeft: return vm::VmBinaryOpcode::ShiftLeft;
    case IrBinaryOpcode::ShiftRight: return vm::VmBinaryOpcode::ShiftRight;
    }
    return vm::VmBinaryOpcode::Add;
}

auto vm_condition(IrCondition condition) -> vm::VmCondition {
    switch (condition) {
    case IrCondition::Equal: return vm::VmCondition::Equal;
    case IrCondition::NotEqual: return vm::VmCondition::NotEqual;
    case IrCondition::UnsignedBelow: return vm::VmCondition::UnsignedBelow;
    case IrCondition::UnsignedAboveOrEqual: return vm::VmCondition::UnsignedAboveOrEqual;
    case IrCondition::SignedLess: return vm::VmCondition::SignedLess;
    case IrCondition::SignedGreaterOrEqual: return vm::VmCondition::SignedGreaterOrEqual;
    case IrCondition::Zero: return vm::VmCondition::Zero;
    case IrCondition::Nonzero: return vm::VmCondition::Nonzero;
    }
    return vm::VmCondition::Equal;
}

struct Patch {
    std::size_t instruction{0};
    IrBlockId target;
};

class LoweringBuilder final {
public:
    explicit LoweringBuilder(const IrFunction& function)
        : function_(function), nextRegister_(function.variableTypes.size()) {
        report_.program.version = vm::currentVmVersion;
        report_.program.localMemorySize = 0;
    }

    auto build() -> Result<VmLoweringReport, Diagnostic> {
        std::vector<const IrArgumentBinding*> arguments;
        arguments.reserve(function_.arguments.size());
        for (const auto& argument : function_.arguments) arguments.push_back(&argument);
        std::sort(arguments.begin(), arguments.end(), [](const auto* left, const auto* right) {
            return left->argumentIndex < right->argumentIndex;
        });
        for (const auto* argument : arguments) {
            emit(vm::VmLoadSlot{
                vm_width(argument->type),
                vm::VmRegister{argument->destination.index},
                vm::VmSlot{argument->argumentIndex},
            }, function_.sourceFunction);
        }
        report_.program.slotCount = static_cast<std::uint16_t>(arguments.size());
        emit(vm::VmJump{0}, function_.sourceFunction);
        patches_.push_back(Patch{report_.program.instructions.size() - 1, function_.entry});

        for (const auto& block : function_.blocks) {
            if (report_.program.instructions.size() > std::numeric_limits<std::uint32_t>::max()) {
                return failure("ir.vm_instruction_overflow", "lowered VM instruction index overflowed");
            }
            blockStarts_.emplace(
                block.id.value, static_cast<std::uint32_t>(report_.program.instructions.size()));
            for (const auto& instruction : block.instructions) {
                const auto lowered = lower_instruction(instruction);
                if (!lowered.has_value()) return lowered;
            }
        }
        for (const auto& patch : patches_) {
            const auto target = blockStarts_.find(patch.target.value);
            if (target == blockStarts_.end()) {
                return failure("ir.branch_target_missing", "lowered branch target does not exist");
            }
            if (auto* jump = std::get_if<vm::VmJump>(
                    &report_.program.instructions[patch.instruction])) {
                jump->target = target->second;
            } else if (auto* branch = std::get_if<vm::VmConditionalJump>(
                           &report_.program.instructions[patch.instruction])) {
                branch->target = target->second;
            } else {
                return failure("ir.lowering_contract_violation", "branch patch is not a VM branch");
            }
        }
        if (nextRegister_ > std::numeric_limits<std::uint16_t>::max()) {
            return failure("ir.vm_register_overflow", "lowered VM register count overflowed");
        }
        report_.program.registerCount = static_cast<std::uint16_t>(nextRegister_);
        return Result<VmLoweringReport, Diagnostic>::success(std::move(report_));
    }

private:
    void emit(vm::VmInstruction instruction, EntityId source) {
        const auto index = static_cast<std::uint32_t>(report_.program.instructions.size());
        report_.program.instructions.push_back(std::move(instruction));
        report_.lineage.push_back(VmLoweringLineage{index, source});
    }

    auto temporary(const IrType& type, std::uint64_t bits, EntityId source)
        -> Result<vm::VmRegister, Diagnostic> {
        if (nextRegister_ >= std::numeric_limits<std::uint16_t>::max()) {
            return Result<vm::VmRegister, Diagnostic>::failure(Diagnostic{
                DiagnosticSeverity::Error,
                "ir.vm_register_overflow",
                "lowered VM register count overflowed"});
        }
        const auto result = vm::VmRegister{static_cast<std::uint16_t>(nextRegister_++)};
        emit(vm::VmLoadConstant{
            result, vm::VmValue::from_bits(vm_width(type), bits)}, source);
        return Result<vm::VmRegister, Diagnostic>::success(result);
    }

    auto operand_register(const IrOperand& operand, EntityId source)
        -> Result<vm::VmRegister, Diagnostic> {
        if (const auto* variable = std::get_if<IrVariableOperand>(&operand)) {
            return Result<vm::VmRegister, Diagnostic>::success(
                vm::VmRegister{variable->variable.index});
        }
        const auto& immediate = std::get<IrImmediateOperand>(operand);
        return temporary(immediate.type, immediate.bits, source);
    }

    auto lower_instruction(const IrInstruction& instruction)
        -> Result<VmLoweringReport, Diagnostic> {
        if (const auto* move = std::get_if<IrMove>(&instruction)) {
            if (const auto* variable = std::get_if<IrVariableOperand>(&move->source)) {
                emit(vm::VmMove{
                    vm_width(move->type),
                    vm::VmRegister{move->destination.index},
                    vm::VmRegister{variable->variable.index},
                }, move->sourceInstruction);
            } else {
                const auto& immediate = std::get<IrImmediateOperand>(move->source);
                emit(vm::VmLoadConstant{
                    vm::VmRegister{move->destination.index},
                    vm::VmValue::from_bits(vm_width(immediate.type), immediate.bits),
                }, move->sourceInstruction);
            }
        } else if (const auto* binary = std::get_if<IrBinaryOperation>(&instruction)) {
            auto right = operand_register(binary->source, binary->sourceInstruction);
            if (!right.has_value()) {
                return Result<VmLoweringReport, Diagnostic>::failure(right.error());
            }
            emit(vm::VmBinaryOperation{
                vm_binary(binary->opcode),
                vm_width(binary->type),
                vm::VmRegister{binary->destination.index},
                vm::VmRegister{binary->destination.index},
                right.value(),
            }, binary->sourceInstruction);
        } else if (const auto* unary = std::get_if<IrUnaryOperation>(&instruction)) {
            emit(vm::VmUnaryOperation{
                vm::VmUnaryOpcode::Not,
                vm_width(unary->type),
                vm::VmRegister{unary->destination.index},
                vm::VmRegister{unary->destination.index},
            }, unary->sourceInstruction);
        } else if (const auto* compare = std::get_if<IrCompare>(&instruction)) {
            auto right = operand_register(compare->right, compare->sourceInstruction);
            if (!right.has_value()) {
                return Result<VmLoweringReport, Diagnostic>::failure(right.error());
            }
            emit(vm::VmCompare{
                vm_width(compare->type), vm::VmRegister{compare->left.index}, right.value()},
                compare->sourceInstruction);
        } else if (const auto* test = std::get_if<IrTest>(&instruction)) {
            auto right = operand_register(test->right, test->sourceInstruction);
            if (!right.has_value()) {
                return Result<VmLoweringReport, Diagnostic>::failure(right.error());
            }
            emit(vm::VmTest{
                vm_width(test->type), vm::VmRegister{test->left.index}, right.value()},
                test->sourceInstruction);
        } else if (const auto* jump = std::get_if<IrJump>(&instruction)) {
            emit(vm::VmJump{0}, jump->sourceInstruction);
            patches_.push_back(Patch{report_.program.instructions.size() - 1, jump->target});
        } else if (const auto* branch = std::get_if<IrConditionalJump>(&instruction)) {
            emit(vm::VmConditionalJump{vm_condition(branch->condition), 0},
                branch->sourceInstruction);
            patches_.push_back(Patch{
                report_.program.instructions.size() - 1, branch->trueTarget});
            emit(vm::VmJump{0}, branch->sourceInstruction);
            patches_.push_back(Patch{
                report_.program.instructions.size() - 1, branch->falseTarget});
        } else if (const auto* returned = std::get_if<IrReturn>(&instruction)) {
            if (!returned->value.has_value()) {
                return failure(
                    "vm.unsupported_native_ir",
                    "VM lowering does not support a void IR return");
            }
            emit(vm::VmReturn{vm::VmRegister{returned->value->index}},
                returned->sourceInstruction);
        } else if (std::holds_alternative<IrInternalCall>(instruction)) {
            return failure(
                "ir.internal_call_requires_module",
                "IR internal calls require module VM lowering");
        } else {
            const auto unsupported = compatibility_failure(
                instruction_name(instruction), instruction_source(instruction));
            return Result<VmLoweringReport, Diagnostic>::failure(unsupported.error());
        }
        return Result<VmLoweringReport, Diagnostic>::success(VmLoweringReport{});
    }

    const IrFunction& function_;
    VmLoweringReport report_;
    std::size_t nextRegister_{0};
    std::map<std::uint32_t, std::uint32_t> blockStarts_;
    std::vector<Patch> patches_;
};

struct ModuleBlockKey {
    std::uint64_t function{0};
    std::uint32_t block{0};
    auto operator<=>(const ModuleBlockKey&) const = default;
};

struct ModuleBranchPatch {
    std::size_t instruction{0};
    ModuleBlockKey target;
};

struct ModuleCallPatch {
    std::size_t instruction{0};
    EntityId target;
};

class ModuleLoweringBuilder final {
public:
    explicit ModuleLoweringBuilder(const IrModule& module) : module_(module) {
        report_.program.version = vm::currentVmVersion;
        report_.program.localMemorySize = 0;
    }

    auto build() -> Result<VmLoweringReport, Diagnostic> {
        std::vector<const IrFunction*> order;
        order.reserve(module_.functions.size());
        const auto entry = std::find_if(module_.functions.begin(), module_.functions.end(),
            [&](const auto& function) { return function.sourceFunction == module_.entryFunction; });
        if (entry == module_.functions.end()) {
            return failure("ir.module_entry_missing", "IR module entry function does not exist");
        }
        order.push_back(&*entry);
        for (const auto& function : module_.functions) {
            if (function.sourceFunction != module_.entryFunction) order.push_back(&function);
        }

        std::size_t maximumRegisters = 0;
        std::size_t maximumSlots = 0;
        for (const auto* function : order) {
            if (report_.program.instructions.size() > std::numeric_limits<std::uint32_t>::max()) {
                return failure("ir.vm_instruction_overflow", "lowered VM instruction index overflowed");
            }
            functionStarts_.emplace(
                function->sourceFunction.value(),
                static_cast<std::uint32_t>(report_.program.instructions.size()));
            nextRegister_ = function->variableTypes.size();
            maximumSlots = std::max(maximumSlots, function->arguments.size());

            std::vector<const IrArgumentBinding*> arguments;
            arguments.reserve(function->arguments.size());
            for (const auto& argument : function->arguments) arguments.push_back(&argument);
            std::sort(arguments.begin(), arguments.end(), [](const auto* left, const auto* right) {
                return left->argumentIndex < right->argumentIndex;
            });
            for (const auto* argument : arguments) {
                emit(vm::VmLoadSlot{
                    vm_width(argument->type),
                    vm::VmRegister{argument->destination.index},
                    vm::VmSlot{argument->argumentIndex},
                }, function->sourceFunction);
            }
            emit(vm::VmJump{0}, function->sourceFunction);
            branchPatches_.push_back(ModuleBranchPatch{
                report_.program.instructions.size() - 1,
                ModuleBlockKey{function->sourceFunction.value(), function->entry.value},
            });

            for (const auto& block : function->blocks) {
                if (report_.program.instructions.size() > std::numeric_limits<std::uint32_t>::max()) {
                    return failure(
                        "ir.vm_instruction_overflow", "lowered VM instruction index overflowed");
                }
                blockStarts_.emplace(
                    ModuleBlockKey{function->sourceFunction.value(), block.id.value},
                    static_cast<std::uint32_t>(report_.program.instructions.size()));
                for (const auto& instruction : block.instructions) {
                    const auto lowered = lower_instruction(*function, instruction);
                    if (!lowered.has_value()) {
                        return Result<VmLoweringReport, Diagnostic>::failure(lowered.error());
                    }
                }
            }
            maximumRegisters = std::max(maximumRegisters, nextRegister_);
        }

        for (const auto& patch : branchPatches_) {
            const auto target = blockStarts_.find(patch.target);
            if (target == blockStarts_.end()) {
                return failure("ir.branch_target_missing", "lowered module branch target is missing");
            }
            if (auto* jump = std::get_if<vm::VmJump>(
                    &report_.program.instructions[patch.instruction])) {
                jump->target = target->second;
            } else if (auto* branch = std::get_if<vm::VmConditionalJump>(
                           &report_.program.instructions[patch.instruction])) {
                branch->target = target->second;
            } else {
                return failure(
                    "ir.lowering_contract_violation", "module branch patch is not a branch");
            }
        }
        for (const auto& patch : callPatches_) {
            const auto target = functionStarts_.find(patch.target.value());
            if (target == functionStarts_.end()) {
                return failure(
                    "ir.internal_call_target_missing", "lowered module call target is missing");
            }
            auto* call = std::get_if<vm::VmCall>(
                &report_.program.instructions[patch.instruction]);
            if (call == nullptr) {
                return failure(
                    "ir.lowering_contract_violation", "module call patch is not a call");
            }
            call->target = target->second;
        }
        if (maximumRegisters > std::numeric_limits<std::uint16_t>::max()
            || maximumSlots > std::numeric_limits<std::uint16_t>::max()) {
            return failure("ir.vm_resource_overflow", "lowered module VM resources overflowed");
        }
        report_.program.registerCount = static_cast<std::uint16_t>(maximumRegisters);
        report_.program.slotCount = static_cast<std::uint16_t>(maximumSlots);
        return Result<VmLoweringReport, Diagnostic>::success(std::move(report_));
    }

private:
    void emit(vm::VmInstruction instruction, EntityId source) {
        const auto index = static_cast<std::uint32_t>(report_.program.instructions.size());
        report_.program.instructions.push_back(std::move(instruction));
        report_.lineage.push_back(VmLoweringLineage{index, source});
    }

    auto operand_register(const IrOperand& operand, EntityId source)
        -> Result<vm::VmRegister, Diagnostic> {
        if (const auto* variable = std::get_if<IrVariableOperand>(&operand)) {
            return Result<vm::VmRegister, Diagnostic>::success(
                vm::VmRegister{variable->variable.index});
        }
        if (nextRegister_ >= std::numeric_limits<std::uint16_t>::max()) {
            return Result<vm::VmRegister, Diagnostic>::failure(Diagnostic{
                DiagnosticSeverity::Error,
                "ir.vm_register_overflow",
                "lowered module VM register count overflowed"});
        }
        const auto& immediate = std::get<IrImmediateOperand>(operand);
        const auto result = vm::VmRegister{static_cast<std::uint16_t>(nextRegister_++)};
        emit(vm::VmLoadConstant{
            result, vm::VmValue::from_bits(vm_width(immediate.type), immediate.bits)}, source);
        return Result<vm::VmRegister, Diagnostic>::success(result);
    }

    auto lower_instruction(const IrFunction& function, const IrInstruction& instruction)
        -> Result<std::size_t, Diagnostic> {
        if (const auto* move = std::get_if<IrMove>(&instruction)) {
            if (const auto* variable = std::get_if<IrVariableOperand>(&move->source)) {
                emit(vm::VmMove{
                    vm_width(move->type), vm::VmRegister{move->destination.index},
                    vm::VmRegister{variable->variable.index}}, move->sourceInstruction);
            } else {
                const auto& immediate = std::get<IrImmediateOperand>(move->source);
                emit(vm::VmLoadConstant{
                    vm::VmRegister{move->destination.index},
                    vm::VmValue::from_bits(vm_width(immediate.type), immediate.bits)},
                    move->sourceInstruction);
            }
        } else if (const auto* binary = std::get_if<IrBinaryOperation>(&instruction)) {
            const auto right = operand_register(binary->source, binary->sourceInstruction);
            if (!right.has_value()) {
                return Result<std::size_t, Diagnostic>::failure(right.error());
            }
            emit(vm::VmBinaryOperation{
                vm_binary(binary->opcode), vm_width(binary->type),
                vm::VmRegister{binary->destination.index},
                vm::VmRegister{binary->destination.index}, right.value()},
                binary->sourceInstruction);
        } else if (const auto* unary = std::get_if<IrUnaryOperation>(&instruction)) {
            emit(vm::VmUnaryOperation{
                vm::VmUnaryOpcode::Not, vm_width(unary->type),
                vm::VmRegister{unary->destination.index},
                vm::VmRegister{unary->destination.index}}, unary->sourceInstruction);
        } else if (const auto* compare = std::get_if<IrCompare>(&instruction)) {
            const auto right = operand_register(compare->right, compare->sourceInstruction);
            if (!right.has_value()) return Result<std::size_t, Diagnostic>::failure(right.error());
            emit(vm::VmCompare{
                vm_width(compare->type), vm::VmRegister{compare->left.index}, right.value()},
                compare->sourceInstruction);
        } else if (const auto* test = std::get_if<IrTest>(&instruction)) {
            const auto right = operand_register(test->right, test->sourceInstruction);
            if (!right.has_value()) return Result<std::size_t, Diagnostic>::failure(right.error());
            emit(vm::VmTest{
                vm_width(test->type), vm::VmRegister{test->left.index}, right.value()},
                test->sourceInstruction);
        } else if (const auto* jump = std::get_if<IrJump>(&instruction)) {
            emit(vm::VmJump{0}, jump->sourceInstruction);
            branchPatches_.push_back(ModuleBranchPatch{
                report_.program.instructions.size() - 1,
                ModuleBlockKey{function.sourceFunction.value(), jump->target.value}});
        } else if (const auto* branch = std::get_if<IrConditionalJump>(&instruction)) {
            emit(vm::VmConditionalJump{vm_condition(branch->condition), 0},
                branch->sourceInstruction);
            branchPatches_.push_back(ModuleBranchPatch{
                report_.program.instructions.size() - 1,
                ModuleBlockKey{function.sourceFunction.value(), branch->trueTarget.value}});
            emit(vm::VmJump{0}, branch->sourceInstruction);
            branchPatches_.push_back(ModuleBranchPatch{
                report_.program.instructions.size() - 1,
                ModuleBlockKey{function.sourceFunction.value(), branch->falseTarget.value}});
        } else if (const auto* call = std::get_if<IrInternalCall>(&instruction)) {
            if (!call->destination.has_value()) {
                return compatibility_failure(
                    instruction_name(instruction), instruction_source(instruction));
            }
            std::vector<vm::VmRegister> arguments;
            arguments.reserve(call->arguments.size());
            for (const auto& argument : call->arguments) {
                const auto lowered = operand_register(argument, call->sourceInstruction);
                if (!lowered.has_value()) {
                    return Result<std::size_t, Diagnostic>::failure(lowered.error());
                }
                arguments.push_back(lowered.value());
            }
            emit(vm::VmCall{
                vm::VmRegister{call->destination->index}, 0, std::move(arguments)},
                call->sourceInstruction);
            callPatches_.push_back(ModuleCallPatch{
                report_.program.instructions.size() - 1, call->targetFunction});
        } else if (const auto* returned = std::get_if<IrReturn>(&instruction)) {
            if (!returned->value.has_value()) {
                return compatibility_failure(
                    instruction_name(instruction), instruction_source(instruction));
            }
            emit(vm::VmReturn{vm::VmRegister{returned->value->index}},
                returned->sourceInstruction);
        } else {
            return compatibility_failure(
                instruction_name(instruction), instruction_source(instruction));
        }
        return Result<std::size_t, Diagnostic>::success(1);
    }

    const IrModule& module_;
    VmLoweringReport report_;
    std::size_t nextRegister_{0};
    std::map<std::uint64_t, std::uint32_t> functionStarts_;
    std::map<ModuleBlockKey, std::uint32_t> blockStarts_;
    std::vector<ModuleBranchPatch> branchPatches_;
    std::vector<ModuleCallPatch> callPatches_;
};

} // namespace

auto lower_to_vm(
    const IrFunction& function,
    const IrLimits& irLimits,
    const vm::VmLimits& vmLimits) -> Result<VmLoweringReport, Diagnostic> {
    if (function.variableTypes.size() > std::numeric_limits<std::uint16_t>::max()) {
        return failure("ir.vm_register_overflow", "IR variable count exceeds the VM field");
    }
    if (function_contains_fallback(function)) {
        return failure("ir.fallback_not_lowerable", "IR fallback cannot be lowered to the VM");
    }
    const auto validated = validate_function(function, irLimits);
    if (!validated.has_value()) {
        return Result<VmLoweringReport, Diagnostic>::failure(validated.error());
    }
    const auto compatible = validate_vm_compatibility(function, false);
    if (!compatible.has_value()) {
        return Result<VmLoweringReport, Diagnostic>::failure(compatible.error());
    }
    LoweringBuilder builder{function};
    auto lowered = builder.build();
    if (!lowered.has_value()) return lowered;
    const auto vmValidated = vm::validate_program(lowered.value().program, vmLimits);
    if (!vmValidated.has_value()) {
        return Result<VmLoweringReport, Diagnostic>::failure(vmValidated.error());
    }
    return lowered;
}

auto lower_module_to_vm(
    const IrModule& module,
    const IrLimits& irLimits,
    const vm::VmLimits& vmLimits) -> Result<VmLoweringReport, Diagnostic> {
    for (const auto& function : module.functions) {
        if (function_contains_fallback(function)) {
            return failure(
                "ir.fallback_not_lowerable", "IR fallback cannot be lowered to the VM");
        }
        if (function.variableTypes.size() > std::numeric_limits<std::uint16_t>::max()) {
            return failure("ir.vm_register_overflow", "IR variable count exceeds the VM field");
        }
    }
    auto effectiveIrLimits = irLimits;
    effectiveIrLimits.maxCallDepth = std::min(
        effectiveIrLimits.maxCallDepth, vmLimits.maxFrameDepth);
    const auto validated = validate_module(module, effectiveIrLimits);
    if (!validated.has_value()) {
        return Result<VmLoweringReport, Diagnostic>::failure(validated.error());
    }
    for (const auto& function : module.functions) {
        const auto compatible = validate_vm_compatibility(function, true);
        if (!compatible.has_value()) {
            return Result<VmLoweringReport, Diagnostic>::failure(compatible.error());
        }
    }
    ModuleLoweringBuilder builder{module};
    auto lowered = builder.build();
    if (!lowered.has_value()) return lowered;
    const auto vmValidated = vm::validate_program(lowered.value().program, vmLimits);
    if (!vmValidated.has_value()) {
        return Result<VmLoweringReport, Diagnostic>::failure(vmValidated.error());
    }
    return lowered;
}

} // namespace binobf::ir
