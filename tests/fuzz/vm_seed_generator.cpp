#include <binobf/vm/bytecode.hpp>

#include <cstddef>
#include <fstream>
#include <iostream>

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    using namespace binobf::vm;
    const VmProgram program{
        .version = currentVmVersion,
        .registerCount = 3,
        .slotCount = 1,
        .localMemorySize = 32,
        .instructions = {
            VmLoadConstant{VmRegister{0}, VmValue::from_bits(VmWidth::U32, 17)},
            VmStoreSlot{VmWidth::U32, VmSlot{0}, VmRegister{0}},
            VmLoadSlot{VmWidth::U32, VmRegister{1}, VmSlot{0}},
            VmLoadConstant{VmRegister{2}, VmValue::from_bits(VmWidth::U32, 25)},
            VmBinaryOperation{
                VmBinaryOpcode::Add, VmWidth::U32,
                VmRegister{0}, VmRegister{1}, VmRegister{2}},
            VmReturn{VmRegister{0}},
        },
    };
    const auto bytecode = assemble_program(program, VmAssemblyOptions{12012});
    if (!bytecode.has_value()) {
        std::cerr << bytecode.error().code << ": " << bytecode.error().message << '\n';
        return 1;
    }
    std::ofstream stream(argv[1], std::ios::binary | std::ios::trunc);
    stream.write(
        reinterpret_cast<const char*>(bytecode.value().data()),
        static_cast<std::streamsize>(bytecode.value().size()));
    return stream ? 0 : 1;
}
