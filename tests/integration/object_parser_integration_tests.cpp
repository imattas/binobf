#include "../test_support.hpp"

#include <binobf/formats/object_parser.hpp>

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {

std::filesystem::path coffFixture;
std::filesystem::path elfFixture;

auto parse_file(const std::filesystem::path& path) -> binobf::BinaryImage {
    std::error_code sizeError;
    const auto fileSize = std::filesystem::file_size(path, sizeError);
    if (sizeError) {
        throw std::runtime_error("could not size object fixture: " + path.string());
    }
    std::vector<std::byte> bytes(static_cast<std::size_t>(fileSize));
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw std::runtime_error("could not open object fixture: " + path.string());
    }
    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!stream) {
        throw std::runtime_error("could not read object fixture: " + path.string());
    }
    auto parsed = binobf::parse_object(bytes, path.filename().string());
    if (!parsed.has_value()) {
        throw std::runtime_error(
            "object parser rejected fixture: " + parsed.error().code + ": "
            + parsed.error().message);
    }
    return std::move(parsed).value();
}

auto find_symbol(const binobf::BinaryImage& image, std::string_view name)
    -> const binobf::Symbol* {
    const auto found = std::find_if(image.symbols.begin(), image.symbols.end(), [name](const auto& symbol) {
        return symbol.name == name;
    });
    return found == image.symbols.end() ? nullptr : &*found;
}

auto has_section(const binobf::BinaryImage& image, binobf::EntityId id) -> bool {
    return std::any_of(image.sections.begin(), image.sections.end(), [id](const auto& section) {
        return section.id == id;
    });
}

auto has_symbol(const binobf::BinaryImage& image, binobf::EntityId id) -> bool {
    return std::any_of(image.symbols.begin(), image.symbols.end(), [id](const auto& symbol) {
        return symbol.id == id;
    });
}

void require_real_object_contract(
    const binobf::BinaryImage& image,
    binobf::BinaryFormat expectedFormat) {
    REQUIRE_EQ(image.format, expectedFormat);
    REQUIRE_EQ(image.type, binobf::BinaryType::RelocatableObject);
    REQUIRE_EQ(image.architecture, binobf::Architecture::X86_64);
    const auto* add = find_symbol(image, "binobf_fixture_add");
    const auto* accumulate = find_symbol(image, "binobf_fixture_accumulate");
    REQUIRE(add != nullptr);
    REQUIRE(accumulate != nullptr);
    REQUIRE(add->defined);
    REQUIRE(accumulate->defined);
    REQUIRE_EQ(add->kind, binobf::SymbolKind::Function);
    REQUIRE_EQ(accumulate->kind, binobf::SymbolKind::Function);
    REQUIRE(add->section.has_value());
    REQUIRE(accumulate->section.has_value());
    REQUIRE(has_section(image, *add->section));
    REQUIRE(has_section(image, *accumulate->section));
    REQUIRE(!image.relocations.empty());
    for (const auto& relocation : image.relocations) {
        REQUIRE(has_section(image, relocation.section));
        if (relocation.targetSymbol.has_value()) {
            REQUIRE(has_symbol(image, *relocation.targetSymbol));
        }
    }
}

} // namespace

TEST_CASE(real_compiler_coff_object_satisfies_normalized_contract) {
    require_real_object_contract(parse_file(coffFixture), binobf::BinaryFormat::COFF);
}

TEST_CASE(real_compiler_elf_object_satisfies_normalized_contract) {
    require_real_object_contract(parse_file(elfFixture), binobf::BinaryFormat::ELF);
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "expected COFF and ELF fixture paths\n";
        return 2;
    }
    coffFixture = argv[1];
    elfFixture = argv[2];
    return binobf::test::run_all();
}
