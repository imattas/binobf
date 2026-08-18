#pragma once

#include <utility>
#include <variant>

namespace binobf {

template <typename Value, typename Error>
class Result {
public:
    [[nodiscard]] static auto success(Value value) -> Result {
        return Result(std::in_place_index<0>, std::move(value));
    }

    [[nodiscard]] static auto failure(Error error) -> Result {
        return Result(std::in_place_index<1>, std::move(error));
    }

    [[nodiscard]] auto has_value() const noexcept -> bool {
        return storage_.index() == 0;
    }

    [[nodiscard]] explicit operator bool() const noexcept {
        return has_value();
    }

    [[nodiscard]] auto value() & -> Value& {
        return std::get<0>(storage_);
    }

    [[nodiscard]] auto value() const& -> const Value& {
        return std::get<0>(storage_);
    }

    [[nodiscard]] auto value() && -> Value&& {
        return std::get<0>(std::move(storage_));
    }

    [[nodiscard]] auto error() & -> Error& {
        return std::get<1>(storage_);
    }

    [[nodiscard]] auto error() const& -> const Error& {
        return std::get<1>(storage_);
    }

    [[nodiscard]] auto error() && -> Error&& {
        return std::get<1>(std::move(storage_));
    }

private:
    template <std::size_t Index, typename Item>
    explicit Result(std::in_place_index_t<Index>, Item&& item)
        : storage_(std::in_place_index<Index>, std::forward<Item>(item)) {}

    std::variant<Value, Error> storage_;
};

} // namespace binobf
