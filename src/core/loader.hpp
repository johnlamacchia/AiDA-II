#pragma once
#include "core/binary.hpp"
#include <string>
#include <memory>

namespace aida {

std::unique_ptr<BinaryImage> load_binary(const std::string& path);

}
