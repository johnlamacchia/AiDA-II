#pragma once
#include "core/binary.hpp"
#include <string>

namespace aida {

bool save_project(const BinaryImage& img, const std::string& path);
bool load_project(BinaryImage& img, const std::string& path);

}
