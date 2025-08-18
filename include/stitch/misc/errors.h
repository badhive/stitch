/*
 * This file is part of the 'Stitch' binary patching library.
 * Copyright (c) 2025 pygrum
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef STITCH_ERRORS_H_
#define STITCH_ERRORS_H_

#include <stdexcept>

namespace stitch {
//----------------------------------------------------------------------------//
//------------------           top-level errors           --------------------//
//----------------------------------------------------------------------------//
class binary_error : public std::runtime_error {
 public:
  explicit binary_error(const std::string& msg) : std::runtime_error(msg) {}
};

class section_error : public std::runtime_error {
 public:
  explicit section_error(const std::string& msg) : runtime_error(msg) {}
};

class code_error : public std::runtime_error {
 public:
  explicit code_error(const std::string& msg) : runtime_error(msg) {}
};

//----------------------------------------------------------------------------//
//------------------              sub-errors              --------------------//
//----------------------------------------------------------------------------//
class invalid_binary_format_error : public binary_error {
 public:
  invalid_binary_format_error() : binary_error("invalid binary format") {}
};

class unsupported_section_type_error : public section_error {
 public:
  explicit unsupported_section_type_error(const std::string& name)
      : section_error("section '" + name +
                      "' stores data of an unsupported type") {}
};

class section_not_found_error : public section_error {
 public:
  explicit section_not_found_error(const std::string& name)
      : section_error("section '" + name + "' not found") {}
};

class invalid_section_name_error : public section_error {
 public:
  invalid_section_name_error() : section_error("section name too long") {}
};

class section_exists_error : public section_error {
 public:
  section_exists_error() : section_error("section already exists") {}
};

class arch_mismatch_error : public code_error {
 public:
  arch_mismatch_error()
      : code_error("architecture mismatch between code components") {}
};
}  // namespace stitch

#endif  // STITCH_ERRORS_H_