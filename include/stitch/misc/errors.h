/*
 * Licensed to BadHive under one or more contributor license
 * agreements.  See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * BadHive licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
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

class import_not_found_error : public code_error {
 public:
  import_not_found_error() : code_error("import not found") {}
};
}  // namespace stitch

#endif  // STITCH_ERRORS_H_