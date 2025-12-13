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

#ifndef STITCH_UTILS_H_
#define STITCH_UTILS_H_

#include <string>

namespace stitch {
using VA = std::intptr_t;
using RVA = std::intptr_t;

namespace utils {
template <typename T>
inline constexpr bool dependent_false = false;

template <typename V, typename A>
V RoundToBoundary(V value, A alignment) {
  return value ? ((value + alignment - 1) / alignment) * alignment : 0;
}

inline std::string tolower(const std::string& str) {
  std::string ret(str);
  for (int i = 0; i < str.length(); i++) {
    ret[i] = std::tolower(str[i]);
  }
  return ret;
}

// stupidly simple solving that is useless outside this project
namespace sym {
class Reg {
  bool defined_;
  const std::string name_;
  uint64_t value_;

 public:
  explicit Reg(const std::string& name)
      : defined_(false), name_(name), value_(~0) {}

  explicit Reg(const std::string& name, const uint64_t value)
      : defined_(true), name_(name), value_(value) {}

  operator uint64_t() const { return value_; }

  bool Defined() const { return defined_; }

  void Undefine() {
    defined_ = false;
    value_ = ~0;
  }

  Reg& operator=(const uint64_t value) {
    value_ = value;
    defined_ = true;
    return *this;
  }

  Reg& operator=(const Reg& other) {
    defined_ = other.defined_;
    value_ = other.value_;
    return *this;
  }

  Reg& operator+(const Reg& other) {
    if (!other.defined_) {
      defined_ = false;
    } else {
      value_ += other.value_;
    }
    return *this;
  }

  Reg& operator-(const Reg& other) {
    if (!other.defined_) {
      if (*this == other) {
        defined_ = true;
        value_ = 0;
      } else
        defined_ = false;
    } else {
      value_ -= other.value_;
    }
    return *this;
  }

  Reg& operator*(const Reg& other) {
    if (!other.defined_) {
      defined_ = false;
    } else {
      value_ *= other.value_;
    }
    return *this;
  }

  Reg& operator/(const Reg& other) {
    if (!other.defined_) {
      if (*this == other) {
        defined_ = true;
        value_ = 1;
      } else
        defined_ = false;
    } else {
      value_ /= other.value_;
    }
    return *this;
  }

  Reg& operator&(const Reg& other) {
    if (!other.defined_) {
      defined_ = false;
    } else {
      value_ &= other.value_;
    }
    return *this;
  }

  Reg& operator|(const Reg& other) {
    if (!other.defined_) {
      defined_ = false;
    } else {
      value_ |= other.value_;
    }
    return *this;
  }

  Reg& operator^(const Reg& other) {
    if (!other.defined_) {
      if (*this == other) {
        defined_ = true;
        value_ = 0;
      } else
        defined_ = false;
    } else {
      value_ ^= other.value_;
    }
    return *this;
  }

  Reg operator+(const uint64_t other) {
    auto r = Reg(*this);
    r.value_ += other;
    return r;
  }

  Reg operator-(const uint64_t other) {
    auto r = Reg(*this);
    r.value_ -= other;
    return r;
  }

  Reg operator*(const uint64_t other) {
    auto r = Reg(*this);
    r.value_ *= other;
    return r;
  }

  Reg operator/(const uint64_t other) {
    auto r = Reg(*this);
    r.value_ /= other;
    return r;
  }

  Reg operator&(const uint64_t other) {
    auto r = Reg(*this);
    r.value_ &= other;
    return r;
  }

  Reg operator|(const uint64_t other) {
    auto r = Reg(*this);
    r.value_ |= other;
    return r;
  }

  Reg operator^(const uint64_t other) {
    auto r = Reg(*this);
    r.value_ ^= other;
    return r;
  }

  bool operator==(const Reg& other) const {
    return name_ == other.name_ && defined_ == other.defined_ &&
           value_ == other.value_;
  }

  bool operator==(const uint64_t other) const {
    return defined_ && value_ == other;
  }
};
}  // namespace sym
}  // namespace utils
}  // namespace stitch

#endif  // STITCH_UTILS_H_