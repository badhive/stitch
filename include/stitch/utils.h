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

#ifndef STITCH_UTILS_H_
#define STITCH_UTILS_H_

namespace stitch {
using VA = std::intptr_t;
using RVA = std::intptr_t;

namespace utils {
template <typename V, typename A>
V RoundToBoundary(V value, A alignment) {
  return value ? ((value + alignment - 1) / alignment) * alignment : 0;
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