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
}  // namespace utils
}  // namespace stitch

#endif  // STITCH_UTILS_H_