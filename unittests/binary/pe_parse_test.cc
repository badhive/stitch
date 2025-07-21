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

#include "stitch/binary/pe.h"

#include <fstream>

using namespace stitch;

int main() {
    std::fstream fs("pe_simple.bin");
    PEFormat format{};
    PEFormat::Parse(fs, format);

    format.GetSectionInfo(".CRT");
    format.GetSectionInfo(".bss");
    format.GetSectionInfo(".data");
    format.GetSectionInfo(".idata");
    format.GetSectionInfo(".pdata");
    format.GetSectionInfo(".rdata");
    format.GetSectionInfo(".reloc");
    format.GetSectionInfo(".reloc");
    format.GetSectionInfo(".text");
    format.GetSectionInfo(".tls");
    format.GetSectionInfo(".xdata");
    format.GetSectionInfo(".xdata");

    fs.close();
}
