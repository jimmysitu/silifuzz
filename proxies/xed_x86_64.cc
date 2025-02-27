// Copyright 2025 The SiliFuzz Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "instruction/xed_util.h"


// Initialize the XED library tables once before any decoding.
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  // Initialize XED tables used for decoding.
  silifuzz::InitXedIfNeeded();
  return 0;
}

// LLVMFuzzerTestOneInput uses XED to decode an x86-64 instruction from the
// fuzzing input. This proxy simply decodes an instruction and returns.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // If the input is empty, exit early.
  if (size == 0)
    return 0;

  // Create a decoded instruction object.
  xed_decoded_inst_t xedd;

  // Zero initialize the decoded instruction.
  xed_decoded_inst_zero(&xedd);

  // Set the decoding mode to x86-64 long mode with 64-bit addressing.
  xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  // Attempt to decode the instruction.
  xed_error_enum_t xed_error = xed_decode(&xedd, data, size);
  if (xed_error != XED_ERROR_NONE) {
    // Optionally report decoding errors.
    // For example:
    // fprintf(stderr, "XED decode error: %s\n", xed_error_enum_t2str(xed_error));
    return -1;
  }

  // (Optional) Further processing could be done using the decoded instruction.
  // For instance, examining the opcode, operands, or printing the disassembly.

  return 0;
}