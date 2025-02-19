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

#include <vector>
#include <cstdint>
#include "gtest/gtest.h"

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

namespace {

static int run_bytes(std::vector<uint8_t>&& data) {
  // Ensure initialization is done once.
  static int initialize = LLVMFuzzerInitialize(nullptr, nullptr);
  (void)initialize;  // Silence unused variable warnings.
  return LLVMFuzzerTestOneInput(data.data(), data.size());
}

// For XED, a return value of 0 means the instruction successfully decoded,
// and -1 indicates a decode error.
#define EXPECT_BYTES_ACCEPTED(...) EXPECT_EQ(0, run_bytes(__VA_ARGS__));
#define EXPECT_BYTES_REJECTED(...) EXPECT_EQ(-1, run_bytes(__VA_ARGS__));

TEST(XedX86_64, Nop) {
  EXPECT_BYTES_ACCEPTED({0x90});
}

TEST(XedX86_64, Hlt) {
  EXPECT_BYTES_ACCEPTED({0xF4});
}

TEST(XedX86_64, ReadMappedMem) {
  // This instruction encodes:
  //   mov eax, ds:0x1000010000
  EXPECT_BYTES_ACCEPTED({0xA1, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00});
}

TEST(XedX86_64, ReadUnmappedMem) {
  // In the unicorn proxy, an instruction reading unmapped memory would be rejected.
  // In the XED proxy, the instruction is simply decoded.
  // This corresponds to: mov eax, dword ptr [0]
  EXPECT_BYTES_ACCEPTED({0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00});
}

TEST(XedX86_64, Loop10) {
  // This sequence corresponds to:
  //   xor rcx, rcx
  //   mov cl, 10
  //   loop .
  EXPECT_BYTES_ACCEPTED({0x48, 0x31, 0xC9, 0xB1, 0x0A, 0xE2, 0xFE});
}

TEST(XedX86_64, Runaway) {
  // "jmp ." encoded as EB FE. While this represents an infinite loop at runtime,
  // it is a valid instruction for decoding.
  EXPECT_BYTES_ACCEPTED({0xEB, 0xFE});
}

TEST(XedX86_64, JmpFar) {
  // "jmp .+0x60" encoded as EB 60 is a valid relative jump.
  EXPECT_BYTES_ACCEPTED({0xEB, 0x60});
}

TEST(XedX86_64, UD) {
  // This sequence is expected to be undefined and hence fail to decode.
  EXPECT_BYTES_REJECTED({0x0F, 0xFF});
}

}  // namespace 