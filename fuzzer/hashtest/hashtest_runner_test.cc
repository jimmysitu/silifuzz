// Copyright 2024 The Silifuzz Authors.
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

#include "./fuzzer/hashtest/hashtest_runner.h"

#include <cstdint>
#include <cstring>

#include "gtest/gtest.h"
#include "./fuzzer/hashtest/hashtest_runner_widgits.h"
#include "./instruction/xed_util.h"
#include "./util/platform.h"

namespace silifuzz {

namespace {

// Test to validate the assumptions made in the hashtest runner.
TEST(Runner, AllSupported) {
  InitXedIfNeeded();
  for (size_t i = 0; i < static_cast<size_t>(kMaxPlatformId); i++) {
    PlatformId p = static_cast<PlatformId>(i);
    // Ivybridge machines are the only pre-AVX2 PlatformId.
    // They are pretty old, so we aren't going to worry about supporting them
    // with HashTests right now.
    if (p == PlatformId::kIntelIvybridge) {
      continue;
    }
    xed_chip_enum_t chip = PlatformIdToChip(p);
    if (chip == XED_CHIP_INVALID) {
      continue;
    }
    size_t vector_width = ChipVectorRegisterWidth(chip);
    // Currently, the runner supports 256 and 512 bit vector registers.
    EXPECT_GE(vector_width, 256) << i;
    EXPECT_LE(vector_width, 512) << i;
    // The mask registers are expected to be 64 bit, if they exist.
    if (vector_width >= 512) {
      EXPECT_EQ(ChipMaskRegisterWidth(chip), vector_width / 8) << i;
    }
  }
}

size_t CurrentVectorWidth() {
  InitXedIfNeeded();
  PlatformId platform = CurrentPlatformId();
  xed_chip_enum_t chip = PlatformIdToChip(platform);
  size_t vector_width =
      chip != XED_CHIP_INVALID ? ChipVectorRegisterWidth(chip) : 0;
  return vector_width;
}

void SmokeTest(uint64_t seed, size_t vector_width) {
  TestConfig config = {
      .vector_width = vector_width,
      .num_iterations = 1,
  };
  EntropyBuffer input = {};
  EntropyBuffer output = {};
  RandomizeEntropyBuffer(seed, input);

  // NopTest should leave the registers undisturbed.
  // Running it should result in the input being copied to the output, although
  // bytes at the end of the input may be ignored if the vector width is not the
  // maximum.
  RunHashTest(reinterpret_cast<void*>(&NopTest), config, input, output);

  // Check that the relevant part of the buffer has been copied and the rest has
  // been left untouched.
  size_t num_bytes = input.NumBytes(vector_width);
  for (size_t i = 0; i < sizeof(output.bytes); i++) {
    EXPECT_EQ(output.bytes[i], i < num_bytes ? input.bytes[i] : 0) << i;
  }
}

TEST(Runner, Run512) {
  constexpr size_t kVectorWidth = 512;
  if (CurrentVectorWidth() < kVectorWidth) {
    GTEST_SKIP() << "Chip does not support this vector width.";
  }
  // Test with two different bit patterns.
  SmokeTest(0, kVectorWidth);
  SmokeTest(1, kVectorWidth);
}

TEST(Runner, Run256) {
  constexpr size_t kVectorWidth = 256;
  if (CurrentVectorWidth() < kVectorWidth) {
    GTEST_SKIP() << "Chip does not support this vector width.";
  }

  // Test with two different bit patterns.
  SmokeTest(2, kVectorWidth);
  SmokeTest(3, kVectorWidth);
}

}  // namespace

}  // namespace silifuzz