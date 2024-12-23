// Copyright 2022 The SiliFuzz Authors.
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

#include "./tools/fuzz_filter_tool.h"

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "./runner/make_snapshot.h"
#include "./runner/runner_provider.h"

namespace silifuzz {

// Kept as a separate function so that we can test this exact config.
absl::Status FilterToolMain(absl::string_view raw_insns_bytes) {
  return MakeRawInstructions(raw_insns_bytes,
                             MakingConfig::Quick(RunnerLocation()))
      .status();
}

}  // namespace silifuzz
