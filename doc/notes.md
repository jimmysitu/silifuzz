## 1. Installation

### 1.1. Create container with docker

```bash
git clone https://github.com/jimmysitu/silifuzz.git
git checkout docs
SILIFUZZ_SRC_DIR=`pwd`
docker run -it --tty --security-opt seccomp=unconfined \
    --mount type=bind,source=${SILIFUZZ_SRC_DIR},target=/app \
    --name silifuzz-debian-bookworm --network host \
    debian:bookworm /bin/bash
```

### 1.2. Install build dependencies and set environment variables

Install build dependencies for Debian Bookworm
```bash
cd /app
./install_build_dependencies.debian_bookworm.sh
```

To exit the container, run `exit`.
To restart the container, run `docker start -ai silifuzz-debian-bookworm`.

For simplicity, set `SILIFUZZ_SRC_DIR` to the path of the silifuzz source directory.

```bash
export SILIFUZZ_SRC_DIR=/app
```
And set `SILIFUZZ_BIN_DIR` to the path of the binaries, which is `/app/bazel-bin`.

```bash
export SILIFUZZ_BIN_DIR=/app/bazel-bin
```

### 1.3. Build Silifuzz

Build all the targets and test silifuzz
```bash
cd /app
bazel build ...
bazel test ...
```
If all tests pass, Silifuzz is ready to use.

### Build Tools
```bash
bazel build -c opt @silifuzz//tools:{snap_corpus_tool,fuzz_filter_tool,snap_tool,silifuzz_platform_id,simple_fix_tool_main} \
     @silifuzz//runner:reading_runner_main_nolibc \
     @silifuzz//orchestrator:silifuzz_orchestrator_main
```

### Build Unicorn Proxy
```bash
cd "${SILIFUZZ_SRC_DIR}"
COV_FLAGS_FILE="$(bazel info output_base)/external/com_google_fuzztest/centipede/clang-flags.txt"
bazel build -c opt --copt=-UNDEBUG --dynamic_mode=off \
  --per_file_copt=unicorn/.*@$(xargs < "${COV_FLAGS_FILE}" |sed -e 's/,/\\,/g' -e 's/ /,/g') \
  @//proxies:unicorn_x86_64
```

### Build Centipede
```bash
bazel build -c opt @com_google_fuzztest//centipede:centipede
```
## 2. Run Silifuzz

### 2.1. Fuzz the Unicorn proxy under Centipede

```bash
# Fuzz the Unicorn proxy under Centipede with parallelism of 30 and 1000 runs.
"${SILIFUZZ_BIN_DIR}/external/com_google_fuzztest/centipede/centipede" \
  --binary="${SILIFUZZ_BIN_DIR}/proxies/unicorn_x86_64" \
  --workdir=/tmp/wd \
  --j=4 --num_runs=1000
```
#### Introduction to Unicorn
- A quick start guide to Unicorn engine can be found [here](https://www.unicorn-engine.org/docs/tutorial.html)

- Unicorn is the fuzz target, for more information about fuzz target, please refer to [here](https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md)
  - The entry point of a fuzz target is the function `LLVMFuzzerTestOneInput`, which is defined in `proxies/unicorn_x86_64.cc`.
  ```c++
  extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
  ```


#### Introduction to Centipede
- Introduction to Centipede can be found [here](https://github.com/google/fuzztest/blob/main/centipede/README.md)

- Centipede is fully compatible with libFuzzer, a complete tutorial of libFuzzer can be found [here](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md)
  - An introduction to libFuzzer can be found [here](https://llvm.org/docs/LibFuzzer.html), which introduces the concept of centipede.


- The output of Centipede is corpus, which is a set of inputs that have been successfully fuzzed.
- For more information about corpus, please refer to [here](https://llvm.org/docs/LibFuzzer.html#corpus)

##### Corpus Distillation
```bash
"${SILIFUZZ_BIN_DIR}/external/com_google_fuzztest/centipede/centipede" \
  --binary="${SILIFUZZ_BIN_DIR}/proxies/unicorn_x86_64" \
  --workdir=/tmp/wd \
  --distill --num_threads=1 --total_shards=4
```

#### Create Runnable Corpus

```bash
# Convert fuzzing result corpus.* into a 10-shard runnable corpus for the current architecture
"${SILIFUZZ_BIN_DIR}/tools/simple_fix_tool_main" \
  --num_output_shards=10 \
  --output_path_prefix=/tmp/wd/runnable-corpus \
  --runner=${SILIFUZZ_BIN_DIR}/runner/reading_runner_main_nolibc \
  /tmp/wd/corpus.*
```

#### Scan All Core of a CPU

```bash
ls -1 /tmp/wd/runnable-corpus.* > /tmp/shard_list
${SILIFUZZ_BIN_DIR}/orchestrator/silifuzz_orchestrator_main --duration=30s \
     --runner=${SILIFUZZ_BIN_DIR}/runner/reading_runner_main_nolibc \
     --shard_list_file=/tmp/shard_list

```

## Silifuzz Framework

<div align="center" style="width: 80%">

```mermaid
graph TD

subgraph HOST[Host]
    subgraph FE[Fuzzing Engine: Centipede]
        subgraph PROXIES[Proxies]
            UNICORN[Unicorn Proxy]
            XED[XED Proxy]
        end
        style PROXIES fill:#ccffcc
    end

	subgraph SNAPSHOT[<div style="margin-right:20em">Snapshot</div>]
	    INIT(Initial)
	    CORPUS(Corpus)
	    EXCEPT(Exception)
	end
    PROXIES --> CORPUS
end 

subgraph CLIENT[Client]
    direction LR
    subgraph MEM[Memory]
        SNAP("[SNAP]Snapshot loaded in memory")
    end

    subgraph ORCHESTRATOR[Orchestrator]
        SNAP --> RUNNER_0(Runner0)
        SNAP --> RUNNER_1(Runner1)
        SNAP --> RUNNER_DOT(......)
        SNAP --> RUNNER_N(RunnerN)
    end
end
style HOST fill:none, stroke:#000, stroke-width:1px, stroke-dasharray:5,5
style CLIENT fill:none, stroke:#000, stroke-width:1px, stroke-dasharray:5,5

SNAPSHOT ---> CLIENT
```

</div>

### Unicorn Proxy

#### Before Running Unicorn
- `tracer.InitSnippet()`, initial snapshot for Unicorn
- `tracer.SetInstructionCallback()`, setup callback for each instruction run in Unicorn
  - It disassembles the next 16 bytes with XED
  - Check if the instruction is still in the range of code snippet
 

#### Running Unicorn
- `tracer.Run()`, call Unicorn and run instructions
  - Callback executes after every instruction
  - Stop when callback find that instruction reach the end of code address
  - Or stop when get to max instruction limit

#### After Running Unicorn
- `tracer.ReadMemory()`, get memory image after execution


#### User Feature Generator
- `feature_gen.BeforeInput(features)`, reset features
- `feature_gen.BeforeExecution(registers)`, record initial states
- `feature_gen.AfterInstruction()`, runs after every instruction
  - Record instruction toggle and register toggle
- `feature_gen.AfterExecution()`, runs after code snippet is done
  - Emit global register toggle feature
  - Emit overall register different feature
  - Emit pre-instruction feature, including
    - Instruction id
    - Pre-instruction register toggle
- `feature_gen.FinalMemory()`
  - Memory changes in data1 and data2


### Simple Fix Tool
The tool is designed to process raw instruction sequences from Centipede's corpus, convert them into snapshots, and then partition these snapshots into shards for further use.

- `FixupCorpus()` is a top-level function in the simple fix tool. Its job is to
  - Take raw instruction blobs (such as those coming from Centipede), by `ReadUniqueCentipedeBlobs()` 
  - Process and convert them into “snapshots” (a more structured, executable representation), using `MakeSnapshotsFromBlobs()`
  - Partition these snapshots into output shards, using `PartitionSnapshots()`
  - The resulting relocatable corpus is then ready for use by other tools, for example, runners that execute these snapshots

- `ReadUniqueCentipedeBlobs()`, reads multiple input blob files, extracts all the instruction blobs, and removes any duplicates to create a clean, deduplicated set of instruction sequences for further processing.
  - Using SHA1 to deduplicate blobs
  - Return a vector of unique blobs

- `MakeSnapshotsFromBlobs()`, transforms raw instruction sequences (blobs) into structured Snapshot objects that can be executed.
  - Determines how many worker threads to use based on the provided options
  - Divides the input blobs evenly among the workers using `PartitionEvenly()`
  - Starts a separate thread to monitor and display progress during processing, using `MakeProgressMonitor()`
  - Launches multiple threads to process blobs in parallel
  ```c++
  std::vector<FixToolWorkerArgs> worker_args;
  // ... prepare arguments
  std::vector<std::thread> workers;
  // ... create worker threads
  for (size_t i = 0; i < num_workers; ++i) {
    workers.emplace_back(FixToolWorker, std::ref(worker_args[i]));
  }
  ```

- `FixToolWorker()`, processes its assigned blobs
  - Converting each blob into a snapshot, using `InstructionsToSnapshot()`
  - Setting a unique snapshot ID, using `InstructionsToSnapshotId()`
  - Normalizing the snapshot, using `NormalizeSnapshot()`
  - Rewriting the initial state, using `RewriteInitialState()`
  - Applying any additional fixups as specified by the options, using `FixupSnapshot()`
  - Converting to a relocatable snapshot, using `Snapify()`
  - Returns the final collection of valid snapshots

- `PartitionSnapshots()`, 
  - Partitions the snapshots into output shards.
  - The resulting relocatable corpus is then ready for use by other tools, for example, runners that execute these snapshots

### Orchestrator


### Runner
