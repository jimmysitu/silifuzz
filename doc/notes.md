## Installation

1. Create container with docker

```bash
git clone https://github.com/jimmysitu/silifuzz.git
git checkout docs
SILIFUZZ_SRC_DIR=`pwd`
docker run -it --tty --security-opt seccomp=unconfined \
    --mount type=bind,source=${SILIFUZZ_SRC_DIR},target=/app \
    --name silifuzz-debian-bookworm --network host \
    debian:bookworm /bin/bash
```

2. Install build dependencies

Install build dependencies for Debian Bookworm
```bash
./install_build_dependencies.debian_bookworm.sh
```

3. Build silifuzz

Build all the targets and test silifuzz
```bash
cd /app
bazel build ...
bazel test ...
```
