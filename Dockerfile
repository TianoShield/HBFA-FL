# Dockerfile - Ubuntu 22.04 image ready to build EDK2/HBFAplus with dynamic UID/GID
FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ARG USERNAME=hbfafl

# Install system packages needed to build edk2 and fuzzing tooling
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      software-properties-common \
      apt-utils \
      cryptsetup \
      apt-transport-https \
      wget \
      clang \
      llvm \
      clang-tools \
      cmake \
      cups \
      curl \
      dosfstools \
      unzip \
      libjsoncpp-dev \
      bear \
      build-essential \
      uuid-dev \
      git \
      lcov \
      nasm \
      acpica-tools \
      virtualenv \
      device-tree-compiler \
      mono-devel \
      python3 \
      python3-pip \
      python3-venv \
      locales \
      gnupg \
      ca-certificates \
      ninja-build \
      pkg-config \
      python3-distutils \
      python3-setuptools \
      llvm-dev \
      lld \
      iasl \
      u-boot-tools \
      flex \
      bison \
      libssl-dev \
      libncurses-dev \
      libelf-dev \
      bc \
      xz-utils \
      python-is-python3 \
      python3-dev \
      automake \
      libglib2.0-dev \
      libpixman-1-dev \
      cargo \
      openssh-client \
      libgtk-3-dev \
      gcc-11-plugin-dev \
      libstdc++-11-dev \
      sudo \
      gosu \
      gdb \
      file \
      iproute2 \
      iputils-ping \
      net-tools \
      dnsmasq \
      tcpdump \
      qemu-system-x86 \
      qemu-utils \
      tmux \
 && rm -rf /var/lib/apt/lists/*

# Set up UTF-8 locale for GEF and other tools
RUN locale-gen en_US.UTF-8
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

# Create a default user with UID 1000 (will be adjusted at runtime)
RUN groupadd -g 1000 ${USERNAME} \
 && useradd -m -u 1000 -g 1000 -s /bin/bash ${USERNAME} \
 && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} \
 && chmod 0440 /etc/sudoers.d/${USERNAME}

# Install GEF (GDB Enhanced Features) for the hbfafl user
# Clone directly from GitHub to avoid rate limiting issues with the install script
RUN git clone --depth 1 https://github.com/hugsy/gef.git /tmp/gef 2>/dev/null && \
    su - ${USERNAME} -c "echo 'source /tmp/gef/gef.py' >> ~/.gdbinit" || \
    echo "Warning: GEF installation skipped due to connection issues"

# Create entrypoint script that adjusts UID/GID at runtime
RUN cat > /usr/local/bin/entrypoint.sh <<'ENTRYPOINT_EOF'
#!/bin/bash
set -e

USERNAME=hbfafl
USER_UID=${HOST_UID:-1000}
USER_GID=${HOST_GID:-1000}

# Update the hbfafl group GID if different
if [ "$(id -g ${USERNAME})" != "${USER_GID}" ]; then
    groupmod -g ${USER_GID} ${USERNAME} 2>/dev/null || true
fi

# Update the hbfafl user UID if different
if [ "$(id -u ${USERNAME})" != "${USER_UID}" ]; then
    usermod -u ${USER_UID} ${USERNAME} 2>/dev/null || true
fi

# Fix ownership of home directory
chown -R ${USERNAME}:${USERNAME} /home/${USERNAME} 2>/dev/null || true

# Ensure /tmp is writable (tmpfs mounted at runtime via docker-compose)
chmod 1777 /tmp 2>/dev/null || true

# Execute the command as the builder user
exec gosu ${USERNAME} "$@"
ENTRYPOINT_EOF
RUN chmod +x /usr/local/bin/entrypoint.sh

# Environment variables
ENV USERNAME=${USERNAME}
ENV HOME=/home/${USERNAME}
ENV WORKSPACE=/home/${USERNAME}/workspace
ENV AFL_PATH=/home/${USERNAME}/workspace/afl-2.52b
# NOTE: Do NOT add $AFL_PATH to PATH. The AFL_PATH directory contains an `as`
# symlink (afl-as) that, if found via PATH lookup, causes afl-as to invoke
# itself recursively ("Endless loop when calling 'as'"). Instead, expose only
# the user-facing AFL tools via a separate bin dir (see init_hbfa_env.sh).
#
# Also: do NOT export AFL_BIN as a directory. HBFA's tools_def.txt uses it as
# a path *prefix* (e.g. ${AFL_BIN}gcc-ar). Keeping it unset means the build
# resolves gcc-ar/objcopy via PATH while afl-gcc is found in AFL_TOOLS_BIN.
ENV AFL_TOOLS_BIN=/home/${USERNAME}/.local/afl-bin
ENV PATH="${AFL_TOOLS_BIN}:${PATH}"

# Convenience script to initialize EDK2/HBFA-FL environment
RUN mkdir -p /home/${USERNAME}/workspace \
 && cat > /home/${USERNAME}/init_hbfa_env.sh <<'EOF'
#!/usr/bin/env bash
# Note: do NOT use `set -u` here; edk2/edksetup.sh references unset vars
# such as PYTHON_COMMAND and would abort under nounset.
set -o pipefail

# edksetup.sh expects PYTHON_COMMAND to be defined
export PYTHON_COMMAND="${PYTHON_COMMAND:-python3}"

# Source this script to set up env for building EDK2 + HBFA-FL in this container.
# Set environment variables
export WORKSPACE="$HOME/workspace"
export PACKAGES_PATH="$WORKSPACE/edk2:$WORKSPACE/HBFA"
export AFL_PATH="$WORKSPACE/afl-2.52b"
# Do NOT prepend $AFL_PATH to PATH (see Dockerfile note). Instead expose the
# user-facing AFL tools through $AFL_TOOLS_BIN with selective symlinks below.
# AFL_BIN is intentionally left UNSET (HBFA tools_def uses it as a path prefix
# and expects it to be empty so gcc-ar/objcopy resolve via PATH).
unset AFL_BIN
export AFL_TOOLS_BIN="${AFL_TOOLS_BIN:-$HOME/.local/afl-bin}"
export PATH="$AFL_TOOLS_BIN:$PATH"
export PATH="$PATH:$WORKSPACE/HBFA/UefiHostTestTools"
export PATH="$PATH:$WORKSPACE/HBFA/UefiHostTestTools/Report"
export CLANG_PATH="/usr/bin"
export ASAN_SYMBOLIZER_PATH="$CLANG_PATH/llvm-symbolizer"
export LLVM_PROFILE_FILE="$WORKSPACE/fuzz_session.profraw"

echo "============================================"
echo "HBFA-FL Environment Setup"
echo "============================================"
echo "WORKSPACE=$WORKSPACE"
echo "PACKAGES_PATH=$PACKAGES_PATH"
echo "AFL_PATH=$AFL_PATH"

if [ ! -d "$WORKSPACE/edk2" ]; then
    echo "Missing $WORKSPACE/edk2. Mount or clone the edk2 repo first."
    return 1 2>/dev/null || exit 1
fi

if [ ! -d "$WORKSPACE/HBFA" ]; then
    echo "Missing $WORKSPACE/HBFA. Mount or clone HBFA-FL first."
    return 1 2>/dev/null || exit 1
fi

# Download and build AFL-2.52b if not already present
if [ -f "$AFL_PATH/afl-fuzz" ]; then
    echo "AFL-2.52b: Already built, skipping."
else
    echo "Downloading and building AFL-2.52b..."
    mkdir -p /tmp/afl-build
    cd /tmp/afl-build
    wget -q https://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
    tar xzf afl-latest.tgz
    AFL_SRC_DIR="$(find . -maxdepth 1 -type d -name 'afl-*' | head -n 1)"
    if [ -z "$AFL_SRC_DIR" ]; then
        echo "Unable to locate extracted AFL source directory"
        return 1 2>/dev/null || exit 1
    fi
    cd "$AFL_SRC_DIR"
    make -j$(nproc)
    mkdir -p "$AFL_PATH"
    cp -r . "$AFL_PATH"
    cd /
    rm -rf /tmp/afl-build
    echo "AFL-2.52b: Build complete."
fi

# Expose user-facing AFL tools via $AFL_TOOLS_BIN. We deliberately exclude
# `as`/`afl-as` so PATH lookup for the assembler always resolves to /usr/bin/as,
# while afl-gcc still finds afl-as via $AFL_PATH.
mkdir -p "$AFL_TOOLS_BIN"
for tool in afl-gcc afl-g++ afl-clang afl-clang++ afl-fuzz afl-showmap \
            afl-tmin afl-cmin afl-analyze afl-gotcpu afl-plot afl-whatsup; do
    if [ -x "$AFL_PATH/$tool" ] && [ ! -e "$AFL_TOOLS_BIN/$tool" ]; then
        ln -sf "$AFL_PATH/$tool" "$AFL_TOOLS_BIN/$tool"
    fi
done

# Build edk2 BaseTools if not already built
if [ ! -f "$WORKSPACE/edk2/BaseTools/Source/C/bin/GenFw" ]; then
    echo "Building EDK2 BaseTools..."
    make -j$(nproc) -C "$WORKSPACE/edk2/BaseTools"
fi

export EDK_TOOLS_PATH="$WORKSPACE/edk2/BaseTools"

cd "$WORKSPACE/edk2"
source edksetup.sh
cd "$WORKSPACE"

# WORKSPACE is the parent dir (not edk2), so edksetup.sh would point CONF_PATH
# at $WORKSPACE/Conf. Make sure that directory exists and override CONF_PATH
# explicitly to the edk2 Conf used by the EDK-II build system.
mkdir -p "$WORKSPACE/Conf"
export CONF_PATH="$WORKSPACE/edk2/Conf"

# Run HBFA-FL environment setup script to copy Conf files
if [ -f "$WORKSPACE/HBFA/UefiHostTestTools/HBFAEnvSetup.py" ]; then
    echo "Running HBFA-FL environment setup..."
    python3 "$WORKSPACE/HBFA/UefiHostTestTools/HBFAEnvSetup.py"

    if [ -f "$WORKSPACE/HBFA/UefiHostFuzzTestPkg/Conf/build_rule.txt" ] && [ -f "$WORKSPACE/HBFA/UefiHostFuzzTestPkg/Conf/tools_def.txt" ]; then
        cp "$WORKSPACE/HBFA/UefiHostFuzzTestPkg/Conf/build_rule.txt" "$WORKSPACE/edk2/Conf/build_rule.txt"
        cp "$WORKSPACE/HBFA/UefiHostFuzzTestPkg/Conf/tools_def.txt"  "$WORKSPACE/edk2/Conf/tools_def.txt"
        # Mirror to $WORKSPACE/Conf so build.py can also find them when
        # invoked without an explicit --conf argument.
        cp "$WORKSPACE/HBFA/UefiHostFuzzTestPkg/Conf/build_rule.txt" "$WORKSPACE/Conf/build_rule.txt"
        cp "$WORKSPACE/HBFA/UefiHostFuzzTestPkg/Conf/tools_def.txt"  "$WORKSPACE/Conf/tools_def.txt"
        if [ -f "$WORKSPACE/edk2/Conf/target.txt" ]; then
            cp "$WORKSPACE/edk2/Conf/target.txt" "$WORKSPACE/Conf/target.txt"
        fi
        echo "Copied HBFA Conf files into edk2/Conf and \$WORKSPACE/Conf"
    else
        echo "HBFA Conf files were not generated as expected"
    fi
else
    echo "HBFA-FL setup script not found"
fi

echo "============================================"
echo "HBFA-FL Environment Ready!"
echo "============================================"
EOF
RUN chmod +x /home/${USERNAME}/init_hbfa_env.sh \
 && chown -R ${USERNAME}:${USERNAME} /home/${USERNAME}

WORKDIR /home/${USERNAME}/workspace
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash", "-l"]
