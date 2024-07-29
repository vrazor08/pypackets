#!/bin/sh

CC="${CXX:-cc}"
CFLAGS="-fPIC -Wall -Wextra -std=c11"
LDFLAGS="-shared"
CSRC="./pypackets/syscalls/sendmmsg.c"
CSRC_BIN="./pypackets/syscalls/bin/sendmmsg.so"
BIN_DIR=$(dirname "$CSRC_BIN")

c_build() {
  mkdir -p $BIN_DIR
  $CC $LDFLAGS $CFLAGS -o $CSRC_BIN $CSRC
}

echo "sendmmsg building..."
c_build