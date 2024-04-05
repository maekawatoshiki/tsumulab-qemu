#!/bin/sh -eu

export RISCV=${RISCV:-$HOME/riscv}
BITS=${BITS:-64}

BIN="quicksort"
BIN=Puzzle
ADDRS=$($RISCV/rv${BITS}/bin/riscv${BITS}-unknown-linux-gnu-readelf -s "${BIN}" | awk '
/ FUNC / && / main$/ {
  entry_addr = strtonum("0x"$2)
  ret_addr = strtonum("0x"$2) + strtonum($3) - 4
  printf "%x %x\n", entry_addr, ret_addr
}')
export TRACE_MAIN_ENTRY_ADDR=${ADDRS%% *}
export MEM_STATE_PATH="${BIN}.mem"
export REG_STATE_PATH="${BIN}.reg"
export TRACE_PATH="${BIN}.trace"

rm -f ${MEM_STATE_PATH} ${REG_STATE_PATH} ${TRACE_PATH}

mkfifo "${MEM_STATE_PATH}"
mkfifo "${REG_STATE_PATH}"
mkfifo "${TRACE_PATH}"

../build/qemu-riscv${BITS} -one-insn-per-tb -d plugin -plugin ./plugins/libecstrace.so "${BIN}" &

xz -T0 -c "${MEM_STATE_PATH}" > "${MEM_STATE_PATH}.xz" &
xz -T0 -c "${REG_STATE_PATH}" > "${REG_STATE_PATH}.xz" &
xz -T0 -c "${TRACE_PATH}" > "${TRACE_PATH}.xz" &

wait

rm -f ${MEM_STATE_PATH} ${REG_STATE_PATH} ${TRACE_PATH}
