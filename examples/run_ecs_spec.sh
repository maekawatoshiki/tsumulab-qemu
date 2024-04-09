#!/bin/sh -eu

export RISCV=${RISCV:-$HOME/riscv}
BITS=${BITS:-64}

BIN=${1?Usage: $0 <binary>}
BINNAME=$(basename "${BIN}")
ADDRS=$($RISCV/rv${BITS}/bin/riscv${BITS}-unknown-linux-gnu-readelf -s "${BIN}" | awk '
/ FUNC / && / main$/ {
  entry_addr = strtonum("0x"$2)
  ret_addr = strtonum("0x"$2) + strtonum($3) - 4
  printf "%x %x\n", entry_addr, ret_addr
}')

export TRACE_MAIN_ENTRY_ADDR=${ADDRS%% *}
export TRACE_DIR="${PWD}/traces"
export MEM_STATE_PATH="${TRACE_DIR}/${BINNAME}.mem.%04d"
export REG_STATE_PATH="${TRACE_DIR}/${BINNAME}.reg.%04d"
export TRACE_PATH="${TRACE_DIR}/${BINNAME}.trace.%04d"

mkdir -p "${TRACE_DIR}"

# if [ ! -f "${MEM_STATE_PATH}" ] || [ ! -f "${REG_STATE_PATH}" ] || [ ! -f "${TRACE_PATH}.xz" ]; then
#     rm -f ${MEM_STATE_PATH} ${REG_STATE_PATH} ${TRACE_PATH}
#
#     mkfifo "${TRACE_PATH}"
#
#     make ecs_trace_plugin
#     QEMU=$PWD/../build/qemu-riscv${BITS}
#     PLUGIN=$PWD/plugins/libecstrace.so
#     (
#         cd ~/work/SPECCPU95INT/124.m88ksim/data/train/input
#         $QEMU -one-insn-per-tb -d plugin -plugin $PLUGIN "${BIN}" < ctl.in.riscv
#     ) &
#
#     xz -T0 -c "${TRACE_PATH}" > "${TRACE_PATH}.xz" &
#
#     wait
#
#     rm -f ${TRACE_PATH}
# else
#     echo "\033[0;32mUsing existing trace files.\033[0m"
# fi

echo "\033[0;32mRunning ecs-simulator with:\033[1;37m\n ${MEM_STATE_PATH}\n ${REG_STATE_PATH}\n ${TRACE_PATH}.xz\033[0m"

ECS=$HOME/work/ecs-simulator/ecs
xz -T0 -dc "${TRACE_PATH}.xz" | $ECS "${REG_STATE_PATH}" "${MEM_STATE_PATH}"

echo "\033[0;32mDone. Check the simulation result.\033[0m"

