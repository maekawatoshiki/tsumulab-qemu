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
export MEM_STATE_PATH="${TRACE_DIR}/${BINNAME}.mem"
export REG_STATE_PATH="${TRACE_DIR}/${BINNAME}.reg"
export TRACE_PATH="${TRACE_DIR}/${BINNAME}.trace"

mkdir -p "${TRACE_DIR}"

FORCE_RETRACE=${FORCE_RETRACE:-0}

if [ "${FORCE_RETRACE}" -ne 0 ] || [ ! -f "${MEM_STATE_PATH}" ] || [ ! -f "${REG_STATE_PATH}" ] || [ ! -f "${TRACE_PATH}.xz" ]; then
    rm -f ${MEM_STATE_PATH} ${REG_STATE_PATH} ${TRACE_PATH}

    mkfifo "${TRACE_PATH}"

    make ecs_trace_plugin
    QEMU=$PWD/../build/qemu-riscv${BITS}
    PLUGIN=$PWD/plugins/libecstrace.so

    case "${BINNAME}" in
    go*)
        (
            cd ~/work/SPECCPU95INT/099.go/data/train/input
            $QEMU -one-insn-per-tb -d plugin -plugin $PLUGIN "${BIN}" 50 9 2stone9.in
        ) &
        ;;
    m88ksim*)
        (
            cd ~/work/SPECCPU95INT/124.m88ksim/data/train/input
            $QEMU -one-insn-per-tb -d plugin -plugin $PLUGIN "${BIN}" < ctl.in.riscv
        ) &
        ;;
    gcc*)
        (
            cd ~/work/SPECCPU95INT/126.gcc/data/train/input
            $QEMU -one-insn-per-tb -d plugin -plugin $PLUGIN "${BIN}" \
                -funroll-loops -fforce-mem -fcse-follow-jumps -fcse-skip-blocks \
                -fexpensive-optimizations -fstrength-reduce -fpeephole \
                -fschedule-insns -finline-functions -fschedule-insns2 -O \
                amptjp.i -o /tmp/amptjp.s
        ) &
        ;;
    compress*)
        (
            cd ~/work/SPECCPU95INT/129.compress/data/train/input
            $QEMU -one-insn-per-tb -d plugin -plugin $PLUGIN "${BIN}" < test.in
        ) &
        ;;
    li*)
        (
            cd ~/work/SPECCPU95INT/130.li/data/train/input
            $QEMU -one-insn-per-tb -d plugin -plugin $PLUGIN "${BIN}" train.lsp
        ) &
        ;;
    ijpeg*)
        (
            cd ~/work/SPECCPU95INT/132.ijpeg/data/train/input
            $QEMU -one-insn-per-tb -d plugin -plugin $PLUGIN "${BIN}" \
                -image_file vigo.ppm -compression.quality 90 -compression.optimize_coding 0 \
                -compression.smoothing_factor 90 -difference.image 1 -difference.x_stride 10 \
                -difference.y_stride 10 -verbose 1 -GO.findoptcomp
        ) &
        ;;
    perl*)
        (
            cd ~/work/SPECCPU95INT/134.perl/data/train/input
            $QEMU -one-insn-per-tb -d plugin -plugin $PLUGIN "${BIN}" scrabbl.pl < scrabbl.in
        ) &
        ;;
    vortex*)
        (
            cd ~/work/SPECCPU95INT/147.vortex/data/train/input
            $QEMU -one-insn-per-tb -d plugin -plugin $PLUGIN "${BIN}" vortex.in.riscv
        ) &
        ;;
    *)
        echo "Unknown binary name: $BINNAME"
        exit 1
        ;;
    esac

    xz -T0 -9 -c "${TRACE_PATH}" | pv > "${TRACE_PATH}.xz" &

    wait

    rm -f ${TRACE_PATH}
else
    echo "\033[0;32mUsing existing trace files.\033[0m"
fi

ECS=$HOME/work/ecs-simulator/ecs

echo "\033[0;32mRunning ecs-simulator with:\033[1;37m\n ${MEM_STATE_PATH}\n ${REG_STATE_PATH}\n ${TRACE_PATH}.xz\033[0m"

xz -T0 -dc "${TRACE_PATH}.xz" | $ECS "${REG_STATE_PATH}" "${MEM_STATE_PATH}"

echo "\033[0;32mDone. Check the simulation result.\033[0m"

