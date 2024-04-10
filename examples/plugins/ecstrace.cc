#include "disas/riscv.h"
#include "qemu/qemu-plugin.h"

#include <assert.h>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <array>
#include <fstream>
#include <iostream>
#include <optional>
#include <tuple>
#include <utility>
#include <vector>

#define ERR(fmt, ...)                                                          \
    do {                                                                       \
        fprintf(stderr, "[%s:%-4d] \033[1;31m[  ERR]\033[0m " fmt "\n",        \
                __FILE__, __LINE__, ##__VA_ARGS__);                            \
        exit(1);                                                               \
    } while (0)
#define INFO(fmt, ...)                                                         \
    fprintf(stderr, "[%s:%-4d] \033[1;32m[ INFO]\033[0m " fmt "\n", __FILE__,  \
            __LINE__, ##__VA_ARGS__)
#define WARN(fmt, ...)                                                         \
    fprintf(stderr, "[%s:%-4d] \033[1;33m[ WARN]\033[0m " fmt "\n", __FILE__,  \
            __LINE__, ##__VA_ARGS__)
#define DEBUG(fmt, ...)                                                        \
    fprintf(stderr, "[%s:%-4d] \033[1;34m[DEBUG]\033[0m " fmt "\n", __FILE__,  \
            __LINE__, ##__VA_ARGS__)

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

struct InputOp { // 80 Bytes
    u64 ip;
    u64 next_ip;
    u8 reservedA[4] = {};
    u32 instruction_word;
    u8 logical_src_reg[4];
    u8 logical_dst_reg[2];
    u8 reservedB[2] = {};
    u64 src_value[4];
    u64 dst_value[2];
    u64 imm;
    u64 mem_addr;
    u64 mem_src_value;
    u64 mem_dst_value;

    InputOp(u64 ip, u64 next_ip, u32 instruction_word,
            std::array<u8, 4> src_reg, std::array<u8, 2> dst_reg,
            std::array<u64, 4> src_val, std::array<u64, 2> dst_val, u64 imm,
            u64 mem_addr, u64 mem_src_val, u64 mem_dst_val)
        : ip(ip), next_ip(next_ip), instruction_word(instruction_word),
          imm(imm), mem_addr(mem_addr), mem_src_value(mem_src_val),
          mem_dst_value(mem_dst_val) {
        for (int i = 0; i < 4; i++) {
            this->logical_src_reg[i] = src_reg[i];
            this->src_value[i] = src_val[i];
        }
        for (int i = 0; i < 2; i++) {
            this->logical_dst_reg[i] = dst_reg[i];
            this->dst_value[i] = dst_val[i];
        }
    }
};

class Ctx {
  public:
    Ctx() {
        const auto trace_path = std::getenv("TRACE_PATH");
        if (trace_path)
            INFO("Using trace path '%s'", trace_path);
        else
            WARN("TRACE_PATH not set, using default path 'output.trace'");
        this->trace_file.open(trace_path ? trace_path : "output.trace",
                              std::ios::binary);
        assert(this->trace_file.is_open());
        this->trace_file.write("RISC-V trace 0.0", 16);

        const auto entry_addr_str = std::getenv("TRACE_MAIN_ENTRY_ADDR");
        if (entry_addr_str) {
            this->entry_addr = std::stoull(entry_addr_str, nullptr, 16);
            this->trace_enabled = false;
            INFO("Using entry address 0x%lx", this->entry_addr);
        } else {
            this->trace_enabled = true;
            WARN("TRACE_MAIN_ENTRY_ADDR not set, tracing all instructions");
        }

        const auto skip_insns = std::getenv("SKIP_INSNS");
        if (skip_insns) {
            this->skip_first_n_insns_from_entry =
                std::stoull(skip_insns, nullptr, 10);
            INFO("Skipping first %lu insns from entry",
                 this->skip_first_n_insns_from_entry);
        }

        this->reg_buf = g_byte_array_new();
    }
    // NOTE: This destructor is not called on program exit.
    // ~Ctx() {
    //     this->trace_file.flush();
    //     this->trace_file.close();
    // }

    int bits;

    std::ofstream trace_file;
    std::ofstream mem_state_file;
    std::ofstream reg_state_file;

    const rv_decode *prev_insn = nullptr;
    std::optional<std::function<void(const rv_decode *next_insn)>>
        pending_trace = std::nullopt;

    uint64_t skip_first_n_insns_from_entry = 0;
    uint64_t num_insns_from_entry = 0;
    uint64_t entry_addr = 0, exit_addr = 0;
    bool trace_enabled = false;

    GByteArray *reg_buf;
};

static Ctx ctx;

//
// Utils for reading register values
// TODO: {csr,xpr,fpr}_val() should be merged into reg_val().
//

static uint64_t csr_val(const uint8_t reg) {
    const int n = qemu_plugin_read_register(ctx.reg_buf, reg + 0x20 + /*pc=*/1 +
                                                             0x20 + /*priv=*/1);
    int64_t ret;
    switch (n) {
    case 8:
        ret = *((int64_t *)ctx.reg_buf->data);
        break;
    default:
        ERR("Read bytes: %d. CSR must be 64 bits", n);
    }
    g_byte_array_set_size(ctx.reg_buf, 0);
    return ret;
}

static uint64_t xpr_val(const uint8_t reg) {
    assert(reg <= 0x20); // 0x20 for pc
    const int n = qemu_plugin_read_register(ctx.reg_buf, reg);
    uint64_t ret;
    switch (n) {
    case 4:
        ret = *((uint32_t *)ctx.reg_buf->data);
        break;
    case 8:
        ret = *((uint64_t *)ctx.reg_buf->data);
        break;
    default:
        ERR("Read bytes: %d. XPR must be 32 or 64 bits", n);
    }
    g_byte_array_set_size(ctx.reg_buf, 0);
    return ret;
}

static uint64_t fpr_val(const uint8_t reg) {
    assert(reg < 0x20);
    const int n =
        qemu_plugin_read_register(ctx.reg_buf, reg + 0x20 + /* pc = */ 1);
    uint64_t ret = 0;
    switch (n) {
    case 4:
        ret = *((uint32_t *)ctx.reg_buf->data);
        break;
    case 8:
        ret = *((uint64_t *)ctx.reg_buf->data);
        break;
    default:
        ERR("Read bytes: %d. FPR must be 32 or 64 bits", n);
    }
    g_byte_array_set_size(ctx.reg_buf, 0);
    return ret;
}

static u64 reg_val(const uint8_t reg) {
    // 0~31: XPR, 32~63: FPR, 64: PC
    assert(reg < 64);
    if (reg < 32)
        return xpr_val(reg);
    else if (reg == 64)
        return xpr_val(32);
    else
        return fpr_val(reg - 32);
}

//
// Utils for dumping memory/register state
//

static void dump_register_file() {
    if (!ctx.reg_state_file.is_open())
        return;

    const char header[16 + 1] = "RISC-V reg   0.0";
    ctx.reg_state_file.write((const char *)&header, 16);

    const uint64_t pc = xpr_val(/*pc=*/32);
    ctx.reg_state_file.write((const char *)&pc, sizeof(pc));

    // XPR 32 registers
    for (int i = 0; i < 32; i++) {
        uint64_t val = xpr_val(i);
        ctx.reg_state_file.write((const char *)&val, sizeof(val));
    }
    // FPR 32 registers
    for (int i = 0; i < 32; i++) {
        uint64_t val = fpr_val(i);
        ctx.reg_state_file.write((const char *)&val, sizeof(val));
    }

    const uint64_t x = 0; // TODO: csr_val(0) returns 0 bytes
    const uint64_t fflags = csr_val(1);
    const uint64_t frm = csr_val(2);
    ctx.reg_state_file.write((const char *)&x, sizeof(x));
    ctx.reg_state_file.write((const char *)&fflags, sizeof(fflags));
    ctx.reg_state_file.write((const char *)&frm, sizeof(frm));
}

static int walk_dump_memory(void *, uint64_t start, uint64_t end,
                            unsigned long protection) {
    if (!ctx.mem_state_file.is_open())
        return 0;

    const size_t page_size = 4096;
    struct Page {
        u64 addr;
        u8 data[page_size];
    };

    INFO("Dump memory region (0x%lx - 0x%lx)", start, end);
    if (!(protection & 0x1)) {
        WARN("Memory region is not readable");
        return 0;
    }
    const uint64_t size = end - start;
    uint8_t *buf = (uint8_t *)malloc(size);
    assert(qemu_plugin_read_memory(buf, start, size) == 0 &&
           "Failed to read memory");
    assert(size % page_size == 0);

    for (u64 addr = start; addr < end; addr += page_size) {
        Page page = {.addr = addr, .data = {}};
        memcpy(page.data, buf + (addr - start), page_size);
        ctx.mem_state_file.write((const char *)&page, sizeof(page));
    }

    free(buf);
    return 0;
}

static void dump_memory() {
    if (!ctx.mem_state_file.is_open())
        return;

    const char header[16 + 1] = "RISC-V mem   0.0";
    ctx.mem_state_file.write((const char *)&header, 16);
    qemu_plugin_walk_memory_regions(nullptr, walk_dump_memory);
}

static void dump_state() {
    assert(!ctx.mem_state_file.is_open() &&
           "Memory state file is already open");
    assert(!ctx.reg_state_file.is_open() &&
           "Register state file is already open");

    if (const auto path = std::getenv("MEM_STATE_PATH")) {
        INFO("Using memory state path '%s'", path);
        ctx.mem_state_file.open(path, std::ios::binary);
        assert(ctx.mem_state_file.is_open());
    } else {
        WARN("MEM_STATE_PATH not set, memory state will not be saved");
        return;
    }

    if (const auto path = std::getenv("REG_STATE_PATH")) {
        INFO("Using register state path '%s'", path);
        ctx.reg_state_file.open(path, std::ios::binary);
        assert(ctx.reg_state_file.is_open());
    } else {
        WARN("REG_STATE_PATH not set, register state will not be saved");
        return;
    }

    dump_register_file();
    dump_memory();

    ctx.mem_state_file.close();
    ctx.reg_state_file.close();
}

//
// Plugin callbacks
//

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index) {
    (void)(id);
    assert(vcpu_index == 0 && "Only one vCPU supported");

    {
        int num_reg_files;
        const qemu_plugin_register_file_t *reg_files =
            qemu_plugin_get_register_files(vcpu_index, &num_reg_files);
        // org.gnu.gdb.riscv.cpu
        // org.gnu.gdb.riscv.fpu
        // org.gnu.gdb.riscv.virtual
        // org.gnu.gdb.riscv.csr
        for (int i = 0; i < num_reg_files; i++) {
            const qemu_plugin_register_file_t *reg_file = &reg_files[i];
            DEBUG("%s (%d registers)", reg_file->name, reg_file->num_regs);
#if 0
        for (int k = 0; k < reg_file->num_regs; k++) {
            DEBUG("%d (%d) th register: %s", k, reg_file->base_reg + k,
                  reg_file->regs[k]);
        }
#endif
        }
    }
}

static void vcpu_insn_exec(unsigned int, void *udata) {
    // #define DBG(fmt, ...) DEBUG(fmt, ##__VA_ARGS__)
#define DBG(fmt, ...)                                                          \
    do {                                                                       \
    } while (0)

    const rv_decode *insn = (rv_decode *)udata;
    const bool is_compressed = (insn->inst & 0b11) != 0b11;

    if (insn->pc == ctx.entry_addr) {
        assert((ctx.prev_insn->op == rv_op_jal ||
                ctx.prev_insn->op == rv_op_jalr) &&
               "Entry address must be reached by call instruction");
        ctx.trace_enabled = true;
        ctx.exit_addr = ctx.prev_insn->pc + 4;
        INFO("Entry address (0x%lx) reached, enabling tracing", ctx.entry_addr);
        INFO("Setting exit address to 0x%lx", ctx.exit_addr);
        dump_state();
    }
    if (insn->pc == ctx.exit_addr) {
        INFO("Exit address (0x%lx) reached, disabling tracing", ctx.exit_addr);
        ctx.trace_enabled = false;
    }

    if (const auto trace =
            std::exchange(ctx.pending_trace, std::nullopt).value_or(nullptr)) {
        trace(insn);
    }

    ctx.prev_insn = insn;

    if (!ctx.trace_enabled)
        return;

    if (ctx.num_insns_from_entry++ < ctx.skip_first_n_insns_from_entry)
        return;

    if (is_compressed) {
        ERR("Compressed instruction is not supported");
    }

    assert((insn->codec != rv_codec_r2_immhl &&
            insn->codec != rv_codec_r2_imm2_imm5) &&
           "insn->imm1 must be zero");

    u8 off_rd = 0, off_rs1 = 0, off_rs2 = 0, off_rs3 = 0;
    u64 mem_addr = 0, mem_dst_val = 0;
    bool need_mem_src_val = false;

    // clang-format off
    switch (insn->inst & 0x7f) {
    case 0b1110011: // ECALL/CSR
    {
        const int funct3 = (insn->inst >> 12) & 0x07;
        switch (funct3) {
        case 0b000:
            std::array<u64, 64> cur_xpr_fpr;
            for (int i = 0; i < 64; i++) cur_xpr_fpr[i] = reg_val(i);
            ctx.pending_trace = [=](const rv_decode *next_insn) {
                u8 changed_reg = 0;
                for (int i = 0; i < 64; i++) {
                    u64 new_xpr_fpr = reg_val(i);
                    if (cur_xpr_fpr[i] != new_xpr_fpr) {
                        assert(changed_reg == 0 && "Only one register should be modified");
                        changed_reg = i;
                    }
                }
                const auto pc = insn->pc;
                const auto npc = next_insn ? next_insn->pc : 0;
                u64 changed_val = reg_val(changed_reg);
                InputOp op(pc, npc, insn->inst, {0, 0, 0, 0}, {changed_reg, 0},
                           {0, 0, 0, 0}, {changed_val, 0}, 0, 0, 0, 0);
                ctx.trace_file.write((const char *)&op, sizeof(op));
            };
            break;
        default:
            ERR("Unknown csr/ecall: 0x%lx (%lb)", insn->inst, insn->inst & 0x7f);
        }
    } break;
    case 0x37: // LUI
    case 0x17: // AUIPC
        break;
    case 0x1b: // IntALU(rd,rs1,imm) (e.g., slliw in RV64I)
    case 0x13:
        break;
    case 0x33:
    case 0x3b: // (e.g., addw in RV64I)
        break;
    case 0b0000011: // Load
        mem_addr = reg_val(insn->rs1) + insn->imm;
        need_mem_src_val = true;
        break;
    case 0b1101111: // JAL
    case 0b1100111: // JALR
    case 0b1100011: // BRcc
        break;
    case 0b0100011: // Store
    {
        mem_addr = reg_val(insn->rs1) + insn->imm;
        mem_dst_val = xpr_val(insn->rs2);
        const uint64_t funct3 = (insn->inst >> 12) & 0x07;
        switch (funct3) {
        case 0b000: mem_dst_val = mem_dst_val & 0xff;       break; // SB
        case 0b001: mem_dst_val = mem_dst_val & 0xffff;     break; // SH
        case 0b010: mem_dst_val = mem_dst_val & 0xffffffff; break; // SW
        case 0b011:                                         break; // SD
        default: ERR("Unknown funct3: 0x%lx", funct3);
        }
    } break;
    case 0b0000111: // FpLoad
        off_rd = 32;
        mem_addr = reg_val(insn->rs1) + insn->imm;
        need_mem_src_val = true;
        break;
    case 0b0100111: // FpStore
    {
        off_rs2 = 32;
        mem_addr = reg_val(insn->rs1) + insn->imm;
        mem_dst_val = fpr_val(insn->rs2);
        const uint64_t funct3 = (insn->inst >> 12) & 0x07;
        switch (funct3) {
        case 0b010: mem_dst_val = mem_dst_val & 0xffffffff; break; // FSW
        case 0b011:                                         break; // FSD
        default: ERR("Unknown funct3: 0x%lx", funct3);
        }
    } break;
    case 0b1000011: // FMADD.S
    case 0b1000111: // FMSUB.S
    case 0b1001011: // FNMSUB.S
    case 0b1001111: // FNMADD.S
        off_rs1 = off_rs2 = off_rs3 = off_rd = 32; // rs1:f,rs2:f,rs3:f,rd:f
        break;
    case 0b1010011: // FpInst
    {
        const uint64_t funct5 = (insn->inst >> 25) & 0x7f;
        switch (funct5) {
            case 0b0010000: case 0b0010001: // FSGNJ.S, FSGNJN.S, FSGNJX.S, FSGNJ.D, FSGNJN.D, FSGNJX.D
            case 0b0101100: case 0b0101101: // FSQRT.D, FSQRT.S
            case 0b0100000: case 0b0100001: // FCVT.S.D, FCVT.D.S
                off_rs1 = off_rd = 32; // rs1:f,rd:f
                break;
            case 0b1100000: // FCVT.L.S, FCVT.LU.S, FCVT.W.S, FCVT.WU.S
            case 0b1100001: // FCVT.W.D, FCVT.WU.D, FCVT.L.D, FCVT.LU.D
            case 0b1110000: case 0b1110001: // FMV.X.W, FCLASS.S, FMV.X.D, FCLASS.D
                off_rs1 = 32; // rs1:f,rd:x
                break;
            case 0b0000000: case 0b0000001: // FADD.S, FADD.D
            case 0b0000100: case 0b0000101: // FSUB.S, FSUB.D
            case 0b0001000: case 0b0001001: // FMUL.S, FMUL.D
            case 0b0001100: case 0b0001101: // FDIV.S, FDIV.D
                off_rs1 = off_rs2 = off_rd = 32; // rs1:f,rs2:f,rd:f
                break;
            case 0b1101000: // FCVT.S.L, FCVT.S.LU, FCVT.S.W, FCVT.S.WU
            case 0b1101001: // FCVT.D.W, FCVT.D.WU, FCVT.D.L, FCVT.D.LU
            case 0b1111000: // FMV.W.X
            case 0b1111001: // FMV.D.X
                off_rd = 32; // rs1:x,rd:f
                break;
            case 0b1010001: // FEQ.D, FLT.D, FLE.D
                off_rs1 = off_rs2 = 32; // rs1:f,rs2:f,rd:x
                break;
            default:
                ERR("Unknown funct5: %07lb", funct5);
        }
        break;
    }
    default: ERR("Unknown opcode: 0x%lx (%lb)", insn->inst, insn->inst & 0x7f);
    }
    // clang-format off

    const u8 rd = insn->rd + off_rd, rs1 = insn->rs1 + off_rs1,
       rs2 = insn->rs2 + off_rs2, rs3 = insn->rs3 + off_rs3;
    const u64 rs1_val = reg_val(rs1), rs2_val = reg_val(rs2), rs3_val = reg_val(rs3);

    ctx.pending_trace = [=](const rv_decode *next_insn) {
        const auto pc = insn->pc;
        const auto npc = next_insn ? next_insn->pc : 0;
        DBG("OP: rd = %d, rs1 = %d, rs2 = %d, r3 = %d, imm = 0x%x %d", rd, rs1,
            rs2, rs3, insn->imm, insn->op);
        u64 dst_val = reg_val(rd);
        u64 mem_src_val = need_mem_src_val ? dst_val : 0;
        InputOp op(pc, npc, insn->inst, {rs1, rs2, rs3, 0}, {rd, 0},
                   {rs1_val, rs2_val, rs3_val, 0}, {dst_val, 0},
                   (u64)insn->imm, mem_addr, mem_src_val, mem_dst_val);
        ctx.trace_file.write((const char *)&op, sizeof(op));
    };

#undef DBG
}

/**
 * On translation block new translation
 *
 * QEMU convert code by translation block (TB). By hooking here we can then hook
 * a callback on each instruction and memory access.
 */
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    (void)(id);
    struct qemu_plugin_insn *insn;

    const size_t n = qemu_plugin_tb_n_insns(tb);
    assert(n == 1 &&
           "TB must contain only one instruction. Otherwise, incorrect values "
           "will be read from registers. Did you forget to use "
           "-one-instr-per-tb?");

    for (size_t i = 0; i < n; i++) {
        /*
         * `insn` is shared between translations in QEMU, copy needed data here.
         * `output` is never freed as it might be used multiple times during
         * the emulation lifetime.
         * We only consider the first 32 bits of the instruction, this may be
         * a limitation for CISC architectures.
         */
        insn = qemu_plugin_tb_get_insn(tb, i);

        // NOTE: We will never free `dec`.
        rv_decode *dec = (rv_decode *)malloc(sizeof(rv_decode));
        qemu_plugin_insn_decode(insn, dec);
#if 0
    DEBUG("Disas: %s", qemu_plugin_insn_disas(insn));
#endif

        /* Register callback on instruction */
        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                               QEMU_PLUGIN_CB_R_REGS, dec);
    }
}

/**
 * On plugin exit, print last instruction in cache
 */
static void plugin_exit(qemu_plugin_id_t, void *) {
    if (const auto trace =
            std::exchange(ctx.pending_trace, std::nullopt).value_or(nullptr)) {
        trace(nullptr);
    }

    ctx.trace_file.close();
}

extern "C" {
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv) {
    (void)(argc);
    (void)(argv);
    assert(!info->system_emulation && "System emulation not supported");

    INFO("Target name: %s", info->target_name);
    assert(strcmp(info->target_name, "riscv64") == 0 ||
           strcmp(info->target_name, "riscv32") == 0);
    ctx.bits = strcmp(info->target_name, "riscv64") == 0 ? 64 : 32;

    // Register translation block and exit callbacks
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
};
