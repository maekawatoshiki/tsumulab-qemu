#include "../../disas/riscv.h"
#include "../../include/qemu/qemu-plugin.h"

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

#include <fstream>
#include <iostream>
#include <optional>
#include <tuple>
#include <utility>
#include <vector>

#define ERR(fmt, ...)                                                          \
    fprintf(stderr, "[%s:%-4d] \033[1;31m[  ERR]\033[0m " fmt "\n", __FILE__,  \
            __LINE__, ##__VA_ARGS__)
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

struct InputOp {
    u64 ip;
    u32 instruction_word;
    u8 logical_dst_reg; // FIXME: DecodedOpComponentとするべき
    u8 logical_src1_reg;
    u8 logical_src2_reg;
    bool is_wrong_path_instruction;
    u64 imm;
    u64 result;
    u64 address;
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

        const auto entry_addr_str = std::getenv("TRACE_MAIN_ENTRY_ADDR");
        if (entry_addr_str) {
            this->entry_addr = std::stoull(entry_addr_str, nullptr, 16);
            this->trace_enabled = false;
            INFO("Using entry address 0x%lx", this->entry_addr);
        } else {
            this->trace_enabled = true;
            WARN("TRACE_MAIN_ENTRY_ADDR or TRACE_MAIN_EXIT_ADDR"
                 " not set, tracing all instructions");
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

    std::vector<uint8_t> trace_bytes;
    std::ofstream trace_file;

    std::ofstream state_dump_file;

    const rv_decode *prev_insn = nullptr;
    std::optional<std::function<void(const rv_decode *next_insn)>>
        pending_trace = std::nullopt;

    uint64_t skip_first_n_insns_from_entry = 0;
    uint64_t num_insns_from_entry = 0;
    uint64_t entry_addr = 0, exit_addr = 0;
    bool trace_enabled = false;
    bool trace_started = false;

    GByteArray *reg_buf;

    template <typename T> void write(const T &data) {
        if (this->trace_bytes.size() > 100 * 1024 * 1024) {
            this->flush();
        }
        this->trace_bytes.insert(this->trace_bytes.end(), (const char *)&data,
                                 (const char *)&data + sizeof(T));
    }

    void flush() {
        this->trace_file.write((const char *)this->trace_bytes.data(),
                               this->trace_bytes.size());
        this->trace_file.flush();
        this->trace_bytes.clear();
    }
};

static Ctx ctx;

static int dump_memory_region(void *priv, uint64_t start, uint64_t end,
                              unsigned long protection) {
    (void)(priv);
    if (!ctx.state_dump_file.is_open())
        return 0;

    INFO("Dump memory region (0x%lx - 0x%lx)", start, end);
    if (!(protection & 0x1)) {
        WARN("Memory region is not readable");
        return 0;
    }
    const uint64_t size = end - start;
    uint8_t *buf = (uint8_t *)malloc(size);
    assert(qemu_plugin_read_memory(buf, start, size) == 0 &&
           "Failed to read memory");

    ctx.state_dump_file.write((const char *)&start, sizeof(start));
    ctx.state_dump_file.write((const char *)&end, sizeof(end));
    ctx.state_dump_file.write((const char *)buf, size);

    free(buf);
    return 0;
}

static void dump_register_file() {
    int num_reg_files;
    const qemu_plugin_register_file_t *reg_files =
        qemu_plugin_get_register_files(0, &num_reg_files);

    for (int i = 0; i < num_reg_files; i++) {
        const qemu_plugin_register_file_t *reg_file = &reg_files[i];
        DEBUG("base_reg = %d, num_regs = %d", reg_file->base_reg,
              reg_file->num_regs);
        for (int k = 0; k < reg_file->num_regs; k++) {
            const int n =
                qemu_plugin_read_register(ctx.reg_buf, reg_file->base_reg + k);
            if (n == 4) {
                const int32_t val = *((int32_t *)ctx.reg_buf->data);
                DEBUG("Register %s (%d): 0x%x", reg_file->regs[k],
                      reg_file->base_reg + k, val);
            } else if (n == 8) {
                const int64_t val = *((int64_t *)ctx.reg_buf->data);
                DEBUG("Register %s (%d): 0x%lx", reg_file->regs[k],
                      reg_file->base_reg + k, val);
            } else {
                ERR("Register %s (%d): %d bytes", reg_file->regs[k],
                    reg_file->base_reg + k, n);
                // assert(false && "Register must be 32 or 64 bits");
            }
            g_byte_array_set_size(ctx.reg_buf, 0);
        }
    }
}

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

static int64_t xpr_val(const uint8_t reg) {
    assert(reg < 0x20);
    const int n = qemu_plugin_read_register(ctx.reg_buf, reg);
    int64_t ret;
    switch (n) {
    case 4:
        ret = *((int32_t *)ctx.reg_buf->data);
        break;
    case 8:
        ret = *((int64_t *)ctx.reg_buf->data);
        break;
    default:
        ERR("Read bytes: %d", n);
        assert(false && "XPR must be 32 or 64 bits");
    }
    g_byte_array_set_size(ctx.reg_buf, 0);
    return ret;
}

static uint64_t fpr_val(const uint8_t reg) {
    assert(reg < 0x20);
    const int n =
        qemu_plugin_read_register(ctx.reg_buf, reg + 0x20 + /* pc = */ 1);
    uint64_t ret;
    switch (n) {
    case 4:
        ret = *((uint32_t *)ctx.reg_buf->data);
        break;
    case 8:
        ret = *((uint64_t *)ctx.reg_buf->data);
        break;
    default:
        ERR("Read bytes: %d", n);
        assert(false && "FPR must be 32 or 64 bits");
    }
    g_byte_array_set_size(ctx.reg_buf, 0);
    return ret;
}

static void vcpu_insn_exec(unsigned int cpu_index, void *udata) {
    (void)(cpu_index);
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

        if (!ctx.state_dump_file.is_open()) {
            const auto dump_path = std::getenv("STATE_DUMP_PATH");
            if (dump_path) {
                INFO("Using state dump path '%s'", dump_path);
                ctx.state_dump_file.open(dump_path, std::ios::binary);
                assert(ctx.state_dump_file.is_open());
            } else {
                WARN("STATE_DUMP_PATH not set, state dump will not be saved");
            }
        }
        dump_register_file();
        qemu_plugin_walk_memory_regions(nullptr, dump_memory_region);
        if (ctx.state_dump_file.is_open())
            ctx.state_dump_file.close();
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

#if 0
DEBUG("opcode = 0x%lx", insn->inst);
#endif

    if (is_compressed) {
        ERR("Compressed instruction is not supported");
        assert(false && "Compressed instruction is not supported");
    }

    const uint64_t opcode = insn->inst & 0x7f;

    assert((insn->codec != rv_codec_r2_immhl &&
            insn->codec != rv_codec_r2_imm2_imm5) &&
           "insn->imm1 must be zero");

// #define DBG(fmt, ...) DEBUG(fmt, ##__VA_ARGS__)
#define DBG(fmt, ...)                                                          \
    do {                                                                       \
    } while (0)

    switch (opcode) {
    case 0b0110011: // ALU64
    case 0b0011011: // ALU32Imm
    case 0b0010011: // ALU64Imm
    case 0b0110111: // LUi
    case 0b0010111: // AUiPC
        ctx.pending_trace = [insn](const rv_decode *) {
            u64 dst = xpr_val(insn->rd);
            InputOp op = {
                insn->pc, (uint32_t)insn->inst, insn->rd, insn->rs1, insn->rs2,
                false,    (u64)insn->imm,       dst,      0};
            DBG("Int: rd = %d, rs1 = %d, rs2 = %d, imm = 0x%x, val = 0x%lx",
                insn->rd, insn->rs1, insn->rs2, insn->imm, dst);
            ctx.write(op);
        };
        break;
    case 0b1101111: // JAL
    case 0b1100111: // JALR
    case 0b1100011: // BRcc
        ctx.pending_trace = [insn](const rv_decode *next_insn) {
            const auto pc = insn->pc;
            const auto npc = next_insn->pc;
            const auto taken = pc + 4 != npc;
            u64 dst = xpr_val(insn->rd);
            InputOp op = {
                insn->pc, (uint32_t)insn->inst, insn->rd, insn->rs1, insn->rs2,
                false,    (u64)insn->imm,       dst,      0};
            DBG("Branch: rd = %d, rs1 = %d, rs2 = %d, imm = 0x%x", insn->rd,
                insn->rs1, insn->rs2, insn->imm);
            ctx.write(op);
        };
        break;
    case 0b0100011: // Store
    {
        u64 addr = xpr_val(insn->rs1) + insn->imm;
        ctx.pending_trace = [insn, addr](const rv_decode *) {
            InputOp op = {
                insn->pc, (uint32_t)insn->inst, insn->rd, insn->rs1, insn->rs2,
                false,    (u64)insn->imm,       0,        addr};
            DBG("Store: rd = %d, rs1 = %d, rs2 = %d, imm = 0x%x, addr = "
                "0x%lx, val = 0x%lx",
                insn->rd, insn->rs1, insn->rs2, insn->imm, addr,
                xpr_val(insn->rd));
            ctx.write(op);
        };
    } break;
    case 0b0000011: // Load
    {
        u64 addr = xpr_val(insn->rs1) + insn->imm;
        DBG("Load: rs1 val = 0x%lx, imm = 0x%x, addr = 0x%lx",
            xpr_val(insn->rs1), insn->imm, addr);
        ctx.pending_trace = [insn, addr](const rv_decode *) {
            InputOp op = {insn->pc,
                          (uint32_t)insn->inst,
                          insn->rd,
                          insn->rs1,
                          insn->rs2,
                          false,
                          (u64)insn->imm,
                          (u64)xpr_val(insn->rd),
                          addr};
            DBG("Load: rd = %d, rs1 = %d, rs2 = %d, imm = 0x%x, addr = 0x%lx",
                insn->rd, insn->rs1, insn->rs2, insn->imm, addr);
            ctx.write(op);
        };
    } break;
    default:
        ctx.pending_trace = [insn](const rv_decode *) {
            InputOp op = {
                insn->pc, (uint32_t)insn->inst, insn->rd, insn->rs1, insn->rs2,
                false,    (u64)insn->imm,       0,        0};
            DBG("Unknown: rd = %d, rs1 = %d, rs2 = %d, imm = 0x%x", insn->rd,
                insn->rs1, insn->rs2, insn->imm);
            ctx.write(op);
        };
        break;
    }

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
static void plugin_exit(qemu_plugin_id_t id, void *p) {
    (void)(id);
    (void)(p);
    if (const auto trace =
            std::exchange(ctx.pending_trace, std::nullopt).value_or(nullptr)) {
        trace(nullptr);
    }

    ctx.flush();
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
    ctx.bits = strcmp(info->target_name, "riscv64") == 0 ? 64 : 32;

    // Register translation block and exit callbacks
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
};
