#include "../../disas/riscv.h"
#include "../../include/qemu/qemu-plugin.h"

#include <assert.h>
#include <cstdlib>
#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <optional>
#include <tuple>
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

        // TODO: The prefix 'SPIKE_' is not appropriate.
        const auto entry_addr_str = std::getenv("SPIKE_MAIN_ENTRY_ADDR");
        const auto exit_addr_str = std::getenv("SPIKE_MAIN_EXIT_ADDR");
        if (entry_addr_str && exit_addr_str) {
            this->entry_addr = std::stoull(entry_addr_str, nullptr, 16);
            this->exit_addr = std::stoull(exit_addr_str, nullptr, 16);
            this->trace_enabled = false;
            INFO("Using entry address 0x%lx", this->entry_addr);
            INFO("Using exit address 0x%lx", this->exit_addr);
        } else {
            this->trace_enabled = true;
            WARN("SPIKE_MAIN_ENTRY_ADDR or SPIKE_MAIN_EXIT_ADDR"
                 " not set, tracing all instructions");
        }

        this->reg_buf = g_byte_array_new();
    }
    // NOTE: This destructor is not called on program exit.
    // ~Ctx() {
    //     this->trace_file.flush();
    //     this->trace_file.close();
    // }

    std::vector<uint8_t> trace_bytes;
    std::ofstream trace_file;
    GByteArray *reg_buf;
    std::optional<const rv_decode *> pending_insn = std::nullopt;
    uint64_t entry_addr = 0, exit_addr = 0;
    bool trace_enabled = false;

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

static void trace_alu(const uint8_t inst_type, const uint64_t pc,
                      const std::vector<uint64_t> &input_regs, const uint8_t rd,
                      const uint64_t val) {
    assert(inst_type == 0 || inst_type == 6 || inst_type == 7);
    uint8_t num_input_regs = input_regs.size();
    uint8_t num_output_regs = 1;
    ctx.write(pc);
    ctx.write(inst_type);
    ctx.write(num_input_regs);
    for (int i = 0; i < num_input_regs; i++) {
        assert(input_regs[i] < 0x40);
        ctx.write((uint8_t)input_regs[i]);
    }
    ctx.write(num_output_regs);
    assert(rd < 0x40);
    ctx.write(rd);
    if (rd < 0x20) { // int reg
        ctx.write(val);
    } else { // fp reg
        ctx.write(val);
        uint64_t zero = 0;
        ctx.write(zero);
    }
}

static void trace_load(const uint64_t pc, uint64_t effective_addr,
                       const uint8_t access_size,
                       const std::vector<uint64_t> &input_regs,
                       const uint8_t rd, const uint64_t val) {
    uint8_t inst_type = 1;
    uint8_t num_input_regs = input_regs.size();
    uint8_t num_output_regs = 1;
    ctx.write(pc);
    ctx.write(inst_type);
    ctx.write(effective_addr);
    ctx.write(access_size);
    ctx.write(num_input_regs);
    for (int i = 0; i < num_input_regs; i++) {
        assert(input_regs[i] < 0x40);
        ctx.write((uint8_t)input_regs[i]);
    }
    ctx.write(num_output_regs);
    assert(rd < 0x40);
    ctx.write(rd);
    if (rd < 0x20) { // int reg
        ctx.write(val);
    } else { // fp reg
        ctx.write(val);
        uint64_t zero = 0;
        ctx.write(zero);
    }
}

static void trace_amo(const uint64_t pc, uint64_t effective_addr,
                      const uint8_t access_size,
                      const std::vector<uint64_t> &input_regs, const uint8_t rd,
                      const uint64_t val) {
    uint8_t inst_type = 0xd; // amoInstClass
    uint8_t num_input_regs = input_regs.size();
    uint8_t num_output_regs = 1;
    ctx.write(pc);
    ctx.write(inst_type);
    ctx.write(effective_addr);
    ctx.write(access_size);
    ctx.write(num_input_regs);
    for (int i = 0; i < num_input_regs; i++) {
        assert(input_regs[i] < 0x40);
        ctx.write((uint8_t)input_regs[i]);
    }
    ctx.write(num_output_regs);
    assert(rd < 0x40);
    ctx.write(rd);
    if (rd < 0x20) { // int reg
        ctx.write(val);
    } else { // fp reg
        ctx.write(val);
        uint64_t zero = 0;
        ctx.write(zero);
    }
}

static void
trace_br(const uint8_t inst_type, const uint64_t pc, const uint8_t taken,
         const uint64_t npc, const std::vector<uint64_t> &input_regs,
         const std::vector<std::pair<uint8_t, uint64_t>> &output_regs) {
    assert(inst_type == 3 || inst_type == 4 || inst_type == 5 ||
           inst_type == 9 || inst_type == 0xa);
    uint8_t num_input_regs = input_regs.size();
    uint8_t num_output_regs = output_regs.size();
    ctx.write(pc);
    ctx.write(inst_type);
    ctx.write(taken);
    if (taken) {
        ctx.write(npc);
    }
    ctx.write(num_input_regs);
    for (int i = 0; i < num_input_regs; i++) {
        assert(input_regs[i] < 0x40);
        ctx.write((uint8_t)input_regs[i]);
    }
    ctx.write(num_output_regs);
    for (int i = 0; i < num_output_regs; i++) {
        const uint8_t rd = output_regs[i].first;
        const uint64_t val = output_regs[i].second;
        assert(rd < 0x40);
        ctx.write(rd);
        if (rd < 0x20) { // int reg
            ctx.write(val);
        } else { // fp reg
            assert(false && "Not implemented: fp reg");
        }
    }
}

static void trace_store(const uint64_t pc, uint64_t effective_addr,
                        const uint8_t access_size,
                        const std::vector<uint64_t> &input_regs) {
    uint8_t inst_type = 2;
    uint8_t num_input_regs = input_regs.size();
    uint8_t num_output_regs = 0;
    ctx.write(pc);
    ctx.write(inst_type);
    ctx.write(effective_addr);
    ctx.write(access_size);
    ctx.write(num_input_regs);
    for (int i = 0; i < num_input_regs; i++) {
        assert((uint8_t)input_regs[i] < 0x40);
        ctx.write((uint8_t)input_regs[i]);
    }
    ctx.write(num_output_regs);
}

static void trace_simple(const uint8_t inst_type, const uint64_t pc) {
    assert(inst_type == 0xb || inst_type == 0xc || inst_type == 0x7);
    uint8_t num_input_regs = 0;
    uint8_t num_output_regs = 0;
    ctx.write(pc);
    ctx.write(inst_type);
    ctx.write(num_input_regs);
    ctx.write(num_output_regs);
}

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index) {
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

static int32_t xpr_val(const uint8_t reg) {
    assert(reg < 0x20);
    const int n = qemu_plugin_read_register(ctx.reg_buf, reg);
    assert(n == 4 && "RV32 support only for now");
    const auto ret = *((int32_t *)ctx.reg_buf->data);
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
        assert(false && "FPR must 32 or 64 bits");
    }
    g_byte_array_set_size(ctx.reg_buf, 0);
    return ret;
}

static void vcpu_insn_exec(unsigned int cpu_index, void *udata) {
    const rv_decode *next_insn = (rv_decode *)udata;

    if (next_insn->pc == ctx.entry_addr) {
        INFO("Entry address (%lx) reached, enabling tracing", ctx.entry_addr);
        ctx.trace_enabled = true;
    }
    if (next_insn->pc == ctx.exit_addr) {
        INFO("Exit address (%lx) reached, disabling tracing", ctx.exit_addr);
        ctx.trace_enabled = false;
    }
    if (!ctx.trace_enabled)
        return;

    const rv_decode *insn = ctx.pending_insn.value_or(nullptr);
    ctx.pending_insn = next_insn;
    if (insn == nullptr)
        return;

#if 0
    DEBUG("opcode = 0x%lx", insn->inst);
#endif

    const uint64_t opcode = insn->inst & 0x7f;
    const uint64_t alusize = (insn->inst >> 12) & 0x07;
    const uint64_t alutype = (insn->inst >> 25) & 0x7f;

    assert((insn->codec != rv_codec_r2_immhl &&
            insn->codec != rv_codec_r2_imm2_imm5) &&
           "insn->imm1 must be zero");

    switch (opcode) {
    case 0x37:
    case 0x17: {
        // aluInstClass(lui, auipc)
        trace_alu(0, insn->pc, {}, insn->rd, xpr_val(insn->rd));
        break;
    }
    case 0x13: // aluInstClass(alu(immediate))
        trace_alu(0, insn->pc, {insn->rs1}, insn->rd, xpr_val(insn->rd));
        break;
    case 0x33:
        if (alutype == 0x00 || alutype == 0x20) {
            // aluInstClass(alu)
            trace_alu(0, insn->pc, {insn->rs1, insn->rs2}, insn->rd,
                      xpr_val(insn->rd));
        } else if (alutype == 0x01) {
            // slowAluInstClass
            trace_alu(7, insn->pc, {insn->rs1, insn->rs1}, insn->rd,
                      xpr_val(insn->rd));
        }
        break;
    case 0x03: {
        const uint64_t effaddr = xpr_val(insn->rs1) + insn->imm;
        if (alusize == 0x00 || alusize == 0x04) {
            // loadInstClass(b,ub)
            trace_load(insn->pc, effaddr, 1, {insn->rs1}, insn->rd,
                       xpr_val(insn->rd));
        } else if (alusize == 0x01 || alusize == 0x05) {
            // loadInstClass(h,uh)
            trace_load(insn->pc, effaddr, 2, {insn->rs1}, insn->rd,
                       xpr_val(insn->rd));
        } else if (alusize == 0x02) {
            // loadInstClass(w)
            trace_load(insn->pc, effaddr, 4, {insn->rs1}, insn->rd,
                       xpr_val(insn->rd));
        } else if (alusize == 0x03) {
            // loadInstClass(d)
            trace_load(insn->pc, effaddr, 8, {insn->rs1}, insn->rd,
                       xpr_val(insn->rd));
        }
        break;
    }
    case 0x2f: { // Atomic operations
        assert(0 <= alusize && alusize <= 3);
        const uint8_t funct5 = alutype >> 2;
        const uint8_t access_size = 1 << alusize;
#if 0
        DEBUG("funct5 = %x", funct5);
        DEBUG("access_size = %d", access_size);
#endif
        switch (funct5) {
        case 0b00000: // amoadd.*
        case 0b11100: // amomaxu.*
        case 0b00001: // amoswap.*
            trace_amo(insn->pc, xpr_val(insn->rs1), access_size,
                      {insn->rs1, insn->rs2}, insn->rd, xpr_val(insn->rd));
            break;
        case 0b00010: {
            // lr.*
            // TODO: Currently we ignore reservation.
            trace_load(insn->pc, xpr_val(insn->rs1), access_size, {insn->rs1},
                       insn->rd, xpr_val(insn->rd));
            break;
        }
        case 0b00011: {
            // sc.*
            // TODO: Currently we ignore reservation.
            trace_store(insn->pc, xpr_val(insn->rs1), access_size,
                        {insn->rs1, insn->rs2});
            trace_alu(0, insn->pc, {}, insn->rd, xpr_val(insn->rd));
            break;
        }
        default:
            ERR("Unknown atomic operation: 0x%lx (0x%x)", insn->inst, insn->op);
            assert(false && "Unknown opcode");
            break;
        }
        break;
    }
    case 0x07: {
        const uint64_t effaddr = xpr_val(insn->rs1) + insn->imm;
        if (alusize == 0x02) {
            // fpload(rs1:x,rd:f,w)
            trace_load(insn->pc, effaddr, 4, {insn->rs1}, insn->rd + 0x20u,
                       fpr_val(insn->rd));
        } else if (alusize == 0x03) {
            // fpload(rs1:x,rd:f,d)
            trace_load(insn->pc, effaddr, 8, {insn->rs1}, insn->rd + 0x20u,
                       fpr_val(insn->rd));
        }
        break;
    }
    case 0x23: {
        const uint64_t effaddr = xpr_val(insn->rs1) + insn->imm;
        if (alusize == 0x00 || alusize == 0x04) {
            // storeInstClass(b,ub)
            trace_store(insn->pc, effaddr, 1, {insn->rs1, insn->rs2});
        } else if (alusize == 0x01 || alusize == 0x05) {
            // storeInstClass(h,uh)
            trace_store(insn->pc, effaddr, 2, {insn->rs1, insn->rs2});
        } else if (alusize == 0x02) {
            // storeInstClass(w)
            trace_store(insn->pc, effaddr, 4, {insn->rs1, insn->rs2});
        } else if (alusize == 0x03) {
            // storeInstClass(d)
            trace_store(insn->pc, effaddr, 8, {insn->rs1, insn->rs2});
        }
        break;
    }
    case 0x27: {
        const uint64_t effaddr = xpr_val(insn->rs1) + insn->imm;
        if (alusize == 0x02) {
            // fpstore(rs1:x, rs2:f, w)
            trace_store(insn->pc, effaddr, 4, {insn->rs1, insn->rs2 + 0x20u});
        } else if (alusize == 0x03) {
            // fpstore(rs1:x, rs2:f, d)
            trace_store(insn->pc, effaddr, 8, {insn->rs1, insn->rs2 + 0x20u});
        }
        break;
    }
    case 0x63: {
        const auto pc = insn->pc;
        const auto npc = next_insn->pc;
        const auto taken = pc + 4 != npc;
        trace_br(3, pc, taken, npc, {}, {});
        break;
    }
    case 0x6f: {
        const auto pc = insn->pc;
        const auto npc = next_insn->pc;
        if (insn->rd == /* ra = */ 0x01) {
            trace_br(9, pc, true, npc, {}, {{1, xpr_val(1)}});
        } else if (insn->rd == 0x00) {
            trace_br(4, pc, true, npc, {}, {});
        }
        break;
    }
    case 0x67: {
        const auto pc = insn->pc;
        const auto npc = next_insn->pc;
        if (insn->rd == 0 && insn->rs1 == 1 && insn->imm == 0) {
            // retClass
            trace_br(0xa, pc, true, npc, {1}, {});
        } else {
            // uncondIndirectBranchInstClass
            trace_br(5, pc, true, npc, {insn->rs1},
                     {{insn->rd, xpr_val(insn->rd)}});
        }
        break;
    }
    case 0x53:
        if (alutype == 0x2c || alutype == 0x2d || alutype == 0x20 ||
            alutype == 0x22) {
            // fpInstClass(rs1:f,rd:f)
            trace_alu(6, insn->pc, {insn->rs1 + 0x20u}, insn->rd + 0x20u,
                      fpr_val(insn->rd));
        } else if (alutype == 0x60 || alutype == 0x70 || alutype == 0x61 ||
                   alutype == 0x71) {
            // fpInstClass(rs1:f,rd:x)
            trace_alu(6, insn->pc, {insn->rs1 + 0x20u}, insn->rd,
                      xpr_val(insn->rd));
        } else if (alutype == 0x2c || alutype == 0x2d || alutype == 0x20 ||
                   alutype == 0x21) {
            // fpInstClass(rs1:x,rd:f)
            trace_alu(6, insn->pc, {insn->rs1}, insn->rd + 0x20u,
                      fpr_val(insn->rd));
        } else if (alutype <= 0x3f) {
            // fpInstClass(rs1:f,rs2:f,rd:f) (arith)
            trace_alu(6, insn->pc, {insn->rs1 + 0x20u, insn->rs2 + 0x20u},
                      insn->rd + 0x20u, fpr_val(insn->rd));
        } else if (alutype >= 0x40) {
            // fpInstClass(rs1:f,rs2:f,rd:x) (cmp)
            trace_alu(6, insn->pc, {insn->rs1 + 0x20u, insn->rs2 + 0x20u},
                      insn->rd, xpr_val(insn->rd));
        }
        break;
    case 0x43:
    case 0x47:
    case 0x4b:
    case 0x4f:
        // fpInstClass(rs1:f,rs2:f,rs3:f,rd:f)
        trace_alu(6, insn->pc, {insn->rs1, insn->rs2, insn->rs3}, insn->rd,
                  xpr_val(insn->rd));
        break;
    case 0x73:
        if (insn->inst == 0x10200073) {
            // sretInstClass
            assert(false);
        } else if (alusize == 0) {
            // slowAluInstClass // fence ecall/break
            trace_simple(7, insn->pc);
        } else if (alusize >= 1) {
            // csrInstClass
            trace_simple(0xb, insn->pc);
        }
        break;
    case 0x0f:
        if (alutype == 1)
            // slowAluInstClass
            trace_alu(7, insn->pc, {insn->rs1, insn->rs2}, insn->rd,
                      xpr_val(insn->rd));
        else if (alusize == 0) {
            // slowAluInstClass (fence)
            trace_simple(7, insn->pc);
        } else {
            ERR("Unknown opcode: 0x%lx (0x%x)", insn->inst, insn->op);
            assert(false && "Unknown opcode");
        }
        break;
    default:
        ERR("Unknown opcode: 0x%lx (0x%x)", insn->inst, insn->op);
        assert(false && "Unknown opcode");
        break;
    }
}

/**
 * On translation block new translation
 *
 * QEMU convert code by translation block (TB). By hooking here we can then hook
 * a callback on each instruction and memory access.
 */
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    struct qemu_plugin_insn *insn;

    const size_t n = qemu_plugin_tb_n_insns(tb);
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
    ctx.flush();
    ctx.trace_file.close();
}

extern "C" {
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv) {
    assert(!info->system_emulation && "System emulation not supported");

    // Register translation block and exit callbacks
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
};
