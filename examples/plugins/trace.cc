#include "../../disas/riscv.h"
#include "../../include/qemu/qemu-plugin.h"

#include <assert.h>
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

class Ctx {
  public:
    Ctx() {
        this->trace_out.open("trace.out", std::ios::binary | std::ios::out);
        assert(this->trace_out.is_open());

        this->reg_buf = g_byte_array_new();
    }
    ~Ctx() {
        this->trace_out.flush();
        this->trace_out.close();
    }

    std::ofstream trace_out;
    GByteArray *reg_buf;
    std::optional<const rv_decode *> pending_insn = std::nullopt;
};

static Ctx ctx;

static void trace_alu(const uint8_t inst_type, const uint64_t pc,
                      const std::vector<uint64_t> &input_regs, const uint8_t rd,
                      const uint64_t val) {
    assert(inst_type == 0 || inst_type == 6 || inst_type == 7);
    uint8_t num_input_regs = input_regs.size();
    uint8_t num_output_regs = 1;
    ctx.trace_out.write((char *)&pc, sizeof(pc));
    ctx.trace_out.write((char *)&inst_type, sizeof(inst_type));
    ctx.trace_out.write((char *)&num_input_regs, sizeof(num_input_regs));
    for (int i = 0; i < num_input_regs; i++) {
        assert(input_regs[i] < 0x40);
        ctx.trace_out.write((char *)&input_regs[i], sizeof(uint8_t));
    }
    ctx.trace_out.write((char *)&num_output_regs, sizeof(num_output_regs));
    assert(rd < 0x40);
    ctx.trace_out.write((char *)&rd, sizeof(rd));
    if (rd < 0x20) { // int reg
        ctx.trace_out.write((char *)&val, 8);
    } else { // fp reg
        ctx.trace_out.write((char *)&val, 8);
        uint64_t zero = 0;
        ctx.trace_out.write((char *)&zero, 8);
    }
}

static void trace_load(const uint64_t pc, uint64_t effective_addr,
                       const uint8_t access_size,
                       const std::vector<uint64_t> &input_regs,
                       const uint8_t rd, const uint64_t val) {
    uint8_t inst_type = 1;
    uint8_t num_input_regs = input_regs.size();
    uint8_t num_output_regs = 1;
    ctx.trace_out.write((char *)&pc, sizeof(pc));
    ctx.trace_out.write((char *)&inst_type, sizeof(inst_type));
    ctx.trace_out.write((char *)&effective_addr, sizeof(effective_addr));
    ctx.trace_out.write((char *)&access_size, sizeof(access_size));
    ctx.trace_out.write((char *)&num_input_regs, sizeof(num_input_regs));
    for (int i = 0; i < num_input_regs; i++) {
        assert(input_regs[i] < 0x40);
        ctx.trace_out.write((char *)&input_regs[i], sizeof(uint8_t));
    }
    ctx.trace_out.write((char *)&num_output_regs, sizeof(num_output_regs));
    assert(rd < 0x40);
    ctx.trace_out.write((char *)&rd, sizeof(rd));
    if (rd < 0x20) { // int reg
        ctx.trace_out.write((char *)&val, 8);
    } else { // fp reg
        ctx.trace_out.write((char *)&val, 8);
        uint64_t zero = 0;
        ctx.trace_out.write((char *)&zero, 8);
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
    ctx.trace_out.write((char *)&pc, sizeof(pc));
    ctx.trace_out.write((char *)&inst_type, sizeof(inst_type));
    ctx.trace_out.write((char *)&taken, sizeof(taken));
    if (taken) {
        ctx.trace_out.write((char *)&npc, sizeof(npc));
    }
    ctx.trace_out.write((char *)&num_input_regs, sizeof(num_input_regs));
    for (int i = 0; i < num_input_regs; i++) {
        assert(input_regs[i] < 0x40);
        ctx.trace_out.write((char *)&input_regs[i], sizeof(uint8_t));
    }
    ctx.trace_out.write((char *)&num_output_regs, sizeof(num_output_regs));
    for (int i = 0; i < num_output_regs; i++) {
        const uint8_t rd = output_regs[i].first;
        const uint64_t val = output_regs[i].second;
        assert(rd < 0x40);
        ctx.trace_out.write((char *)&rd, sizeof(rd));
        if (rd < 0x20) { // int reg
            ctx.trace_out.write((char *)&val, 8);
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
    ctx.trace_out.write((char *)&pc, sizeof(pc));
    ctx.trace_out.write((char *)&inst_type, sizeof(inst_type));
    ctx.trace_out.write((char *)&effective_addr, sizeof(effective_addr));
    ctx.trace_out.write((char *)&access_size, sizeof(access_size));
    ctx.trace_out.write((char *)&num_input_regs, sizeof(num_input_regs));
    for (int i = 0; i < num_input_regs; i++) {
        assert(input_regs[i] < 0x40);
        ctx.trace_out.write((char *)&input_regs[i], sizeof(uint8_t));
    }
    ctx.trace_out.write((char *)&num_output_regs, sizeof(num_output_regs));
}

static void trace_simple(const uint8_t inst_type, const uint64_t pc) {
    assert(inst_type == 0xb || inst_type == 0xc || inst_type == 0x7);
    uint8_t num_input_regs = 0;
    uint8_t num_output_regs = 0;
    ctx.trace_out.write((char *)&pc, sizeof(pc));
    ctx.trace_out.write((char *)&inst_type, sizeof(inst_type));
    ctx.trace_out.write((char *)&num_input_regs, sizeof(num_input_regs));
    ctx.trace_out.write((char *)&num_output_regs, sizeof(num_output_regs));
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
        // int idx = 0;
        for (int i = 0; i < num_reg_files; i++) {
            const qemu_plugin_register_file_t *reg_file = &reg_files[i];
            printf("\033[1;32m%s\033[0m (%d registers)\n", reg_file->name,
                   reg_file->num_regs);
#if 0
            for (int k = 0; k < reg_file->num_regs; k++) {
                printf("%d (%d): %s\n", k, idx, reg_file->regs[k]);
                idx += 1;
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
        fprintf(stderr, "\033[1;31mRead bytes: %d\033[0m\n", n);
        assert(false && "FPR must 32 or 64 bits");
    }
    g_byte_array_set_size(ctx.reg_buf, 0);
    return ret;
}

static void vcpu_insn_exec(unsigned int cpu_index, void *udata) {
    const rv_decode *insn = ctx.pending_insn.value_or(nullptr);
    const rv_decode *next_insn = (rv_decode *)udata;
    ctx.pending_insn = next_insn;
    if (insn == nullptr)
        return;

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
            assert(false);
        }
        break;
    case 0x0f:
        // slowAluInstClass
        assert(false);
        break;
    default:
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

        // We will never free `dec`.
        rv_decode *dec = (rv_decode *)malloc(sizeof(rv_decode));
        qemu_plugin_insn_decode(insn, dec);

        /* Register callback on instruction */
        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                               QEMU_PLUGIN_CB_R_REGS, dec);
    }
}

/**
 * On plugin exit, print last instruction in cache
 */
static void plugin_exit(qemu_plugin_id_t id, void *p) {
    ctx.trace_out.flush();
    ctx.trace_out.close();
    return;
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
