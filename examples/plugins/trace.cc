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
  private:
    std::optional<std::tuple<const rv_decode *, const uint64_t>> pending_br;

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

    void clear_br() { this->pending_br = std::nullopt; }
    void set_br(const rv_decode *dec, const uint64_t rd_val) {
        this->pending_br.emplace(dec, rd_val);
    }
    std::optional<std::tuple<const rv_decode *, const uint64_t>> get_br() {
        return this->pending_br;
    }
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
        assert(input_regs[i] < 256);
        ctx.trace_out.write((char *)&input_regs[i], sizeof(uint8_t));
    }
    ctx.trace_out.write((char *)&num_output_regs, sizeof(num_output_regs));
    assert(rd < 32);
    ctx.trace_out.write((char *)&rd, sizeof(rd));
    if (rd < 0x20) { // int reg
        ctx.trace_out.write((char *)&val, 8);
    } else { // fp reg
        assert(false && "Not implemented: fp reg");
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
        assert(input_regs[i] < 256);
        ctx.trace_out.write((char *)&input_regs[i], sizeof(uint8_t));
    }
    ctx.trace_out.write((char *)&num_output_regs, sizeof(num_output_regs));
    assert(rd < 32);
    ctx.trace_out.write((char *)&rd, sizeof(rd));
    if (rd < 0x20) { // int reg
        ctx.trace_out.write((char *)&val, 8);
    } else { // fp reg
        assert(false && "Not implemented: fp reg");
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
        assert(input_regs[i] < 256);
        ctx.trace_out.write((char *)&input_regs[i], sizeof(uint8_t));
    }
    ctx.trace_out.write((char *)&num_output_regs, sizeof(num_output_regs));
    for (int i = 0; i < num_output_regs; i++) {
        const uint8_t rd = output_regs[i].first;
        const uint64_t val = output_regs[i].second;
        assert(rd < 32);
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
        assert(input_regs[i] < 32);
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
        /* org.gnu.gdb.riscv.cpu */
        /* org.gnu.gdb.riscv.fpu */
        /* org.gnu.gdb.riscv.virtual */
        /* org.gnu.gdb.riscv.csr */
        for (int i = 0; i < num_reg_files; i++) {
            const qemu_plugin_register_file_t *reg_file = &reg_files[i];
            printf("\033[1;32m%s\033[0m\n", reg_file->name);
            for (int k = 0; k < reg_file->num_regs; k++) {
                printf("%d: %s\n", k, reg_file->regs[k]);
            }
            break;
        }
    }
}

static uint32_t reg_val(const uint8_t reg) {
    const int n = qemu_plugin_read_register(ctx.reg_buf, reg);
    assert(n == 4 && ctx.reg_buf->len == 4);
    const auto ret = *((uint32_t *)ctx.reg_buf->data);
    g_byte_array_set_size(ctx.reg_buf, 0);
    return ret;
}

static void vcpu_insn_exec(unsigned int cpu_index, void *udata) {
    const rv_decode *dec = (rv_decode *)udata;
    const uint64_t opcode = dec->inst & 0x7f;
    const uint64_t alusize = (dec->inst >> 12) & 0x07;
    const uint64_t alutype = (dec->inst >> 25) & 0x7f;

    if (const auto br_rd = ctx.get_br()) {
        const auto [br, rd_val] = *br_rd;
        const auto br_opcode = br->inst & 0x7f;
        const auto pc = br->pc;
        const auto npc = dec->pc;
        const auto taken = pc + 4 != npc;
        switch (br_opcode) {
        case 0x63: // beq, bne, blt, bge, bltu, bgeu
            trace_br(3, pc, taken, npc, {}, {});
            break;
        case 0x6f: // jal
            if (br->rd == /* ra = */ 0x01) {
                trace_br(9, pc, true, npc, {}, {{1, rd_val}});
            } else if (br->rd == 0x00) {
                trace_br(4, pc, true, npc, {}, {});
            }
            break;
        case 0x67: // jalr
            if (br->rd == 0 && br->rs1 == 1 && br->imm == 0) {
                trace_br(0xa, pc, true, npc, {1}, {});
            } else {
                trace_br(5, pc, true, npc, {br->rs1}, {{br->rd, rd_val}});
            }
            break;
        default:
            assert(false && "Unknown br_opcode");
            break;
        }
        ctx.clear_br();
    }

#define puts(_)                                                                \
    do {                                                                       \
    } while (0)

    assert((dec->codec != rv_codec_r2_immhl && dec->codec != rv_codec_r2_imm2_imm5) && "dec->imm1 must be zero");

    switch (opcode) {
    case 0x37:
    case 0x17: {
        puts("aluInstClass(lui, auipc)");
        trace_alu(0, dec->pc, {}, dec->rd, reg_val(dec->rd));
        break;
    }
    case 0x13: {
        puts("aluInstClass(alu(immediate))");
        trace_alu(0, dec->pc, {dec->rs1}, dec->rd, reg_val(dec->rd));
        break;
    }
    case 0x33:
        if (alutype == 0x00 || alutype == 0x20) {
            puts("aluInstClass(alu)");
            trace_alu(0, dec->pc, {dec->rs1, dec->rs2}, dec->rd,
                      reg_val(dec->rd));
        } else if (alutype == 0x01) {
            puts("slowAluInstClass");
            trace_alu(7, dec->pc, {dec->rs1, dec->rs1}, dec->rd,
                      reg_val(dec->rd));
        }
        break;
    case 0x03:
        if (alusize == 0x00 || alusize == 0x04) {
            puts("loadInstClass(b,ub)");
            const uint64_t effaddr = reg_val(dec->rs1) + dec->imm;
            trace_load(dec->pc, effaddr, 1, {dec->rs1}, dec->rd,
                       reg_val(dec->rd));
        } else if (alusize == 0x01 || alusize == 0x05) {
            puts("loadInstClass(h,uh)");
            const uint64_t effaddr = reg_val(dec->rs1) + dec->imm;
            trace_load(dec->pc, effaddr, 2, {dec->rs1}, dec->rd,
                       reg_val(dec->rd));
        } else if (alusize == 0x02) {
            puts("loadInstClass(w)");
            const uint64_t effaddr = reg_val(dec->rs1) + dec->imm;
            trace_load(dec->pc, effaddr, 4, {dec->rs1}, dec->rd,
                       reg_val(dec->rd));
        } else if (alusize == 0x03) {
            puts("loadInstClass(d)");
            const uint64_t effaddr = reg_val(dec->rs1) + dec->imm;
            trace_load(dec->pc, effaddr, 8, {dec->rs1}, dec->rd,
                       reg_val(dec->rd));
        }
        break;
    case 0x07:
        if (alusize == 0x02) {
            puts("fploadInstClass(w)");
            const uint64_t effaddr = reg_val(dec->rs1) + dec->imm;
            trace_load(dec->pc, effaddr, 4, {dec->rs1}, dec->rd,
                       reg_val(dec->rd));
        } else if (alusize == 0x03) {
            puts("fploadInstClass(d)");
            const uint64_t effaddr = reg_val(dec->rs1) + dec->imm;
            trace_load(dec->pc, effaddr, 8, {dec->rs1}, dec->rd,
                       reg_val(dec->rd));
        }
        break;
    case 0x23:
        if (alusize == 0x00 || alusize == 0x04) {
            puts("storeInstClass(b,ub)");
            const uint64_t effaddr = reg_val(dec->rs1) + dec->imm;
            trace_store(dec->pc, effaddr, 1, {dec->rs1, dec->rs2});
        } else if (alusize == 0x01 || alusize == 0x05) {
            puts("storeInstClass(h,uh)");
            const uint64_t effaddr = reg_val(dec->rs1) + dec->imm;
            trace_store(dec->pc, effaddr, 2, {dec->rs1, dec->rs2});
        } else if (alusize == 0x02) {
            puts("storeInstClass(w)");
            const uint64_t effaddr = reg_val(dec->rs1) + dec->imm;
            trace_store(dec->pc, effaddr, 4, {dec->rs1, dec->rs2});
        } else if (alusize == 0x03) {
            puts("storeInstClass(d)");
            const uint64_t effaddr = reg_val(dec->rs1) + dec->imm;
            trace_store(dec->pc, effaddr, 8, {dec->rs1, dec->rs2});
        }
        break;
    case 0x27:
        if (alusize == 0x02)
            puts("fpstoreInstClass(w)");
        else if (alusize == 0x03)
            puts("fpstoreInstClass(d)");
        assert(false);
        break;
    case 0x63:
        ctx.set_br(dec, reg_val(dec->rd));
        break;
    case 0x6f:
        ctx.set_br(dec, reg_val(dec->rd));
        break;
    case 0x67:
        ctx.set_br(dec, reg_val(dec->rd));
        // if (dec->rd == 0 && dec->rs1 == 1 && dec->imm == 0 && dec->imm1 == 0)
        //     puts("retClass");
        // else
        //     puts("uncondIndirectBranchInstClass");
        break;
    case 0x53:
        assert(false && "fpInstClass");
        // if (alutype == 0x2c || alutype == 0x2d || alutype == 0x20 ||
        //     alutype == 0x21)
        //     puts("fpInstClass(rs1:f,rd:f)");
        // else if (alutype == 0x60 || alutype == 0x70 || alutype == 0x61 ||
        //          alutype == 0x71)
        //     puts("fpInstClass(rs1:f,rd:x)");
        // else if (alutype == 0x2c || alutype == 0x2d || alutype == 0x20 ||
        //          alutype == 0x21)
        //     puts("fpInstClass(rs1:x,rd:f)");
        // else if (alutype <= 0x3f)
        //     puts("fpInstClass(rs1:x,rd
        break;
    case 0x43:
    case 0x47:
    case 0x4b:
    case 0x4f:
        puts("fpInstClass(rs1:f,rs2:f,rs3:f,rd:f");
        assert(false);
        break;
    case 0x73:
        if (dec->inst == 0x10200073) {
            puts("sretInstClass");
            assert(false);
        } else if (alusize == 0) {
            puts("slowAluInstClass"); // fence ecall/break
            trace_simple(7, dec->pc);
        } else if (alusize >= 1) {
            puts("csrInstClass");
            assert(false);
        }
        break;
    case 0x0f:
        puts("slowAluInstClass");
        assert(false);
        break;
    default:
        assert(false && "Unknown opcode");
        break;
    }
#undef puts

#if 0
    /* Find or create vCPU in array */
    g_rw_lock_reader_lock(&expand_array_lock);
    // cpu = cpus[cpu_index];
    g_rw_lock_reader_unlock(&expand_array_lock);
    int n = qemu_plugin_read_register(cpu.reg_buf, cpu.reg);

    /* Print previous instruction in cache */
    if (cpu.last_exec->len) {
        // qemu_plugin_outs(cpu.last_exec->str);
        // qemu_plugin_outs("\n");
    }

    /* Store new instruction in cache */
    /* vcpu_mem will add memory access information to last_exec */
    g_string_printf(cpu.last_exec, "%u, ", cpu_index);
    g_string_append(cpu.last_exec, (char *)udata);

    g_string_append(cpu.last_exec, ", reg,");
    n = qemu_plugin_read_register(cpu.reg_buf, cpu.reg);
    for (i = 0; i < n; i++) {
        g_string_append_printf(cpu.last_exec, " 0x%02X", cpu.reg_buf->data[i]);
    }
    g_byte_array_set_size(cpu.reg_buf, 0);
#endif
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
    assert(!ctx.get_br().has_value());
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
