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
#include <vector>

static GRWLock expand_array_lock;

class Ctx {
  private:
    std::optional<const rv_decode *> pending_br;

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

    void clear_br() { pending_br = std::nullopt; }
    void set_br(const rv_decode *dec) { pending_br = dec; }
    std::optional<const rv_decode *> get_br() const { return pending_br; }
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
    assert(rd < 0x7f);
    ctx.trace_out.write((char *)&rd, sizeof(rd));
    if (rd < 0x20) { // int reg
        ctx.trace_out.write((char *)&val, 8);
    } else { // fp reg
        assert(false && "Not implemented: fp reg");
    }
}

// static void write_alu(FILE *trace, const uint8_t inst_type, const uint64_t
// pc,
//                       const std::vector<uint64_t> &input_regs, const uint8_t
//                       rd, const freg_t val) {
//   assert(inst_type == 0 || inst_type == 6 || inst_type == 7);
//   uint8_t num_input_regs = input_regs.size();
//   uint8_t num_output_regs = 1;
//   fwrite(&pc, sizeof(pc), 1, trace);
//   fwrite(&inst_type, sizeof(inst_type), 1, trace);
//   fwrite(&num_input_regs, sizeof(num_input_regs), 1, trace);
//   for (int i = 0; i < num_input_regs; i++) {
//     assert(input_regs[i] < 256);
//     fwrite(&input_regs[i], sizeof(uint8_t), 1, trace);
//   }
//   fwrite(&num_output_regs, sizeof(num_output_regs), 1, trace);
//   assert(rd < RFSIZE);
//   fwrite(&rd, sizeof(rd), 1, trace);
//   if (rd < 0x20) { // int reg
//     fwrite(&val.v, 8, 1, trace);
//   } else { // fp reg
//     fwrite(&val.v, 16, 1, trace);
//   }
// }
//
// static void write_load(FILE *trace, const uint64_t pc,
//                        const uint64_t effective_addr, const uint8_t
//                        access_size, const std::vector<uint64_t> &input_regs,
//                        const uint8_t rd, const freg_t val) {
//   uint8_t inst_type = 1;
//   uint8_t num_input_regs = input_regs.size();
//   uint8_t num_output_regs = 1;
//   fwrite(&pc, sizeof(pc), 1, trace);
//   fwrite(&inst_type, sizeof(inst_type), 1, trace);
//   fwrite(&effective_addr, sizeof(effective_addr), 1, trace);
//   fwrite(&access_size, sizeof(access_size), 1, trace);
//   fwrite(&num_input_regs, sizeof(num_input_regs), 1, trace);
//   for (int i = 0; i < num_input_regs; i++) {
//     assert(input_regs[i] < 256);
//     fwrite(&input_regs[i], sizeof(uint8_t), 1, trace);
//   }
//   fwrite(&num_output_regs, sizeof(num_output_regs), 1, trace);
//   assert(rd < RFSIZE);
//   fwrite(&rd, sizeof(rd), 1, trace);
//   if (rd < 0x20) { // int reg
//     fwrite(&val.v, 8, 1, trace);
//   } else { // fp reg
//     fwrite(&val.v, 16, 1, trace);
//   }
// }
//
// static void write_store(FILE *trace, const uint64_t pc,
//                         const uint64_t effective_addr,
//                         const uint8_t access_size,
//                         const std::vector<uint64_t> &input_regs) {
//   uint8_t inst_type = 2;
//   uint8_t num_input_regs = input_regs.size();
//   uint8_t num_output_regs = 0;
//   fwrite(&pc, sizeof(pc), 1, trace);
//   fwrite(&inst_type, sizeof(inst_type), 1, trace);
//   fwrite(&effective_addr, sizeof(effective_addr), 1, trace);
//   fwrite(&access_size, sizeof(access_size), 1, trace);
//   fwrite(&num_input_regs, sizeof(num_input_regs), 1, trace);
//   for (int i = 0; i < num_input_regs; i++) {
//     assert(input_regs[i] < 256);
//     fwrite(&input_regs[i], sizeof(uint8_t), 1, trace);
//   }
//   fwrite(&num_output_regs, sizeof(num_output_regs), 1, trace);
// }
//
// static void
// write_br(FILE *trace, const uint8_t inst_type, const uint64_t pc,
//          const uint8_t taken, const uint64_t npc,
//          const std::vector<uint64_t> &input_regs,
//          const std::vector<std::pair<uint8_t, freg_t>> &output_regs) {
//   assert(inst_type == 3 || inst_type == 4 || inst_type == 5 || inst_type == 9
//   ||
//          inst_type == 0xa);
//   uint8_t num_input_regs = input_regs.size();
//   uint8_t num_output_regs = output_regs.size();
//   fwrite(&pc, sizeof(pc), 1, trace);
//   fwrite(&inst_type, sizeof(inst_type), 1, trace);
//   fwrite(&taken, sizeof(taken), 1, trace);
//   if (taken == 1) {
//     fwrite(&npc, sizeof(npc), 1, trace);
//   }
//   fwrite(&num_input_regs, sizeof(num_input_regs), 1, trace);
//   for (int i = 0; i < num_input_regs; i++) {
//     assert(input_regs[i] < 256);
//     fwrite(&input_regs[i], sizeof(uint8_t), 1, trace);
//   }
//   fwrite(&num_output_regs, sizeof(num_output_regs), 1, trace);
//   for (int i = 0; i < num_output_regs; i++) {
//     uint8_t rd = output_regs[i].first;
//     freg_t val = output_regs[i].second;
//     assert(rd < RFSIZE);
//     fwrite(&rd, sizeof(rd), 1, trace);
//     if (rd < 0x20) { // int reg
//       fwrite(&val.v, 8, 1, trace);
//     } else { // fp reg
//       fwrite(&val.v, 16, 1, trace);
//     }
//   }
// }
//
// static void write_simple(FILE *trace, const uint8_t inst_type,
//                          const uint64_t pc) {
//   assert(inst_type == 0xb || inst_type == 0xc || inst_type == 0x7);
//   uint8_t num_input_regs = 0;
//   uint8_t num_output_regs = 0;
//   fwrite(&pc, sizeof(pc), 1, trace);
//   fwrite(&inst_type, sizeof(inst_type), 1, trace);
//   fwrite(&num_input_regs, sizeof(num_input_regs), 1, trace);
//   fwrite(&num_output_regs, sizeof(num_output_regs), 1, trace);
// }

/**
 * Add memory read or write information to current instruction log
 */
static void vcpu_mem(unsigned int cpu_index, qemu_plugin_meminfo_t info,
                     uint64_t vaddr, void *udata) {
    // GString *s;

    /* Find vCPU in array */
    // g_rw_lock_reader_lock(&expand_array_lock);
    // g_assert(cpu_index < num_cpus);
    // s = cpus[cpu_index].last_exec;
    // g_rw_lock_reader_unlock(&expand_array_lock);

    /* Indicate type of memory access */
    if (qemu_plugin_mem_is_store(info)) {
        // g_string_append(s, ", store");
    } else {
        // g_string_append(s, ", load");
    }

    /* If full system emulation log physical address and device name */
    struct qemu_plugin_hwaddr *hwaddr = qemu_plugin_get_hwaddr(info, vaddr);
    if (hwaddr) {
        // uint64_t addr = qemu_plugin_hwaddr_phys_addr(hwaddr);
        // const char *name = qemu_plugin_hwaddr_device_name(hwaddr);
        // g_string_append_printf(s, ", 0x%08" PRIx64 ", %s", addr, name);
    } else {
        // g_string_append_printf(s, ", 0x%08" PRIx64, vaddr);
    }
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
        }
    }

    g_rw_lock_writer_lock(&expand_array_lock);
    // cpus[vcpu_index].reg = found ? reg : -1;
    g_rw_lock_writer_unlock(&expand_array_lock);
}

static uint32_t reg_val(const uint8_t reg) {
    const int n = qemu_plugin_read_register(ctx.reg_buf, reg);
    assert(n == 4);
    return *((uint32_t *)ctx.reg_buf->data);
}

static void vcpu_insn_exec(unsigned int cpu_index, void *udata) {
    const rv_decode *dec = (rv_decode *)udata;
    const uint64_t opcode = dec->inst & 0x7f;
    const uint64_t alusize = (dec->inst >> 12) & 0x07;
    const uint64_t alutype = (dec->inst >> 25) & 0x07f;

    if (const auto br = ctx.get_br()) {
        const auto prev_pc = (*br)->pc;
        const auto cur_pc = dec->pc;
#if 0
        if (prev_pc + 4 == cur_pc)
            puts("condBranchInstClass(not taken)");
        else {
            printf("condBranchInstClass(taken, %lx -> %lx)\n", prev_pc, cur_pc);
        }
#endif
        ctx.clear_br();
    }

#define puts(_)                                                                \
    do {                                                                       \
    } while (0)

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
        if (alusize == 0x00 || alusize == 0x04)
            puts("loadInstClass(b,ub)");
        else if (alusize == 0x01 || alusize == 0x05)
            puts("loadInstClass(h,uh)");
        else if (alusize == 0x02)
            puts("loadInstClass(w)");
        else if (alusize == 0x03)
            puts("loadInstClass(d)");
        break;
    case 0x07:
        if (alusize == 0x02)
            puts("fploadInstClass(w)");
        else if (alusize == 0x03)
            puts("fploadInstClass(d)");
        break;
    case 0x23:
        if (alusize == 0x00 || alusize == 0x04)
            puts("storeInstClass(b,ub)");
        else if (alusize == 0x01 || alusize == 0x05)
            puts("storeInstClass(h,uh)");
        else if (alusize == 0x02)
            puts("storeInstClass(w)");
        else if (alusize == 0x03)
            puts("storeInstClass(d)");
        break;
    case 0x27:
        if (alusize == 0x02)
            puts("fpstoreInstClass(w)");
        else if (alusize == 0x03)
            puts("fpstoreInstClass(d)");
        break;
    case 0x63:
        ctx.set_br(dec);
        break;
    case 0x6f:
        if (dec->rd == /* ra = */ 0x01)
            puts("jalClass(ra)");
        else if (dec->rd == 0x00)
            puts("uncondDirectBranchInstClass");
        break;
    case 0x67:
        if (dec->rd == 0 && dec->rs1 == 1 && dec->imm == 0 && dec->imm1 == 0)
            puts("retClass");
        else
            puts("uncondIndirectBranchInstClass");
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
        break;
    case 0x73:
        if (alusize == 0)
            puts("slowAluInstClass"); // fence ecall/break
        else if (alusize >= 1)
            puts("csrInstClass");
        break;
    case 73:
        if (dec->inst == 0x102000)
            puts("sretInstClass");
        break;
    case 0x0f:
        puts("slowAluInstClass");
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
        // char *insn_disas;
        // uint64_t insn_vaddr;

        /*
         * `insn` is shared between translations in QEMU, copy needed data here.
         * `output` is never freed as it might be used multiple times during
         * the emulation lifetime.
         * We only consider the first 32 bits of the instruction, this may be
         * a limitation for CISC architectures.
         */
        insn = qemu_plugin_tb_get_insn(tb, i);
        // insn_disas = qemu_plugin_insn_disas(insn);

        // We will never free `dec`.
        rv_decode *dec = (rv_decode *)malloc(sizeof(rv_decode));
        qemu_plugin_insn_decode(insn, dec);

        // insn_vaddr = qemu_plugin_insn_vaddr(insn);

        // uint32_t insn_opcode;
        // insn_opcode = *((uint32_t *)qemu_plugin_insn_data(insn));
        // char *output =
        //     g_strdup_printf("0x%" PRIx64 ", 0x%" PRIx32 ", \"%s\", (%x)",
        //                     insn_vaddr, insn_opcode, insn_disas, dec.op);

        /* Register callback on memory read or write */
        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem, QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW, NULL);

        /* Register callback on instruction */
        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                               "org.gnu.gdb.riscv.cpu"
                                                   ? QEMU_PLUGIN_CB_R_REGS
                                                   : QEMU_PLUGIN_CB_NO_REGS,
                                               dec);
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
