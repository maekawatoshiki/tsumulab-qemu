#include "../../disas/riscv.h"
#include "../../include/qemu/qemu-plugin.h"

#include <assert.h>
#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <optional>

static GRWLock expand_array_lock;

class Ctx {
  private:
    std::optional<const rv_decode *> last_br;

  public:
    void clear_br() { last_br = std::nullopt; }
    void set_br(const rv_decode *dec) { last_br = dec; }
    std::optional<const rv_decode *> get_br() { return last_br; }
};

static Ctx ctx;

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

/**
 * Log instruction execution
 */
static void vcpu_insn_exec(unsigned int cpu_index, void *udata) {
    const rv_decode *dec = (rv_decode *)udata;
    const uint64_t opcode = dec->inst & 0x7f;
    const uint64_t alusize = (dec->inst >> 12) & 0x07;
    const uint64_t alutype = (dec->inst >> 25) & 0x07f;

    if (const auto br = ctx.get_br()) {
        const auto prev_pc = (*br)->pc;
        const auto cur_pc = dec->pc;
        if (prev_pc + 4 == cur_pc)
            puts("condBranchInstClass(not taken)");
        else {
            printf("condBranchInstClass(taken, %lx -> %lx)\n", prev_pc, cur_pc);
        }
        ctx.clear_br();
    }

    switch (opcode) {
    case 0x37:
    case 0x17:
        puts("aluInstClass(lui, auipc)");
        break;
    case 0x13:
        puts("aluInstClass(alu(immediate))");
        break;
    case 0x33:
        if (alutype == 0x00 || alutype == 0x20)
            puts("aluInstClass(alu)");
        else if (alutype == 0x01)
            puts("slowAluInstClass");
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
    return;

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
