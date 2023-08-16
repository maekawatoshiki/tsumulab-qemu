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
#include <unordered_map>
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

class Ctx {
  public:
    Ctx() {}
    // NOTE: Destructor is not called on program exit.
    // ~Ctx() {
    // }

    int bits;
    uint64_t num_insns = 0;
    uint64_t prev_ip = 0;
    std::unordered_map<uint64_t, uint64_t> ip2bb;
    std::unordered_map<uint64_t, uint64_t> bb2count;
};

static Ctx ctx;

void dump();

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index) {
    (void)(id);
    assert(vcpu_index == 0 && "Only one vCPU supported");

    {
        int num_reg_files;
        const qemu_plugin_register_file_t *reg_files =
            qemu_plugin_get_register_files(vcpu_index, &num_reg_files);
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

//
// Plugin callbacks
//

static void vcpu_insn_exec(unsigned int, void *udata) {
    const uint64_t ip = *(uint64_t *)udata;

    ctx.num_insns++;

    if (ctx.num_insns % 1'000'000 == 0) { // 1M
        dump();
    }

    if (ctx.ip2bb.find(ip) != ctx.ip2bb.end()) {
        ctx.bb2count[ctx.ip2bb[ip]]++;
    } else if (abs((int64_t)ip - (int64_t)ctx.prev_ip) >= 16) {
        if (ctx.ip2bb.find(ip) == ctx.ip2bb.end()) {
            ctx.ip2bb[ip] = ctx.ip2bb.size();
        }
        ctx.bb2count[ctx.ip2bb[ip]]++;
    }

    // DEBUG("ip=0x%lx, diff=%ld, bb=%d, count=%d", ip, (int64_t)ip - (int64_t)ctx.prev_ip, ctx.ip2bb[ip], ctx.bb2count[ctx.ip2bb[ip]]);

    ctx.prev_ip = ip;
}

/**
 * On translation block new translation
 *
 * QEMU convert code by translation block (TB). By hooking here we can then hook
 * a callback on each instruction and memory access.
 */
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    (void)(id);

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
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);

#if 0
        DEBUG("Disas: %s", qemu_plugin_insn_disas(insn));
#endif

        /* Register callback on instruction */
        uint64_t *ip = (uint64_t *)malloc(sizeof(uint64_t));
        *ip = (uint64_t)qemu_plugin_insn_vaddr(insn);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                               QEMU_PLUGIN_CB_R_REGS, ip);
    }
}

void dump() {
    FILE *bbv_out = fopen("out.bb", "a");
    std::vector<std::pair<uint64_t, uint64_t>> bbv(ctx.bb2count.begin(),
                                                   ctx.bb2count.end());
    std::sort(bbv.begin(), bbv.end(),
              [](const std::pair<uint64_t, uint64_t> &a,
                 const std::pair<uint64_t, uint64_t> &b) {
                  return a.first < b.first;
              });
    fprintf(bbv_out, "T");
    for (auto &bbfq : bbv) {
        const auto bb = bbfq.first;
        const auto count = bbfq.second;
        if (count == 0)
            continue;
        fprintf(bbv_out, ":%lu:%lu ", bb, count);
    }
    for (auto &entry : ctx.bb2count)
        entry.second = 0;
    fprintf(bbv_out, "\n");
    fclose(bbv_out);
}

/**
 * On plugin exit, print last instruction in cache
 */
static void plugin_exit(qemu_plugin_id_t, void *) { dump(); }

extern "C" {
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv) {
    (void)(argc);
    (void)(argv);
    assert(!info->system_emulation && "System emulation not supported");

    INFO("Target name: %s", info->target_name);
    assert(strcmp(info->target_name, "x86_64") == 0);
    ctx.bits = 64;

    // Register translation block and exit callbacks
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
};
