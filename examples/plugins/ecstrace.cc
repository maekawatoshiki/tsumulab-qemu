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

G_BEGIN_DECLS // Ensure C linkage
#include "qemu/qemu-plugin.h"
G_END_DECLS

#define ERR(fmt, ...)                                                                                       \
    do {                                                                                                    \
        fprintf(stderr, "[%s:%-4d] \033[1;31m[  ERR]\033[0m " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
        exit(1);                                                                                            \
    } while (0)
#define INFO(fmt, ...) fprintf(stderr, "[%s:%-4d] \033[1;32m[ INFO]\033[0m " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define WARN(fmt, ...) fprintf(stderr, "[%s:%-4d] \033[1;33m[ WARN]\033[0m " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define DEBUG(fmt, ...) fprintf(stderr, "[%s:%-4d] \033[1;34m[DEBUG]\033[0m " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#define TRACE_HEADER "RISC-V trace 0.1"
#define REG_HEADER "RISC-V reg   0.1"
#define MEM_HEADER "RISC-V mem   0.1"

typedef uint64_t u64;
typedef int64_t s64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

struct InputOp { // 80 Bytes
    u64 ip;
    u64 next_ip;
    u32 instruction_word;
    u8 reservedA[4] = {};
    u8 logical_src_reg[4];
    u8 logical_dst_reg[2];
    u8 reservedB[2] = {};
    u64 src_value[4];
    u64 dst_value[2];
    u64 imm;
    u64 mem_addr;
    u64 mem_src_value;
    u64 mem_dst_value;

    constexpr InputOp(u64 ip, u64 next_ip, u32 instruction_word,
                      std::array<u8, 4> src_reg, std::array<u8, 2> dst_reg,
                      std::array<u64, 4> src_val, std::array<u64, 2> dst_val,
                      u64 imm, u64 mem_addr, u64 mem_src_val, u64 mem_dst_val)
        : ip(ip), next_ip(next_ip), instruction_word(instruction_word),
          logical_src_reg{src_reg[0], src_reg[1], src_reg[2], src_reg[3]},
          logical_dst_reg{dst_reg[0], dst_reg[1]},
          src_value{src_val[0], src_val[1], src_val[2], src_val[3]},
          dst_value{dst_val[0], dst_val[1]}, imm(imm), mem_addr(mem_addr),
          mem_src_value(mem_src_val), mem_dst_value(mem_dst_val) {}
};

const size_t page_size = 4096;
struct Page {
    u64 version; // 0: initial state, 1: after first ecall, ...
    u64 addr;
    u8 data[page_size];
};

enum rv_op : u16 {
    rv_op_default = 0,
    rv_op_jal,
    rv_op_jalr,
};

struct rv_decode {
    u64 pc;
    u64 inst;
    int64_t imm;
    u16 op;
    u8 rd;
    u8 rs1;
    u8 rs2;
    u8 rs3;
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
        this->trace_file.write(TRACE_HEADER, 16);

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
        this->mem_buf = g_byte_array_new();
    }

    int bits;

    std::ofstream trace_file;
    std::ofstream mem_state_file;
    std::ofstream reg_state_file;

    u64 last_call_insn_pc = 0;
    std::optional<std::function<void(const rv_decode *next_insn)>>
        pending_trace = std::nullopt;

    u64 skip_first_n_insns_from_entry = 0;
    u64 num_insns_from_entry = 0;
    u64 entry_addr = 0, exit_addr = 0;
    bool trace_enabled = false;

    GByteArray *reg_buf, *mem_buf;
    std::vector<struct qemu_plugin_register *> reg_list;

    u64 num_ecalls = 0;
    std::unordered_map<u64, Page> pages;
};

static Ctx ctx;

static constexpr int64_t sign_extend(u32 value, u32 bits) {
    if (bits == 0) {
        return 0;
    }
    assert(bits <= 32);
    const u32 shift = 32 - bits;
    return static_cast<int64_t>(static_cast<int32_t>(value << shift) >> shift);
}

static void decode_rv64(u32 inst, rv_decode *dec) {
    const u32 opcode = inst & 0x7f;
    const u8 rd = (inst >> 7) & 0x1f;
    const u8 rs1 = (inst >> 15) & 0x1f;
    const u8 rs2 = (inst >> 20) & 0x1f;
    const u8 rs3 = (inst >> 27) & 0x1f;

    dec->rd = dec->rs1 = dec->rs2 = dec->rs3 = dec->imm = 0;

    switch (opcode) {
    case 0x17: // AUIPC
    case 0x37: // LUI
        dec->rd = rd;
        dec->imm = sign_extend(inst >> 12, 20) << 12;
        break;
    case 0x6f: // JAL
        dec->rd = rd;
        dec->imm = sign_extend(
            ((inst >> 31) << 20) | (((inst >> 21) & 0x3ffu) << 1) |
                (((inst >> 20) & 0x1u) << 11) | (((inst >> 12) & 0xffu) << 12),
            21);
        dec->op = rv_op_jal;
        break;
    case 0x63: // Branch
        dec->rs1 = rs1;
        dec->rs2 = rs2;
        dec->imm = sign_extend(
            (((inst >> 31) & 0x1u) << 12) | (((inst >> 25) & 0x3fu) << 5) |
                (((inst >> 8) & 0xfu) << 1) | (((inst >> 7) & 0x1u) << 11),
            13);
        break;
    case 0x23: // Store
    case 0x27: // FpStore
        dec->rs1 = rs1;
        dec->rs2 = rs2;
        dec->imm = sign_extend(
            (((inst >> 25) & 0x7fu) << 5) | ((inst >> 7) & 0x1fu), 12);
        break;
    case 0x03: // Load
    case 0x07: // FpLoad
    case 0x0f: // FENCE / FENCE.I
    case 0x13: // Integer immediate
    case 0x1b: // Integer immediate (word)
    case 0x67: // JALR
    case 0x73: // SYSTEM / CSR
        dec->rd = rd;
        dec->rs1 = rs1;
        dec->imm = sign_extend(inst >> 20, 12);
        if (opcode == 0x67) {
            dec->op = rv_op_jalr;
        }
        break;
    case 0x43: // FMADD.S
    case 0x47: // FMSUB.S
    case 0x4b: // FNMSUB.S
    case 0x4f: // FNMADD.S
        dec->rd = rd;
        dec->rs1 = rs1;
        dec->rs2 = rs2;
        dec->rs3 = rs3;
        dec->imm = 0;
        break;
    default:
        dec->rd = rd;
        dec->rs1 = rs1;
        dec->rs2 = rs2;
        dec->rs3 = rs3;
        break;
    }
}

extern "C" void qemu_plugin_insn_decode(const struct qemu_plugin_insn *insn,
                                        rv_decode *dec) {
    memset(dec, 0, sizeof(rv_decode));
    dec->pc = qemu_plugin_insn_vaddr(insn);
    dec->op = rv_op_default;

    const size_t size = qemu_plugin_insn_size(insn);
    assert(size == sizeof(u32) &&
           "Unexpected instruction size. Only RV64G supported.");

    u8 raw[sizeof(u32)] = {};
    const size_t fetched = qemu_plugin_insn_data(insn, raw, size);
    assert(fetched == size && "Failed to fetch instruction bytes");

    u32 inst;
    memcpy(&inst, raw, sizeof(inst)); // assume little-endian
    dec->inst = inst;

    decode_rv64(inst, dec);
}
//
// Utils for reading register values
//

static u64 reg_val(const u8 reg) {
    // 0~31: XPR, 32~63: FPR, 64: PC, 65: fflags, 66: frm, 67: fcsr, ...
    const int n = qemu_plugin_read_register(ctx.reg_list[reg], ctx.reg_buf);
    u64 ret = 0;
    switch (n) {
    case 4:
        ret = *((u32 *)ctx.reg_buf->data);
        break;
    case 8:
        ret = *((u64 *)ctx.reg_buf->data);
        break;
    default:
        ERR("Read bytes: %d. Must be 32 or 64 bits", n);
    }
    g_byte_array_set_size(ctx.reg_buf, 0);
    return ret;
}

//
// Utils for dumping memory/register state
//

static void dump_register_file() {
    if (!ctx.reg_state_file.is_open())
        return;

    ctx.reg_state_file.write(REG_HEADER, 16);

    const u64 pc = reg_val(/*pc=*/64);
    ctx.reg_state_file.write((const char *)&pc, sizeof(pc));

    // XPR 32 registers
    for (int i = 0; i < 32; i++) {
        u64 val = reg_val(i);
        ctx.reg_state_file.write((const char *)&val, sizeof(val));
    }
    // FPR 32 registers
    for (int i = 0; i < 32; i++) {
        u64 val = reg_val(i + 32);
        ctx.reg_state_file.write((const char *)&val, sizeof(val));
    }

    const u64 x = 0; // TODO: csr_val(0) returns 0 bytes
    const u64 fflags = reg_val(65);
    const u64 frm = reg_val(66);
    ctx.reg_state_file.write((const char *)&x, sizeof(x));
    ctx.reg_state_file.write((const char *)&fflags, sizeof(fflags));
    ctx.reg_state_file.write((const char *)&frm, sizeof(frm));
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
    ctx.reg_state_file.close();

    ctx.mem_state_file.write(MEM_HEADER, 16);
}

//
// Plugin callbacks
//

static void vcpu_init(qemu_plugin_id_t id, u32 vcpu_index) {
    (void)(id);
    assert(vcpu_index == 0 && "Only one vCPU supported");

    const GArray *list_regs = qemu_plugin_get_registers();
    assert(list_regs != nullptr);

    for (size_t i = 0; i < 32; i++) {
        const qemu_plugin_reg_descriptor *reg = &g_array_index(list_regs, qemu_plugin_reg_descriptor, i);
        // DEBUG("Register: %s", reg->name);
        ctx.reg_list.push_back(reg->handle);
    }
    assert(g_array_index(list_regs, qemu_plugin_reg_descriptor, 0).name == std::string("zero"));
    assert(g_array_index(list_regs, qemu_plugin_reg_descriptor, 31).name == std::string("t6"));
    assert(g_array_index(list_regs, qemu_plugin_reg_descriptor, 32).name == std::string("pc"));

    for (size_t i = 33; i < 33 + 32; i++) {
        const qemu_plugin_reg_descriptor *reg = &g_array_index(list_regs, qemu_plugin_reg_descriptor, i);
        // DEBUG("Register: %s", reg->name);
        ctx.reg_list.push_back(reg->handle);
    }
    assert(g_array_index(list_regs, qemu_plugin_reg_descriptor, 33).name == std::string("ft0"));
    assert(g_array_index(list_regs, qemu_plugin_reg_descriptor, 33 + 31).name == std::string("ft11"));

    ctx.reg_list.push_back(g_array_index(list_regs, qemu_plugin_reg_descriptor, 32).handle);  // PC
    ctx.reg_list.push_back(g_array_index(list_regs, qemu_plugin_reg_descriptor, 98).handle);  // fflags
    ctx.reg_list.push_back(g_array_index(list_regs, qemu_plugin_reg_descriptor, 99).handle);  // frm
    ctx.reg_list.push_back(g_array_index(list_regs, qemu_plugin_reg_descriptor, 100).handle); // fcsr
}

static void vcpu_insn_exec(u32, void *udata) {
    // #define DBG(fmt, ...) DEBUG(fmt, ##__VA_ARGS__)
#define DBG(fmt, ...)                                                          \
    do {                                                                       \
    } while (0)

    const rv_decode *insn = (rv_decode *)udata;
    const bool is_compressed = (insn->inst & 0b11) != 0b11;

    if (insn->op == rv_op_jal || insn->op == rv_op_jalr) {
        ctx.last_call_insn_pc = insn->pc;
    }
    if (insn->pc == ctx.entry_addr) {
        ctx.trace_enabled = true;
        ctx.exit_addr = ctx.last_call_insn_pc + 4;
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

    if (!ctx.trace_enabled)
        return;

    if (ctx.num_insns_from_entry++ < ctx.skip_first_n_insns_from_entry)
        return;

    if (is_compressed) {
        ERR("Compressed instruction is not supported");
    }

    u8 rd = insn->rd, rs1 = insn->rs1, rs2 = insn->rs2, rs3 = insn->rs3;
    u8 frm = 0, fflags = 0;
    u64 mem_addr = 0;
    size_t mem_dst_size = 0;
    bool need_mem_src_val = false;
    const auto to_fp = [](u8 reg) { return static_cast<u8>(reg + 32); };

    // clang-format off
    switch (insn->inst & 0x7f) {
    case 0b1110011: // ECALL/CSR
    {
        const int funct3 = (insn->inst >> 12) & 0x07;
        switch (funct3) {
        case 0b000: // ECALL
        {
            ctx.num_ecalls++;

            std::array<u64, 64> prev_xpr_fpr;
            for (int i = 0; i < 64; i++) prev_xpr_fpr[i] = reg_val(i);

            ctx.pending_trace = [=](const rv_decode *next_insn) {
                std::vector<Page> changed_pages;
                for (auto &[addr, page] : ctx.pages) {
                    qemu_plugin_read_memory_vaddr(addr, ctx.mem_buf, page_size);
                    assert(ctx.mem_buf->len == page_size);
                    if (memcmp(ctx.mem_buf->data, page.data, page_size) != 0) {
                        memcpy(page.data, ctx.mem_buf->data, page_size);
                        page.version = ctx.num_ecalls;
                        ctx.mem_state_file.write(reinterpret_cast<const char *>(&page), sizeof(page));
                    }
                }

                // Find the modified register
                u8 changed_reg = 0;
                for (int i = 0; i < 64; i++) {
                    u64 new_xpr_fpr = reg_val(i);
                    if (prev_xpr_fpr[i] != new_xpr_fpr) {
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
        } return;
        case 0b001: // CSRRW
        case 0b010: // CSRRS
            break;
        default:
            ERR("Unknown csr/ecall: 0x%lx (%b)", insn->inst, funct3);
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
        const u64 funct3 = (insn->inst >> 12) & 0x07;
        switch (funct3) {
        case 0b000: mem_dst_size = 1; break; // SB
        case 0b001: mem_dst_size = 2; break; // SH
        case 0b010: mem_dst_size = 4; break; // SW
        case 0b011: mem_dst_size = 8; break; // SD
        default: ERR("Unknown funct3: %03lb", funct3);
        }
    } break;
    case 0b0000111: // FpLoad
        rd = to_fp(rd);
        mem_addr = reg_val(insn->rs1) + insn->imm;
        need_mem_src_val = true;
        break;
    case 0b0100111: // FpStore
    {
        rs2 = to_fp(rs2);
        mem_addr = reg_val(insn->rs1) + insn->imm;
        const u64 funct3 = (insn->inst >> 12) & 0x07;
        switch (funct3) {
        case 0b010: mem_dst_size = 4; break; // FSW
        case 0b011: mem_dst_size = 8; break; // FSD
        default: ERR("Unknown funct3: %03lb", funct3);
        }
    } break;
    case 0b1000011: // FMADD.S
    case 0b1000111: // FMSUB.S
    case 0b1001011: // FNMSUB.S
    case 0b1001111: // FNMADD.S
        rd = to_fp(rd);
        rs1 = to_fp(rs1);
        rs2 = to_fp(rs2);
        rs3 = to_fp(rs3);
        break;
    case 0b1010011: // FpInst
    {
        const u64 rm = (insn->inst >> 12) & 0x07;
        if (rm == 0b111) frm = 66;
        fflags = 65;
        const u64 ty = (insn->inst >> 25) & 0x7f;
        switch (ty) {
            case 0b0010000: case 0b0010001: // FSGNJ.S, FSGNJN.S, FSGNJX.S, FSGNJ.D, FSGNJN.D, FSGNJX.D
            case 0b0101100: case 0b0101101: // FSQRT.D, FSQRT.S
            case 0b0100000: case 0b0100001: // FCVT.S.D, FCVT.D.S
                rd = to_fp(rd);
                rs1 = to_fp(rs1); // rs1:f,rd:f
                break;
            case 0b1100000: // FCVT.L.S, FCVT.LU.S, FCVT.W.S, FCVT.WU.S
            case 0b1100001: // FCVT.W.D, FCVT.WU.D, FCVT.L.D, FCVT.LU.D
            case 0b1110000: case 0b1110001: // FMV.X.W, FCLASS.S, FMV.X.D, FCLASS.D
                rs1 = to_fp(rs1); // rs1:f,rd:x
                break;
            case 0b0000000: case 0b0000001: // FADD.S, FADD.D
            case 0b0000100: case 0b0000101: // FSUB.S, FSUB.D
            case 0b0001000: case 0b0001001: // FMUL.S, FMUL.D
            case 0b0001100: case 0b0001101: // FDIV.S, FDIV.D
                rd = to_fp(rd);
                rs1 = to_fp(rs1);
                rs2 = to_fp(rs2); // rs1:f,rs2:f,rd:f
                break;
            case 0b1101000: // FCVT.S.L, FCVT.S.LU, FCVT.S.W, FCVT.S.WU
            case 0b1101001: // FCVT.D.W, FCVT.D.WU, FCVT.D.L, FCVT.D.LU
            case 0b1111000: // FMV.W.X
            case 0b1111001: // FMV.D.X
                rd = to_fp(rd); // rs1:x,rd:f
                break;
            case 0b1010000: // FEQ.S, FLT.S, FLE.S
            case 0b1010001: // FEQ.D, FLT.D, FLE.D
                rs1 = to_fp(rs1);
                rs2 = to_fp(rs2); // rs1:f,rs2:f,rd:x
                break;
            default:
                ERR("Unknown type: %07lb", ty);
        }
        break;
    }
    case 0b0101111: // ATOMIC
    {
        mem_addr = reg_val(insn->rs1);
        need_mem_src_val = true;
        const int funct3 = (insn->inst >> 12) & 0x07;
        switch (funct3) {
        case 0b010: mem_dst_size = 4; break;
        case 0b011: mem_dst_size = 8; break;
        default: ERR("Unknown funct3: %03b", funct3);
        }
    } break;
    case 0b0001111: // FENCE
        break;
    default: ERR("Unknown opcode: 0x%lx (%lb)", insn->inst, insn->inst & 0x7f);
    }
    // clang-format on

    const u64 rs1_val = reg_val(rs1), rs2_val = reg_val(rs2),
              rs3_val = reg_val(rs3), frm_val = reg_val(frm);

    ctx.pending_trace = [=](const rv_decode *next_insn) {
        const auto pc = insn->pc;
        const auto npc = next_insn ? next_insn->pc : 0;
        DBG("OP: rd = %d, rs1 = %d, rs2 = %d, r3 = %d, imm = 0x%x %d", rd, rs1,
            rs2, rs3, insn->imm, insn->op);
        u64 dst_val = reg_val(rd);
        u64 mem_src_val = need_mem_src_val ? dst_val : 0;
        u64 mem_dst_val = 0;
        if (mem_dst_size || need_mem_src_val) {
            u64 page_addr = mem_addr - mem_addr % page_size;
            auto [it, inserted] = ctx.pages.emplace(page_addr, Page {ctx.num_ecalls, page_addr, {}});
            if (inserted) {
                qemu_plugin_read_memory_vaddr(page_addr, ctx.mem_buf,
                                              page_size);
                assert(ctx.mem_buf->len == page_size);
                memcpy(it->second.data, ctx.mem_buf->data, page_size);
                ctx.mem_state_file.write(reinterpret_cast<const char *>(&it->second), sizeof(it->second));
            }
            if (mem_dst_size > 0) {
                qemu_plugin_read_memory_vaddr(mem_addr, ctx.mem_buf,
                                              mem_dst_size);
                assert(ctx.mem_buf->len == mem_dst_size);
                memcpy(&mem_dst_val, ctx.mem_buf->data, mem_dst_size);
                memcpy(it->second.data + mem_addr % page_size, &mem_dst_val,
                       mem_dst_size);
            }
        }
        u64 fflags_val = 0;
        if (fflags > 0)
            fflags_val = reg_val(fflags);
        InputOp op(pc, npc, insn->inst, {rs1, rs2, rs3, frm}, {rd, fflags},
                   {rs1_val, rs2_val, rs3_val, frm_val}, {dst_val, fflags_val},
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
static void vcpu_tb_trans(qemu_plugin_id_t, struct qemu_plugin_tb *tb) {
    struct qemu_plugin_insn *insn;

    const size_t n = qemu_plugin_tb_n_insns(tb);
    assert(n == 1 &&
           "TB must contain only one instruction. Otherwise, incorrect values "
           "will be read from registers. Did you forget to use "
           "-one-instr-per-tb?");

    insn = qemu_plugin_tb_get_insn(tb, 0);

    // NOTE: We will never free `dec`.
    rv_decode *dec = (rv_decode *)malloc(sizeof(rv_decode));
    qemu_plugin_insn_decode(insn, dec);
#if 0
    DEBUG("Disas: %s", qemu_plugin_insn_disas(insn));
#endif

    qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                           QEMU_PLUGIN_CB_R_REGS, dec);
}

/**
 * On plugin exit, print last instruction in cache
 */
static void plugin_exit(qemu_plugin_id_t, void *) {
    if (const auto trace =
            std::exchange(ctx.pending_trace, std::nullopt).value_or(nullptr)) {
        trace(nullptr);
    }

    ctx.mem_state_file.close();
    ctx.trace_file.close();
}

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
