/*
 * QEMU disassembler -- RISC-V specific header.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISAS_RISCV_H
#define DISAS_RISCV_H

#include "target/riscv/cpu_cfg.h"

/* types */

typedef uint64_t rv_inst;
typedef uint16_t rv_opcode;

/* enums */

typedef enum {
    /* 0 is reserved for rv_op_illegal. */
    rv_op_lui = 1,
    rv_op_auipc = 2,
    rv_op_jal = 3,
    rv_op_jalr = 4,
    rv_op_beq = 5,
    rv_op_bne = 6,
    rv_op_blt = 7,
    rv_op_bge = 8,
    rv_op_bltu = 9,
    rv_op_bgeu = 10,
    rv_op_lb = 11,
    rv_op_lh = 12,
    rv_op_lw = 13,
    rv_op_lbu = 14,
    rv_op_lhu = 15,
    rv_op_sb = 16,
    rv_op_sh = 17,
    rv_op_sw = 18,
    rv_op_addi = 19,
    rv_op_slti = 20,
    rv_op_sltiu = 21,
    rv_op_xori = 22,
    rv_op_ori = 23,
    rv_op_andi = 24,
    rv_op_slli = 25,
    rv_op_srli = 26,
    rv_op_srai = 27,
    rv_op_add = 28,
    rv_op_sub = 29,
    rv_op_sll = 30,
    rv_op_slt = 31,
    rv_op_sltu = 32,
    rv_op_xor = 33,
    rv_op_srl = 34,
    rv_op_sra = 35,
    rv_op_or = 36,
    rv_op_and = 37,
    rv_op_fence = 38,
    rv_op_fence_i = 39,
    rv_op_lwu = 40,
    rv_op_ld = 41,
    rv_op_sd = 42,
    rv_op_addiw = 43,
    rv_op_slliw = 44,
    rv_op_srliw = 45,
    rv_op_sraiw = 46,
    rv_op_addw = 47,
    rv_op_subw = 48,
    rv_op_sllw = 49,
    rv_op_srlw = 50,
    rv_op_sraw = 51,
    rv_op_ldu = 52,
    rv_op_lq = 53,
    rv_op_sq = 54,
    rv_op_addid = 55,
    rv_op_sllid = 56,
    rv_op_srlid = 57,
    rv_op_sraid = 58,
    rv_op_addd = 59,
    rv_op_subd = 60,
    rv_op_slld = 61,
    rv_op_srld = 62,
    rv_op_srad = 63,
    rv_op_mul = 64,
    rv_op_mulh = 65,
    rv_op_mulhsu = 66,
    rv_op_mulhu = 67,
    rv_op_div = 68,
    rv_op_divu = 69,
    rv_op_rem = 70,
    rv_op_remu = 71,
    rv_op_mulw = 72,
    rv_op_divw = 73,
    rv_op_divuw = 74,
    rv_op_remw = 75,
    rv_op_remuw = 76,
    rv_op_muld = 77,
    rv_op_divd = 78,
    rv_op_divud = 79,
    rv_op_remd = 80,
    rv_op_remud = 81,
    rv_op_lr_w = 82,
    rv_op_sc_w = 83,
    rv_op_amoswap_w = 84,
    rv_op_amoadd_w = 85,
    rv_op_amoxor_w = 86,
    rv_op_amoor_w = 87,
    rv_op_amoand_w = 88,
    rv_op_amomin_w = 89,
    rv_op_amomax_w = 90,
    rv_op_amominu_w = 91,
    rv_op_amomaxu_w = 92,
    rv_op_lr_d = 93,
    rv_op_sc_d = 94,
    rv_op_amoswap_d = 95,
    rv_op_amoadd_d = 96,
    rv_op_amoxor_d = 97,
    rv_op_amoor_d = 98,
    rv_op_amoand_d = 99,
    rv_op_amomin_d = 100,
    rv_op_amomax_d = 101,
    rv_op_amominu_d = 102,
    rv_op_amomaxu_d = 103,
    rv_op_lr_q = 104,
    rv_op_sc_q = 105,
    rv_op_amoswap_q = 106,
    rv_op_amoadd_q = 107,
    rv_op_amoxor_q = 108,
    rv_op_amoor_q = 109,
    rv_op_amoand_q = 110,
    rv_op_amomin_q = 111,
    rv_op_amomax_q = 112,
    rv_op_amominu_q = 113,
    rv_op_amomaxu_q = 114,
    rv_op_ecall = 115,
    rv_op_ebreak = 116,
    rv_op_uret = 117,
    rv_op_sret = 118,
    rv_op_hret = 119,
    rv_op_mret = 120,
    rv_op_dret = 121,
    rv_op_sfence_vm = 122,
    rv_op_sfence_vma = 123,
    rv_op_wfi = 124,
    rv_op_csrrw = 125,
    rv_op_csrrs = 126,
    rv_op_csrrc = 127,
    rv_op_csrrwi = 128,
    rv_op_csrrsi = 129,
    rv_op_csrrci = 130,
    rv_op_flw = 131,
    rv_op_fsw = 132,
    rv_op_fmadd_s = 133,
    rv_op_fmsub_s = 134,
    rv_op_fnmsub_s = 135,
    rv_op_fnmadd_s = 136,
    rv_op_fadd_s = 137,
    rv_op_fsub_s = 138,
    rv_op_fmul_s = 139,
    rv_op_fdiv_s = 140,
    rv_op_fsgnj_s = 141,
    rv_op_fsgnjn_s = 142,
    rv_op_fsgnjx_s = 143,
    rv_op_fmin_s = 144,
    rv_op_fmax_s = 145,
    rv_op_fsqrt_s = 146,
    rv_op_fle_s = 147,
    rv_op_flt_s = 148,
    rv_op_feq_s = 149,
    rv_op_fcvt_w_s = 150,
    rv_op_fcvt_wu_s = 151,
    rv_op_fcvt_s_w = 152,
    rv_op_fcvt_s_wu = 153,
    rv_op_fmv_x_s = 154,
    rv_op_fclass_s = 155,
    rv_op_fmv_s_x = 156,
    rv_op_fcvt_l_s = 157,
    rv_op_fcvt_lu_s = 158,
    rv_op_fcvt_s_l = 159,
    rv_op_fcvt_s_lu = 160,
    rv_op_fld = 161,
    rv_op_fsd = 162,
    rv_op_fmadd_d = 163,
    rv_op_fmsub_d = 164,
    rv_op_fnmsub_d = 165,
    rv_op_fnmadd_d = 166,
    rv_op_fadd_d = 167,
    rv_op_fsub_d = 168,
    rv_op_fmul_d = 169,
    rv_op_fdiv_d = 170,
    rv_op_fsgnj_d = 171,
    rv_op_fsgnjn_d = 172,
    rv_op_fsgnjx_d = 173,
    rv_op_fmin_d = 174,
    rv_op_fmax_d = 175,
    rv_op_fcvt_s_d = 176,
    rv_op_fcvt_d_s = 177,
    rv_op_fsqrt_d = 178,
    rv_op_fle_d = 179,
    rv_op_flt_d = 180,
    rv_op_feq_d = 181,
    rv_op_fcvt_w_d = 182,
    rv_op_fcvt_wu_d = 183,
    rv_op_fcvt_d_w = 184,
    rv_op_fcvt_d_wu = 185,
    rv_op_fclass_d = 186,
    rv_op_fcvt_l_d = 187,
    rv_op_fcvt_lu_d = 188,
    rv_op_fmv_x_d = 189,
    rv_op_fcvt_d_l = 190,
    rv_op_fcvt_d_lu = 191,
    rv_op_fmv_d_x = 192,
    rv_op_flq = 193,
    rv_op_fsq = 194,
    rv_op_fmadd_q = 195,
    rv_op_fmsub_q = 196,
    rv_op_fnmsub_q = 197,
    rv_op_fnmadd_q = 198,
    rv_op_fadd_q = 199,
    rv_op_fsub_q = 200,
    rv_op_fmul_q = 201,
    rv_op_fdiv_q = 202,
    rv_op_fsgnj_q = 203,
    rv_op_fsgnjn_q = 204,
    rv_op_fsgnjx_q = 205,
    rv_op_fmin_q = 206,
    rv_op_fmax_q = 207,
    rv_op_fcvt_s_q = 208,
    rv_op_fcvt_q_s = 209,
    rv_op_fcvt_d_q = 210,
    rv_op_fcvt_q_d = 211,
    rv_op_fsqrt_q = 212,
    rv_op_fle_q = 213,
    rv_op_flt_q = 214,
    rv_op_feq_q = 215,
    rv_op_fcvt_w_q = 216,
    rv_op_fcvt_wu_q = 217,
    rv_op_fcvt_q_w = 218,
    rv_op_fcvt_q_wu = 219,
    rv_op_fclass_q = 220,
    rv_op_fcvt_l_q = 221,
    rv_op_fcvt_lu_q = 222,
    rv_op_fcvt_q_l = 223,
    rv_op_fcvt_q_lu = 224,
    rv_op_fmv_x_q = 225,
    rv_op_fmv_q_x = 226,
    rv_op_c_addi4spn = 227,
    rv_op_c_fld = 228,
    rv_op_c_lw = 229,
    rv_op_c_flw = 230,
    rv_op_c_fsd = 231,
    rv_op_c_sw = 232,
    rv_op_c_fsw = 233,
    rv_op_c_nop = 234,
    rv_op_c_addi = 235,
    rv_op_c_jal = 236,
    rv_op_c_li = 237,
    rv_op_c_addi16sp = 238,
    rv_op_c_lui = 239,
    rv_op_c_srli = 240,
    rv_op_c_srai = 241,
    rv_op_c_andi = 242,
    rv_op_c_sub = 243,
    rv_op_c_xor = 244,
    rv_op_c_or = 245,
    rv_op_c_and = 246,
    rv_op_c_subw = 247,
    rv_op_c_addw = 248,
    rv_op_c_j = 249,
    rv_op_c_beqz = 250,
    rv_op_c_bnez = 251,
    rv_op_c_slli = 252,
    rv_op_c_fldsp = 253,
    rv_op_c_lwsp = 254,
    rv_op_c_flwsp = 255,
    rv_op_c_jr = 256,
    rv_op_c_mv = 257,
    rv_op_c_ebreak = 258,
    rv_op_c_jalr = 259,
    rv_op_c_add = 260,
    rv_op_c_fsdsp = 261,
    rv_op_c_swsp = 262,
    rv_op_c_fswsp = 263,
    rv_op_c_ld = 264,
    rv_op_c_sd = 265,
    rv_op_c_addiw = 266,
    rv_op_c_ldsp = 267,
    rv_op_c_sdsp = 268,
    rv_op_c_lq = 269,
    rv_op_c_sq = 270,
    rv_op_c_lqsp = 271,
    rv_op_c_sqsp = 272,
    rv_op_nop = 273,
    rv_op_mv = 274,
    rv_op_not = 275,
    rv_op_neg = 276,
    rv_op_negw = 277,
    rv_op_sext_w = 278,
    rv_op_seqz = 279,
    rv_op_snez = 280,
    rv_op_sltz = 281,
    rv_op_sgtz = 282,
    rv_op_fmv_s = 283,
    rv_op_fabs_s = 284,
    rv_op_fneg_s = 285,
    rv_op_fmv_d = 286,
    rv_op_fabs_d = 287,
    rv_op_fneg_d = 288,
    rv_op_fmv_q = 289,
    rv_op_fabs_q = 290,
    rv_op_fneg_q = 291,
    rv_op_beqz = 292,
    rv_op_bnez = 293,
    rv_op_blez = 294,
    rv_op_bgez = 295,
    rv_op_bltz = 296,
    rv_op_bgtz = 297,
    rv_op_ble = 298,
    rv_op_bleu = 299,
    rv_op_bgt = 300,
    rv_op_bgtu = 301,
    rv_op_j = 302,
    rv_op_ret = 303,
    rv_op_jr = 304,
    rv_op_rdcycle = 305,
    rv_op_rdtime = 306,
    rv_op_rdinstret = 307,
    rv_op_rdcycleh = 308,
    rv_op_rdtimeh = 309,
    rv_op_rdinstreth = 310,
    rv_op_frcsr = 311,
    rv_op_frrm = 312,
    rv_op_frflags = 313,
    rv_op_fscsr = 314,
    rv_op_fsrm = 315,
    rv_op_fsflags = 316,
    rv_op_fsrmi = 317,
    rv_op_fsflagsi = 318,
    rv_op_bseti = 319,
    rv_op_bclri = 320,
    rv_op_binvi = 321,
    rv_op_bexti = 322,
    rv_op_rori = 323,
    rv_op_clz = 324,
    rv_op_ctz = 325,
    rv_op_cpop = 326,
    rv_op_sext_h = 327,
    rv_op_sext_b = 328,
    rv_op_xnor = 329,
    rv_op_orn = 330,
    rv_op_andn = 331,
    rv_op_rol = 332,
    rv_op_ror = 333,
    rv_op_sh1add = 334,
    rv_op_sh2add = 335,
    rv_op_sh3add = 336,
    rv_op_sh1add_uw = 337,
    rv_op_sh2add_uw = 338,
    rv_op_sh3add_uw = 339,
    rv_op_clmul = 340,
    rv_op_clmulr = 341,
    rv_op_clmulh = 342,
    rv_op_min = 343,
    rv_op_minu = 344,
    rv_op_max = 345,
    rv_op_maxu = 346,
    rv_op_clzw = 347,
    rv_op_ctzw = 348,
    rv_op_cpopw = 349,
    rv_op_slli_uw = 350,
    rv_op_add_uw = 351,
    rv_op_rolw = 352,
    rv_op_rorw = 353,
    rv_op_rev8 = 354,
    rv_op_zext_h = 355,
    rv_op_roriw = 356,
    rv_op_orc_b = 357,
    rv_op_bset = 358,
    rv_op_bclr = 359,
    rv_op_binv = 360,
    rv_op_bext = 361,
    rv_op_aes32esmi = 362,
    rv_op_aes32esi = 363,
    rv_op_aes32dsmi = 364,
    rv_op_aes32dsi = 365,
    rv_op_aes64ks1i = 366,
    rv_op_aes64ks2 = 367,
    rv_op_aes64im = 368,
    rv_op_aes64esm = 369,
    rv_op_aes64es = 370,
    rv_op_aes64dsm = 371,
    rv_op_aes64ds = 372,
    rv_op_sha256sig0 = 373,
    rv_op_sha256sig1 = 374,
    rv_op_sha256sum0 = 375,
    rv_op_sha256sum1 = 376,
    rv_op_sha512sig0 = 377,
    rv_op_sha512sig1 = 378,
    rv_op_sha512sum0 = 379,
    rv_op_sha512sum1 = 380,
    rv_op_sha512sum0r = 381,
    rv_op_sha512sum1r = 382,
    rv_op_sha512sig0l = 383,
    rv_op_sha512sig0h = 384,
    rv_op_sha512sig1l = 385,
    rv_op_sha512sig1h = 386,
    rv_op_sm3p0 = 387,
    rv_op_sm3p1 = 388,
    rv_op_sm4ed = 389,
    rv_op_sm4ks = 390,
    rv_op_brev8 = 391,
    rv_op_pack = 392,
    rv_op_packh = 393,
    rv_op_packw = 394,
    rv_op_unzip = 395,
    rv_op_zip = 396,
    rv_op_xperm4 = 397,
    rv_op_xperm8 = 398,
    rv_op_vle8_v = 399,
    rv_op_vle16_v = 400,
    rv_op_vle32_v = 401,
    rv_op_vle64_v = 402,
    rv_op_vse8_v = 403,
    rv_op_vse16_v = 404,
    rv_op_vse32_v = 405,
    rv_op_vse64_v = 406,
    rv_op_vlm_v = 407,
    rv_op_vsm_v = 408,
    rv_op_vlse8_v = 409,
    rv_op_vlse16_v = 410,
    rv_op_vlse32_v = 411,
    rv_op_vlse64_v = 412,
    rv_op_vsse8_v = 413,
    rv_op_vsse16_v = 414,
    rv_op_vsse32_v = 415,
    rv_op_vsse64_v = 416,
    rv_op_vluxei8_v = 417,
    rv_op_vluxei16_v = 418,
    rv_op_vluxei32_v = 419,
    rv_op_vluxei64_v = 420,
    rv_op_vloxei8_v = 421,
    rv_op_vloxei16_v = 422,
    rv_op_vloxei32_v = 423,
    rv_op_vloxei64_v = 424,
    rv_op_vsuxei8_v = 425,
    rv_op_vsuxei16_v = 426,
    rv_op_vsuxei32_v = 427,
    rv_op_vsuxei64_v = 428,
    rv_op_vsoxei8_v = 429,
    rv_op_vsoxei16_v = 430,
    rv_op_vsoxei32_v = 431,
    rv_op_vsoxei64_v = 432,
    rv_op_vle8ff_v = 433,
    rv_op_vle16ff_v = 434,
    rv_op_vle32ff_v = 435,
    rv_op_vle64ff_v = 436,
    rv_op_vl1re8_v = 437,
    rv_op_vl1re16_v = 438,
    rv_op_vl1re32_v = 439,
    rv_op_vl1re64_v = 440,
    rv_op_vl2re8_v = 441,
    rv_op_vl2re16_v = 442,
    rv_op_vl2re32_v = 443,
    rv_op_vl2re64_v = 444,
    rv_op_vl4re8_v = 445,
    rv_op_vl4re16_v = 446,
    rv_op_vl4re32_v = 447,
    rv_op_vl4re64_v = 448,
    rv_op_vl8re8_v = 449,
    rv_op_vl8re16_v = 450,
    rv_op_vl8re32_v = 451,
    rv_op_vl8re64_v = 452,
    rv_op_vs1r_v = 453,
    rv_op_vs2r_v = 454,
    rv_op_vs4r_v = 455,
    rv_op_vs8r_v = 456,
    rv_op_vadd_vv = 457,
    rv_op_vadd_vx = 458,
    rv_op_vadd_vi = 459,
    rv_op_vsub_vv = 460,
    rv_op_vsub_vx = 461,
    rv_op_vrsub_vx = 462,
    rv_op_vrsub_vi = 463,
    rv_op_vwaddu_vv = 464,
    rv_op_vwaddu_vx = 465,
    rv_op_vwadd_vv = 466,
    rv_op_vwadd_vx = 467,
    rv_op_vwsubu_vv = 468,
    rv_op_vwsubu_vx = 469,
    rv_op_vwsub_vv = 470,
    rv_op_vwsub_vx = 471,
    rv_op_vwaddu_wv = 472,
    rv_op_vwaddu_wx = 473,
    rv_op_vwadd_wv = 474,
    rv_op_vwadd_wx = 475,
    rv_op_vwsubu_wv = 476,
    rv_op_vwsubu_wx = 477,
    rv_op_vwsub_wv = 478,
    rv_op_vwsub_wx = 479,
    rv_op_vadc_vvm = 480,
    rv_op_vadc_vxm = 481,
    rv_op_vadc_vim = 482,
    rv_op_vmadc_vvm = 483,
    rv_op_vmadc_vxm = 484,
    rv_op_vmadc_vim = 485,
    rv_op_vsbc_vvm = 486,
    rv_op_vsbc_vxm = 487,
    rv_op_vmsbc_vvm = 488,
    rv_op_vmsbc_vxm = 489,
    rv_op_vand_vv = 490,
    rv_op_vand_vx = 491,
    rv_op_vand_vi = 492,
    rv_op_vor_vv = 493,
    rv_op_vor_vx = 494,
    rv_op_vor_vi = 495,
    rv_op_vxor_vv = 496,
    rv_op_vxor_vx = 497,
    rv_op_vxor_vi = 498,
    rv_op_vsll_vv = 499,
    rv_op_vsll_vx = 500,
    rv_op_vsll_vi = 501,
    rv_op_vsrl_vv = 502,
    rv_op_vsrl_vx = 503,
    rv_op_vsrl_vi = 504,
    rv_op_vsra_vv = 505,
    rv_op_vsra_vx = 506,
    rv_op_vsra_vi = 507,
    rv_op_vnsrl_wv = 508,
    rv_op_vnsrl_wx = 509,
    rv_op_vnsrl_wi = 510,
    rv_op_vnsra_wv = 511,
    rv_op_vnsra_wx = 512,
    rv_op_vnsra_wi = 513,
    rv_op_vmseq_vv = 514,
    rv_op_vmseq_vx = 515,
    rv_op_vmseq_vi = 516,
    rv_op_vmsne_vv = 517,
    rv_op_vmsne_vx = 518,
    rv_op_vmsne_vi = 519,
    rv_op_vmsltu_vv = 520,
    rv_op_vmsltu_vx = 521,
    rv_op_vmslt_vv = 522,
    rv_op_vmslt_vx = 523,
    rv_op_vmsleu_vv = 524,
    rv_op_vmsleu_vx = 525,
    rv_op_vmsleu_vi = 526,
    rv_op_vmsle_vv = 527,
    rv_op_vmsle_vx = 528,
    rv_op_vmsle_vi = 529,
    rv_op_vmsgtu_vx = 530,
    rv_op_vmsgtu_vi = 531,
    rv_op_vmsgt_vx = 532,
    rv_op_vmsgt_vi = 533,
    rv_op_vminu_vv = 534,
    rv_op_vminu_vx = 535,
    rv_op_vmin_vv = 536,
    rv_op_vmin_vx = 537,
    rv_op_vmaxu_vv = 538,
    rv_op_vmaxu_vx = 539,
    rv_op_vmax_vv = 540,
    rv_op_vmax_vx = 541,
    rv_op_vmul_vv = 542,
    rv_op_vmul_vx = 543,
    rv_op_vmulh_vv = 544,
    rv_op_vmulh_vx = 545,
    rv_op_vmulhu_vv = 546,
    rv_op_vmulhu_vx = 547,
    rv_op_vmulhsu_vv = 548,
    rv_op_vmulhsu_vx = 549,
    rv_op_vdivu_vv = 550,
    rv_op_vdivu_vx = 551,
    rv_op_vdiv_vv = 552,
    rv_op_vdiv_vx = 553,
    rv_op_vremu_vv = 554,
    rv_op_vremu_vx = 555,
    rv_op_vrem_vv = 556,
    rv_op_vrem_vx = 557,
    rv_op_vwmulu_vv = 558,
    rv_op_vwmulu_vx = 559,
    rv_op_vwmulsu_vv = 560,
    rv_op_vwmulsu_vx = 561,
    rv_op_vwmul_vv = 562,
    rv_op_vwmul_vx = 563,
    rv_op_vmacc_vv = 564,
    rv_op_vmacc_vx = 565,
    rv_op_vnmsac_vv = 566,
    rv_op_vnmsac_vx = 567,
    rv_op_vmadd_vv = 568,
    rv_op_vmadd_vx = 569,
    rv_op_vnmsub_vv = 570,
    rv_op_vnmsub_vx = 571,
    rv_op_vwmaccu_vv = 572,
    rv_op_vwmaccu_vx = 573,
    rv_op_vwmacc_vv = 574,
    rv_op_vwmacc_vx = 575,
    rv_op_vwmaccsu_vv = 576,
    rv_op_vwmaccsu_vx = 577,
    rv_op_vwmaccus_vx = 578,
    rv_op_vmv_v_v = 579,
    rv_op_vmv_v_x = 580,
    rv_op_vmv_v_i = 581,
    rv_op_vmerge_vvm = 582,
    rv_op_vmerge_vxm = 583,
    rv_op_vmerge_vim = 584,
    rv_op_vsaddu_vv = 585,
    rv_op_vsaddu_vx = 586,
    rv_op_vsaddu_vi = 587,
    rv_op_vsadd_vv = 588,
    rv_op_vsadd_vx = 589,
    rv_op_vsadd_vi = 590,
    rv_op_vssubu_vv = 591,
    rv_op_vssubu_vx = 592,
    rv_op_vssub_vv = 593,
    rv_op_vssub_vx = 594,
    rv_op_vaadd_vv = 595,
    rv_op_vaadd_vx = 596,
    rv_op_vaaddu_vv = 597,
    rv_op_vaaddu_vx = 598,
    rv_op_vasub_vv = 599,
    rv_op_vasub_vx = 600,
    rv_op_vasubu_vv = 601,
    rv_op_vasubu_vx = 602,
    rv_op_vsmul_vv = 603,
    rv_op_vsmul_vx = 604,
    rv_op_vssrl_vv = 605,
    rv_op_vssrl_vx = 606,
    rv_op_vssrl_vi = 607,
    rv_op_vssra_vv = 608,
    rv_op_vssra_vx = 609,
    rv_op_vssra_vi = 610,
    rv_op_vnclipu_wv = 611,
    rv_op_vnclipu_wx = 612,
    rv_op_vnclipu_wi = 613,
    rv_op_vnclip_wv = 614,
    rv_op_vnclip_wx = 615,
    rv_op_vnclip_wi = 616,
    rv_op_vfadd_vv = 617,
    rv_op_vfadd_vf = 618,
    rv_op_vfsub_vv = 619,
    rv_op_vfsub_vf = 620,
    rv_op_vfrsub_vf = 621,
    rv_op_vfwadd_vv = 622,
    rv_op_vfwadd_vf = 623,
    rv_op_vfwadd_wv = 624,
    rv_op_vfwadd_wf = 625,
    rv_op_vfwsub_vv = 626,
    rv_op_vfwsub_vf = 627,
    rv_op_vfwsub_wv = 628,
    rv_op_vfwsub_wf = 629,
    rv_op_vfmul_vv = 630,
    rv_op_vfmul_vf = 631,
    rv_op_vfdiv_vv = 632,
    rv_op_vfdiv_vf = 633,
    rv_op_vfrdiv_vf = 634,
    rv_op_vfwmul_vv = 635,
    rv_op_vfwmul_vf = 636,
    rv_op_vfmacc_vv = 637,
    rv_op_vfmacc_vf = 638,
    rv_op_vfnmacc_vv = 639,
    rv_op_vfnmacc_vf = 640,
    rv_op_vfmsac_vv = 641,
    rv_op_vfmsac_vf = 642,
    rv_op_vfnmsac_vv = 643,
    rv_op_vfnmsac_vf = 644,
    rv_op_vfmadd_vv = 645,
    rv_op_vfmadd_vf = 646,
    rv_op_vfnmadd_vv = 647,
    rv_op_vfnmadd_vf = 648,
    rv_op_vfmsub_vv = 649,
    rv_op_vfmsub_vf = 650,
    rv_op_vfnmsub_vv = 651,
    rv_op_vfnmsub_vf = 652,
    rv_op_vfwmacc_vv = 653,
    rv_op_vfwmacc_vf = 654,
    rv_op_vfwnmacc_vv = 655,
    rv_op_vfwnmacc_vf = 656,
    rv_op_vfwmsac_vv = 657,
    rv_op_vfwmsac_vf = 658,
    rv_op_vfwnmsac_vv = 659,
    rv_op_vfwnmsac_vf = 660,
    rv_op_vfsqrt_v = 661,
    rv_op_vfrsqrt7_v = 662,
    rv_op_vfrec7_v = 663,
    rv_op_vfmin_vv = 664,
    rv_op_vfmin_vf = 665,
    rv_op_vfmax_vv = 666,
    rv_op_vfmax_vf = 667,
    rv_op_vfsgnj_vv = 668,
    rv_op_vfsgnj_vf = 669,
    rv_op_vfsgnjn_vv = 670,
    rv_op_vfsgnjn_vf = 671,
    rv_op_vfsgnjx_vv = 672,
    rv_op_vfsgnjx_vf = 673,
    rv_op_vfslide1up_vf = 674,
    rv_op_vfslide1down_vf = 675,
    rv_op_vmfeq_vv = 676,
    rv_op_vmfeq_vf = 677,
    rv_op_vmfne_vv = 678,
    rv_op_vmfne_vf = 679,
    rv_op_vmflt_vv = 680,
    rv_op_vmflt_vf = 681,
    rv_op_vmfle_vv = 682,
    rv_op_vmfle_vf = 683,
    rv_op_vmfgt_vf = 684,
    rv_op_vmfge_vf = 685,
    rv_op_vfclass_v = 686,
    rv_op_vfmerge_vfm = 687,
    rv_op_vfmv_v_f = 688,
    rv_op_vfcvt_xu_f_v = 689,
    rv_op_vfcvt_x_f_v = 690,
    rv_op_vfcvt_f_xu_v = 691,
    rv_op_vfcvt_f_x_v = 692,
    rv_op_vfcvt_rtz_xu_f_v = 693,
    rv_op_vfcvt_rtz_x_f_v = 694,
    rv_op_vfwcvt_xu_f_v = 695,
    rv_op_vfwcvt_x_f_v = 696,
    rv_op_vfwcvt_f_xu_v = 697,
    rv_op_vfwcvt_f_x_v = 698,
    rv_op_vfwcvt_f_f_v = 699,
    rv_op_vfwcvt_rtz_xu_f_v = 700,
    rv_op_vfwcvt_rtz_x_f_v = 701,
    rv_op_vfncvt_xu_f_w = 702,
    rv_op_vfncvt_x_f_w = 703,
    rv_op_vfncvt_f_xu_w = 704,
    rv_op_vfncvt_f_x_w = 705,
    rv_op_vfncvt_f_f_w = 706,
    rv_op_vfncvt_rod_f_f_w = 707,
    rv_op_vfncvt_rtz_xu_f_w = 708,
    rv_op_vfncvt_rtz_x_f_w = 709,
    rv_op_vredsum_vs = 710,
    rv_op_vredand_vs = 711,
    rv_op_vredor_vs = 712,
    rv_op_vredxor_vs = 713,
    rv_op_vredminu_vs = 714,
    rv_op_vredmin_vs = 715,
    rv_op_vredmaxu_vs = 716,
    rv_op_vredmax_vs = 717,
    rv_op_vwredsumu_vs = 718,
    rv_op_vwredsum_vs = 719,
    rv_op_vfredusum_vs = 720,
    rv_op_vfredosum_vs = 721,
    rv_op_vfredmin_vs = 722,
    rv_op_vfredmax_vs = 723,
    rv_op_vfwredusum_vs = 724,
    rv_op_vfwredosum_vs = 725,
    rv_op_vmand_mm = 726,
    rv_op_vmnand_mm = 727,
    rv_op_vmandn_mm = 728,
    rv_op_vmxor_mm = 729,
    rv_op_vmor_mm = 730,
    rv_op_vmnor_mm = 731,
    rv_op_vmorn_mm = 732,
    rv_op_vmxnor_mm = 733,
    rv_op_vcpop_m = 734,
    rv_op_vfirst_m = 735,
    rv_op_vmsbf_m = 736,
    rv_op_vmsif_m = 737,
    rv_op_vmsof_m = 738,
    rv_op_viota_m = 739,
    rv_op_vid_v = 740,
    rv_op_vmv_x_s = 741,
    rv_op_vmv_s_x = 742,
    rv_op_vfmv_f_s = 743,
    rv_op_vfmv_s_f = 744,
    rv_op_vslideup_vx = 745,
    rv_op_vslideup_vi = 746,
    rv_op_vslide1up_vx = 747,
    rv_op_vslidedown_vx = 748,
    rv_op_vslidedown_vi = 749,
    rv_op_vslide1down_vx = 750,
    rv_op_vrgather_vv = 751,
    rv_op_vrgatherei16_vv = 752,
    rv_op_vrgather_vx = 753,
    rv_op_vrgather_vi = 754,
    rv_op_vcompress_vm = 755,
    rv_op_vmv1r_v = 756,
    rv_op_vmv2r_v = 757,
    rv_op_vmv4r_v = 758,
    rv_op_vmv8r_v = 759,
    rv_op_vzext_vf2 = 760,
    rv_op_vzext_vf4 = 761,
    rv_op_vzext_vf8 = 762,
    rv_op_vsext_vf2 = 763,
    rv_op_vsext_vf4 = 764,
    rv_op_vsext_vf8 = 765,
    rv_op_vsetvli = 766,
    rv_op_vsetivli = 767,
    rv_op_vsetvl = 768,
    rv_op_c_zext_b = 769,
    rv_op_c_sext_b = 770,
    rv_op_c_zext_h = 771,
    rv_op_c_sext_h = 772,
    rv_op_c_zext_w = 773,
    rv_op_c_not = 774,
    rv_op_c_mul = 775,
    rv_op_c_lbu = 776,
    rv_op_c_lhu = 777,
    rv_op_c_lh = 778,
    rv_op_c_sb = 779,
    rv_op_c_sh = 780,
    rv_op_cm_push = 781,
    rv_op_cm_pop = 782,
    rv_op_cm_popret = 783,
    rv_op_cm_popretz = 784,
    rv_op_cm_mva01s = 785,
    rv_op_cm_mvsa01 = 786,
    rv_op_cm_jt = 787,
    rv_op_cm_jalt = 788,
    rv_op_czero_eqz = 789,
    rv_op_czero_nez = 790,
    rv_op_fcvt_bf16_s = 791,
    rv_op_fcvt_s_bf16 = 792,
    rv_op_vfncvtbf16_f_f_w = 793,
    rv_op_vfwcvtbf16_f_f_v = 794,
    rv_op_vfwmaccbf16_vv = 795,
    rv_op_vfwmaccbf16_vf = 796,
    rv_op_flh = 797,
    rv_op_fsh = 798,
    rv_op_fmv_h_x = 799,
    rv_op_fmv_x_h = 800,
    rv_op_fli_s = 801,
    rv_op_fli_d = 802,
    rv_op_fli_q = 803,
    rv_op_fli_h = 804,
    rv_op_fminm_s = 805,
    rv_op_fmaxm_s = 806,
    rv_op_fminm_d = 807,
    rv_op_fmaxm_d = 808,
    rv_op_fminm_q = 809,
    rv_op_fmaxm_q = 810,
    rv_op_fminm_h = 811,
    rv_op_fmaxm_h = 812,
    rv_op_fround_s = 813,
    rv_op_froundnx_s = 814,
    rv_op_fround_d = 815,
    rv_op_froundnx_d = 816,
    rv_op_fround_q = 817,
    rv_op_froundnx_q = 818,
    rv_op_fround_h = 819,
    rv_op_froundnx_h = 820,
    rv_op_fcvtmod_w_d = 821,
    rv_op_fmvh_x_d = 822,
    rv_op_fmvp_d_x = 823,
    rv_op_fmvh_x_q = 824,
    rv_op_fmvp_q_x = 825,
    rv_op_fleq_s = 826,
    rv_op_fltq_s = 827,
    rv_op_fleq_d = 828,
    rv_op_fltq_d = 829,
    rv_op_fleq_q = 830,
    rv_op_fltq_q = 831,
    rv_op_fleq_h = 832,
    rv_op_fltq_h = 833,
    rv_op_vaesdf_vv = 834,
    rv_op_vaesdf_vs = 835,
    rv_op_vaesdm_vv = 836,
    rv_op_vaesdm_vs = 837,
    rv_op_vaesef_vv = 838,
    rv_op_vaesef_vs = 839,
    rv_op_vaesem_vv = 840,
    rv_op_vaesem_vs = 841,
    rv_op_vaeskf1_vi = 842,
    rv_op_vaeskf2_vi = 843,
    rv_op_vaesz_vs = 844,
    rv_op_vandn_vv = 845,
    rv_op_vandn_vx = 846,
    rv_op_vbrev_v = 847,
    rv_op_vbrev8_v = 848,
    rv_op_vclmul_vv = 849,
    rv_op_vclmul_vx = 850,
    rv_op_vclmulh_vv = 851,
    rv_op_vclmulh_vx = 852,
    rv_op_vclz_v = 853,
    rv_op_vcpop_v = 854,
    rv_op_vctz_v = 855,
    rv_op_vghsh_vv = 856,
    rv_op_vgmul_vv = 857,
    rv_op_vrev8_v = 858,
    rv_op_vrol_vv = 859,
    rv_op_vrol_vx = 860,
    rv_op_vror_vv = 861,
    rv_op_vror_vx = 862,
    rv_op_vror_vi = 863,
    rv_op_vsha2ch_vv = 864,
    rv_op_vsha2cl_vv = 865,
    rv_op_vsha2ms_vv = 866,
    rv_op_vsm3c_vi = 867,
    rv_op_vsm3me_vv = 868,
    rv_op_vsm4k_vi = 869,
    rv_op_vsm4r_vv = 870,
    rv_op_vsm4r_vs = 871,
    rv_op_vwsll_vv = 872,
    rv_op_vwsll_vx = 873,
    rv_op_vwsll_vi = 874,
    rv_op_amocas_w = 875,
    rv_op_amocas_d = 876,
    rv_op_amocas_q = 877,
} rv_op;

typedef enum {
    rv32,
    rv64,
    rv128
} rv_isa;

typedef enum {
    rv_rm_rne = 0,
    rv_rm_rtz = 1,
    rv_rm_rdn = 2,
    rv_rm_rup = 3,
    rv_rm_rmm = 4,
    rv_rm_dyn = 7,
} rv_rm;

typedef enum {
    rv_fence_i = 8,
    rv_fence_o = 4,
    rv_fence_r = 2,
    rv_fence_w = 1,
} rv_fence;

typedef enum {
    rv_ireg_zero,
    rv_ireg_ra,
    rv_ireg_sp,
    rv_ireg_gp,
    rv_ireg_tp,
    rv_ireg_t0,
    rv_ireg_t1,
    rv_ireg_t2,
    rv_ireg_s0,
    rv_ireg_s1,
    rv_ireg_a0,
    rv_ireg_a1,
    rv_ireg_a2,
    rv_ireg_a3,
    rv_ireg_a4,
    rv_ireg_a5,
    rv_ireg_a6,
    rv_ireg_a7,
    rv_ireg_s2,
    rv_ireg_s3,
    rv_ireg_s4,
    rv_ireg_s5,
    rv_ireg_s6,
    rv_ireg_s7,
    rv_ireg_s8,
    rv_ireg_s9,
    rv_ireg_s10,
    rv_ireg_s11,
    rv_ireg_t3,
    rv_ireg_t4,
    rv_ireg_t5,
    rv_ireg_t6,
} rv_ireg;

typedef enum {
    rvc_end,
    rvc_rd_eq_ra,
    rvc_rd_eq_x0,
    rvc_rs1_eq_x0,
    rvc_rs2_eq_x0,
    rvc_rs2_eq_rs1,
    rvc_rs1_eq_ra,
    rvc_imm_eq_zero,
    rvc_imm_eq_n1,
    rvc_imm_eq_p1,
    rvc_csr_eq_0x001,
    rvc_csr_eq_0x002,
    rvc_csr_eq_0x003,
    rvc_csr_eq_0xc00,
    rvc_csr_eq_0xc01,
    rvc_csr_eq_0xc02,
    rvc_csr_eq_0xc80,
    rvc_csr_eq_0xc81,
    rvc_csr_eq_0xc82,
} rvc_constraint;

typedef enum {
    rv_codec_illegal,
    rv_codec_none,
    rv_codec_u,
    rv_codec_uj,
    rv_codec_i,
    rv_codec_i_sh5,
    rv_codec_i_sh6,
    rv_codec_i_sh7,
    rv_codec_i_csr,
    rv_codec_s,
    rv_codec_sb,
    rv_codec_r,
    rv_codec_r_m,
    rv_codec_r4_m,
    rv_codec_r_a,
    rv_codec_r_l,
    rv_codec_r_f,
    rv_codec_cb,
    rv_codec_cb_imm,
    rv_codec_cb_sh5,
    rv_codec_cb_sh6,
    rv_codec_ci,
    rv_codec_ci_sh5,
    rv_codec_ci_sh6,
    rv_codec_ci_16sp,
    rv_codec_ci_lwsp,
    rv_codec_ci_ldsp,
    rv_codec_ci_lqsp,
    rv_codec_ci_li,
    rv_codec_ci_lui,
    rv_codec_ci_none,
    rv_codec_ciw_4spn,
    rv_codec_cj,
    rv_codec_cj_jal,
    rv_codec_cl_lw,
    rv_codec_cl_ld,
    rv_codec_cl_lq,
    rv_codec_cr,
    rv_codec_cr_mv,
    rv_codec_cr_jalr,
    rv_codec_cr_jr,
    rv_codec_cs,
    rv_codec_cs_sw,
    rv_codec_cs_sd,
    rv_codec_cs_sq,
    rv_codec_css_swsp,
    rv_codec_css_sdsp,
    rv_codec_css_sqsp,
    rv_codec_k_bs,
    rv_codec_k_rnum,
    rv_codec_v_r,
    rv_codec_v_ldst,
    rv_codec_v_i,
    rv_codec_vsetvli,
    rv_codec_vsetivli,
    rv_codec_vror_vi,
    rv_codec_zcb_ext,
    rv_codec_zcb_mul,
    rv_codec_zcb_lb,
    rv_codec_zcb_lh,
    rv_codec_zcmp_cm_pushpop,
    rv_codec_zcmp_cm_mv,
    rv_codec_zcmt_jt,
    rv_codec_r2_imm5,
    rv_codec_r2,
    rv_codec_r2_imm6,
    rv_codec_r_imm2,
    rv_codec_r2_immhl,
    rv_codec_r2_imm2_imm5,
    rv_codec_fli,
} rv_codec;

/* structures */

typedef struct {
    const int op;
    const rvc_constraint *constraints;
} rv_comp_data;

typedef struct {
    const char * const name;
    const rv_codec codec;
    const char * const format;
    const rv_comp_data *pseudo;
    const short decomp_rv32;
    const short decomp_rv64;
    const short decomp_rv128;
    const short decomp_data;
} rv_opcode_data;

typedef struct rv_decode
{
    RISCVCPUConfig *cfg;
    uint64_t  pc;
    uint64_t  inst;
    const rv_opcode_data *opcode_data;
    int32_t   imm;
    int32_t   imm1;
    uint16_t  op;
    uint8_t   codec;
    uint8_t   rd;
    uint8_t   rs1;
    uint8_t   rs2;
    uint8_t   rs3;
    uint8_t   rm;
    uint8_t   pred;
    uint8_t   succ;
    uint8_t   aq;
    uint8_t   rl;
    uint8_t   bs;
    uint8_t   rnum;
    uint8_t   vm;
    uint32_t  vzimm;
    uint8_t   rlist;
} rv_decode;

enum {
    rv_op_illegal = 0
};

enum {
    rvcd_imm_nz = 0x1
};

/* instruction formats */

#define rv_fmt_none                   "O\t"
#define rv_fmt_rs1                    "O\t1"
#define rv_fmt_offset                 "O\to"
#define rv_fmt_pred_succ              "O\tp,s"
#define rv_fmt_rs1_rs2                "O\t1,2"
#define rv_fmt_rd_imm                 "O\t0,i"
#define rv_fmt_rd_uimm                "O\t0,Ui"
#define rv_fmt_rd_offset              "O\t0,o"
#define rv_fmt_rd_uoffset             "O\t0,Uo"
#define rv_fmt_rd_rs1_rs2             "O\t0,1,2"
#define rv_fmt_frd_rs1                "O\t3,1"
#define rv_fmt_frd_rs1_rs2            "O\t3,1,2"
#define rv_fmt_frd_frs1               "O\t3,4"
#define rv_fmt_rd_frs1                "O\t0,4"
#define rv_fmt_rd_frs1_frs2           "O\t0,4,5"
#define rv_fmt_frd_frs1_frs2          "O\t3,4,5"
#define rv_fmt_rm_frd_frs1            "O\tr,3,4"
#define rv_fmt_rm_frd_rs1             "O\tr,3,1"
#define rv_fmt_rm_rd_frs1             "O\tr,0,4"
#define rv_fmt_rm_frd_frs1_frs2       "O\tr,3,4,5"
#define rv_fmt_rm_frd_frs1_frs2_frs3  "O\tr,3,4,5,6"
#define rv_fmt_rd_rs1_imm             "O\t0,1,i"
#define rv_fmt_rd_rs1_offset          "O\t0,1,i"
#define rv_fmt_rd_offset_rs1          "O\t0,i(1)"
#define rv_fmt_frd_offset_rs1         "O\t3,i(1)"
#define rv_fmt_rd_csr_rs1             "O\t0,c,1"
#define rv_fmt_rd_csr_zimm            "O\t0,c,7"
#define rv_fmt_rs2_offset_rs1         "O\t2,i(1)"
#define rv_fmt_frs2_offset_rs1        "O\t5,i(1)"
#define rv_fmt_rs1_rs2_offset         "O\t1,2,o"
#define rv_fmt_rs2_rs1_offset         "O\t2,1,o"
#define rv_fmt_aqrl_rd_rs2_rs1        "OAR\t0,2,(1)"
#define rv_fmt_aqrl_rd_rs1            "OAR\t0,(1)"
#define rv_fmt_rd                     "O\t0"
#define rv_fmt_rd_zimm                "O\t0,7"
#define rv_fmt_rd_rs1                 "O\t0,1"
#define rv_fmt_rd_rs2                 "O\t0,2"
#define rv_fmt_rs1_offset             "O\t1,o"
#define rv_fmt_rs2_offset             "O\t2,o"
#define rv_fmt_rs1_rs2_bs             "O\t1,2,b"
#define rv_fmt_rd_rs1_rnum            "O\t0,1,n"
#define rv_fmt_ldst_vd_rs1_vm         "O\tD,(1)m"
#define rv_fmt_ldst_vd_rs1_rs2_vm     "O\tD,(1),2m"
#define rv_fmt_ldst_vd_rs1_vs2_vm     "O\tD,(1),Fm"
#define rv_fmt_vd_vs2_vs1             "O\tD,F,E"
#define rv_fmt_vd_vs2_vs1_vl          "O\tD,F,El"
#define rv_fmt_vd_vs2_vs1_vm          "O\tD,F,Em"
#define rv_fmt_vd_vs2_rs1_vl          "O\tD,F,1l"
#define rv_fmt_vd_vs2_fs1_vl          "O\tD,F,4l"
#define rv_fmt_vd_vs2_rs1_vm          "O\tD,F,1m"
#define rv_fmt_vd_vs2_fs1_vm          "O\tD,F,4m"
#define rv_fmt_vd_vs2_imm_vl          "O\tD,F,il"
#define rv_fmt_vd_vs2_imm_vm          "O\tD,F,im"
#define rv_fmt_vd_vs2_uimm            "O\tD,F,u"
#define rv_fmt_vd_vs2_uimm_vm         "O\tD,F,um"
#define rv_fmt_vd_vs1_vs2_vm          "O\tD,E,Fm"
#define rv_fmt_vd_rs1_vs2_vm          "O\tD,1,Fm"
#define rv_fmt_vd_fs1_vs2_vm          "O\tD,4,Fm"
#define rv_fmt_vd_vs1                 "O\tD,E"
#define rv_fmt_vd_rs1                 "O\tD,1"
#define rv_fmt_vd_fs1                 "O\tD,4"
#define rv_fmt_vd_imm                 "O\tD,i"
#define rv_fmt_vd_vs2                 "O\tD,F"
#define rv_fmt_vd_vs2_vm              "O\tD,Fm"
#define rv_fmt_rd_vs2_vm              "O\t0,Fm"
#define rv_fmt_rd_vs2                 "O\t0,F"
#define rv_fmt_fd_vs2                 "O\t3,F"
#define rv_fmt_vd_vm                  "O\tDm"
#define rv_fmt_vsetvli                "O\t0,1,v"
#define rv_fmt_vsetivli               "O\t0,u,v"
#define rv_fmt_rs1_rs2_zce_ldst       "O\t2,i(1)"
#define rv_fmt_push_rlist             "O\tx,-i"
#define rv_fmt_pop_rlist              "O\tx,i"
#define rv_fmt_zcmt_index             "O\ti"
#define rv_fmt_rd_rs1_rs2_imm         "O\t0,1,2,i"
#define rv_fmt_frd_rs1_rs2_imm        "O\t3,1,2,i"
#define rv_fmt_rd_rs1_immh_imml       "O\t0,1,i,j"
#define rv_fmt_rd_rs1_immh_imml_addr  "O\t0,(1),i,j"
#define rv_fmt_rd2_imm                "O\t0,2,(1),i"
#define rv_fmt_fli                    "O\t3,h"

#endif /* DISAS_RISCV_H */
