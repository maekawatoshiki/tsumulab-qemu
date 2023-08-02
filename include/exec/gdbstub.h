#ifndef GDBSTUB_H
#define GDBSTUB_H

#define DEFAULT_GDBSTUB_PORT "1234"

/* GDB breakpoint/watchpoint types */
#define GDB_BREAKPOINT_SW        0
#define GDB_BREAKPOINT_HW        1
#define GDB_WATCHPOINT_WRITE     2
#define GDB_WATCHPOINT_READ      3
#define GDB_WATCHPOINT_ACCESS    4

typedef struct GDBFeature {
    const char *xmlname;
    const char *xml;
    int num_regs;
} GDBFeature;


/* Get or set a register.  Returns the size of the register.  */
typedef int (*gdb_get_reg_cb)(CPUArchState *env, GByteArray *buf, int reg);
typedef int (*gdb_set_reg_cb)(CPUArchState *env, uint8_t *buf, int reg);
void gdb_register_coprocessor(CPUState *cpu,
                              gdb_get_reg_cb get_reg, gdb_set_reg_cb set_reg,
                              const GDBFeature *feature, int g_pos);

/**
 * gdbserver_start: start the gdb server
 * @port_or_device: connection spec for gdb
 *
 * For CONFIG_USER this is either a tcp port or a path to a fifo. For
 * system emulation you can use a full chardev spec for your gdbserver
 * port.
 */
int gdbserver_start(const char *port_or_device);

const GDBFeature *gdb_find_static_feature(const char *xmlname);

void gdb_set_stop_cpu(CPUState *cpu);

/**
 * gdb_has_xml:
 * This is an ugly hack to cope with both new and old gdb.
 * If gdb sends qXfer:features:read then assume we're talking to a newish
 * gdb that understands target descriptions.
 */
extern bool gdb_has_xml;

/* in gdbstub-xml.c, generated by scripts/feature_to_c.py */
extern const GDBFeature gdb_static_features[];

#endif
