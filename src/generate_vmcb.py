#!/usr/bin/python3

import operator

class Range:
    def __init__(self, name, byte_offset, bit_offset, bit_length):
        self.name = name
        self.byte_offset = byte_offset
        self.bit_offset = bit_offset
        self.bit_length = bit_length

    def get_position(self):
        return self.byte_offset * 8 + self.bit_offset

    def get_length(self):
        return self.bit_length

    def get_name(self):
        return self.name

    def get_end(self):
        return self.get_position() + self.get_length()

    def is_vector(self):
        return False

class Vector:
    def __init__(self, name, byte_offset, byte_length):
        self.name = name
        self.byte_offset = byte_offset
        self.byte_length = byte_length
        self.ranges = []

    def is_vector(self):
        return True

    def get_end(self):
        return self.get_position() + self.get_length()

    def get_position(self):
        return self.byte_offset * 8

    def get_length(self):
        return self.byte_length * 8

    def get_name(self):
        return self.name

    def add_range(self, name, byte_offset, bit_offset, bit_length):
        #fixup bit_offset. should never be >= 8
        self.ranges.append(Range(name, byte_offset, bit_offset, bit_length))

    def get_ranges(self):
        sorted_ranges = sorted(self.ranges, key=lambda u: u.get_position())

        # Verify that we don't have overlaps
        for i, range in enumerate(sorted_ranges[:-1]):
            assert(range.get_position() + range.get_length() <= sorted_ranges[i+1].get_position())
                
        return sorted_ranges

class Structure:
    def __init__(self):
        self.naked_ranges = []
        self.vectors = []

    def add_vector(self, vector):
        self.vectors.append(vector)

    def add_naked_range(self, range):
        self.naked_ranges.append(range)

    def get_vectors(self):
        sorted_vectors = sorted(self.vectors, key=lambda u: u.get_position())
        return sorted_vectors

    def get_naked_ranges(self):
        sorted_ranges = sorted(self.naked_ranges, key=lambda u: u.get_position())
        return sorted_ranges

    def get_all_items(self):
        items = self.get_vectors() + self.get_naked_ranges()
        sorted_items = sorted(items, key=lambda u: u.get_position())
        return sorted_items

def generate_header(f):
    f.write("#ifndef MINI_SVM_VMCB\n")
    f.write("#define MINI_SVM_VMCB\n")
    f.write("\n")
    f.write("/* This file is auto-generated */\n")
    f.write("/* Please check generate_vmcb.py */\n")
    f.write("\n")
    f.write("#include <linux/types.h>\n")
    f.write("#include <linux/build_bug.h>\n")
    f.write("\n")

def generate_footer(f):
    f.write("#endif\n")

def generate_body_structure(f, structure, name):

    def select_type(width):
        if width <= 8:
            return "__u8", width == 8
        if width <= 16:
            return "__u16", width == 16
        if width <= 32:
            return "__u32", width == 32
        if width <= 64:
            return "__u64", width == 64
        assert(width <= 64)
    f.write(f"struct {name} {{\n")

    padding_id = 0

    def generate_item(f, prev_range, item, is_nested):
        nonlocal padding_id
        tabs = "\t" * (2 if is_nested else 1)
        pos = item.get_position()
        name = item.get_name()
        bitwidth = item.get_length()
        type, full_width = select_type(bitwidth)
        if prev_range and prev_range.get_end() < pos:
            aligned_up_to_next_byte = int((prev_range.get_end() + 7) / 8) * 8
            remaining_bits_to_a_byte = aligned_up_to_next_byte - prev_range.get_end()
            if remaining_bits_to_a_byte > 0:
                f.write(f"{tabs}u8 pad_pre_{padding_id} : {remaining_bits_to_a_byte};\n")
                padding_id += 1

            current_entry_offset = pos % 8
            current_entry_byte_aligned_start = pos - current_entry_offset
            num_remaining_bytes = int((current_entry_byte_aligned_start - aligned_up_to_next_byte) / 8)
            if num_remaining_bytes > 0:
                f.write(f"{tabs}u8 pad_full_{padding_id}[{num_remaining_bytes}];\n")
                padding_id += 1

            if current_entry_offset != 0:
                f.write(f"{tabs}u8 pad_post_{padding_id} : {current_entry_offset};\n")
                padding_id += 1
        if pos % bitwidth == 0 and full_width == True:
            f.write(f"{tabs}{type} {name};\n")
        else:
            f.write(f"{tabs}{type} {name} : {bitwidth};\n")

    prev_range = None
    for it in structure.get_all_items():
        if it.is_vector():
            vec_name = it.get_name()
            vec_size = it.get_length()
            f.write(f"\tstruct {vec_name}_t {{\n")
            for item in it.get_ranges():
                generate_item(f, prev_range, item, True)
                prev_range = item
            f.write(f"\t}} {vec_name} ;\n")
            prev_range = it
        else:
            generate_item(f, prev_range, it, False)
            prev_range = it
    f.write("} __attribute__ ((packed));\n\n")

def generate_vmcb(f):
    f.write("struct mini_svm_vmcb {\n")
    f.write("\tstruct mini_svm_vmcb_control control;\n")
    f.write("\tunsigned char pad[0x400 - sizeof(struct mini_svm_vmcb_control)];\n")
    f.write("\tstruct mini_svm_vmcb_save_area save;\n")
    f.write("} __attribute__ ((aligned (0x1000)));\n\n")

def generate_static_checks(f):
    f.write("static_assert(offsetof(struct mini_svm_vmcb_control, cr_intercepts) == 0);\n")
    f.write("static_assert(offsetof(struct mini_svm_vmcb_control, dr_intercepts) == 0x4);\n")
    f.write("static_assert(offsetof(struct mini_svm_vmcb_control, excp_vec_intercepts) == 0x8);\n")
    f.write("static_assert(offsetof(struct mini_svm_vmcb_control, guest_asid) == 0x58);\n")
    f.write("static_assert(offsetof(struct mini_svm_vmcb_control, nRIP) == 0xc8);\n")
    f.write("static_assert(offsetof(struct mini_svm_vmcb, save) == 0x400);\n")
    f.write("static_assert(sizeof(struct mini_svm_vmcb) <= 0x1000);\n")

def generate_vmsa_static_checks(f):
    f.write("static_assert(offsetof(struct mini_svm_vmcb_save, reg_cs) == 0x10);\n")
    f.write("static_assert(offsetof(struct mini_svm_vmcb_save, reg_gdtr) == 0x60);\n")
    f.write("static_assert(offsetof(struct mini_svm_vmcb_save, efer) == 0xd0);\n")
    f.write("static_assert(offsetof(struct mini_svm_vmcb_save, rflags) == 0x170);\n")
    f.write("static_assert(offsetof(struct mini_svm_vmcb_save, cstar) == 0x210);\n")
    f.write("static_assert(offsetof(struct mini_svm_vmcb_save, spec_ctrl) == 0x2e0);\n")

def main():
    vmcb = Structure()

    # CR intercepts
    c_vector = Vector("cr_intercepts", byte_offset=0, byte_length=0x4)
    for i, op in enumerate(["rd", "wr"]):
        for u in range(16):
            c_vector.add_range(f"cr_{u}_{op}_intercept", byte_offset=0x0, bit_offset=u + i * 16, bit_length=1)
    vmcb.add_vector(c_vector)

    # DR intercepts
    c_vector = Vector("dr_intercepts", byte_offset=0x4, byte_length=0x4)
    for i, op in enumerate(["rd", "wr"]):
        for u in range(16):
            c_vector.add_range(f"dr_{u}_{op}_intercept", byte_offset=0x4, bit_offset=u + i * 16, bit_length=1)
    vmcb.add_vector(c_vector)

    # Exception vector intercepts
    c_vector = Vector("excp_vec_intercepts", byte_offset=0x8, byte_length=0x2)
    for u in range(16):
        c_vector.add_range(f"exception_{u}_intercept", byte_offset=0x8, bit_offset=u, bit_length=1)
    vmcb.add_vector(c_vector)

    c_vector = Vector("vec3", byte_offset=0xC, byte_length=0x4)
    for i, name in enumerate(["intr", "nmi", "smi", "init", \
              "vintr", "cr0", "idtr_rd", "gdtr_rd", \
              "ldtr_rd", "tr_rd", "idtr_wr", "gdtr_wr", \
              "ldtr_wr", "tr_wr", "rdtsc", "rdpmc",
              "pushf", "popf", "cpuid", "rsm", \
              "iret", "intn", "invd", "pause", \
              "hlt", "invlpg", "invlpga", "ioio_prot", \
              "msr_prot", "task_switch", "ferr_freeze", \
              "shutdown_events"]):
        c_vector.add_range(f"{name}_intercept", byte_offset=0xc, bit_offset=i, bit_length=1)
    vmcb.add_vector(c_vector)

    c_vector = Vector("vec4", byte_offset=0x10, byte_length=0x4)
    for i, name in enumerate(["vmrun", "vmmcall", "vmload", "vmsave", \
                              "stgi", "clgi", "skinit", "rdtscp", "icebp", \
                              "wbinvd_wbnoinvd", "monitor_monitorx", "mwait_mwaitx", "xsetbv" \
                              "rdpru", "efer_wr_after_done"]):
        c_vector.add_range(f"{name}_intercept", byte_offset=0x10, bit_offset=i, bit_length=1)

    for u in range(16):
        c_vector.add_range(f"cr{u}_wr_after_done_intercept", byte_offset=0x10, bit_offset=u + 16, bit_length=1)
    vmcb.add_vector(c_vector)

    vmcb.add_naked_range(Range(f"guest_asid", byte_offset=0x58, bit_offset = 0, bit_length=32))
    vmcb.add_naked_range(Range(f"exitcode", byte_offset=0x70, bit_offset = 0, bit_length=64))
    vmcb.add_naked_range(Range(f"exitinfo_v1", byte_offset=0x78, bit_offset = 0, bit_length=64))
    vmcb.add_naked_range(Range(f"exitinfo_v2", byte_offset=0x80, bit_offset = 0, bit_length=64))
    vmcb.add_naked_range(Range(f"exitintinfo", byte_offset=0x88, bit_offset = 0, bit_length=64))

    vmcb.add_naked_range(Range(f"ncr3", byte_offset=0xb0, bit_offset = 0, bit_length=64))

    vmcb.add_naked_range(Range(f"nRIP", byte_offset=0xc8, bit_offset = 0, bit_length=64))

    c_vector = Vector("vmsa_info", byte_offset=0x108, byte_length=0x8)
    c_vector.add_range(f"padding", byte_offset=0x108, bit_offset = 0, bit_length=12)
    c_vector.add_range(f"vmsa_ptr", byte_offset=0x108, bit_offset = 12, bit_length=52 - 12)
    vmcb.add_vector(c_vector)

    vmsa = Structure()
    for index, reg in enumerate(["es", "cs", "ss", "ds", "fs", "gs", "gdtr", "ldtr", "idtr", "tr"]):
        c_vector = Vector(f"reg_{reg}", byte_offset=0x10 * index, byte_length=0x10)
        c_vector.add_range(f"selector", byte_offset=0x10 * index + 0, bit_offset = 0, bit_length=0x2 * 8)
        c_vector.add_range(f"attribute", byte_offset=0x10 * index + 2, bit_offset = 0, bit_length=0x2 * 8)
        c_vector.add_range(f"limit", byte_offset=0x10 * index + 4, bit_offset = 0, bit_length=0x4 * 8)
        c_vector.add_range(f"base", byte_offset=0x10 * index + 8, bit_offset = 0, bit_length=0x8 * 8)
        vmsa.add_vector(c_vector)

    vmsa.add_naked_range(Range(f"cpl", byte_offset=0xcb, bit_offset = 0, bit_length=8))
    vmsa.add_naked_range(Range(f"efer", byte_offset=0xd0, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"cr4", byte_offset=0x148, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"cr3", byte_offset=0x150, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"cr0", byte_offset=0x158, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"dr7", byte_offset=0x160, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"dr6", byte_offset=0x168, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"rflags", byte_offset=0x170, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"rip", byte_offset=0x178, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"rsp", byte_offset=0x1d8, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"s_cet", byte_offset=0x1e0, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"ssp", byte_offset=0x1e8, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"isst_addr", byte_offset=0x1f0, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"rax", byte_offset=0x1f8, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"star", byte_offset=0x200, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"lstar", byte_offset=0x208, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"cstar", byte_offset=0x210, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"sfmask", byte_offset=0x218, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"kernel_gs_base", byte_offset=0x220, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"sysenter_cs", byte_offset=0x228, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"sysenter_esp", byte_offset=0x230, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"sysenter_eip", byte_offset=0x238, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"cr2", byte_offset=0x240, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"g_pat", byte_offset=0x268, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"dbgctl", byte_offset=0x270, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"br_from", byte_offset=0x278, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"br_to", byte_offset=0x280, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"lastexcpfrom", byte_offset=0x288, bit_offset = 0, bit_length=64))
    vmsa.add_naked_range(Range(f"spec_ctrl", byte_offset=0x2e0, bit_offset = 0, bit_length=32))

    with open("mini-svm-vmcb.h", "w") as vmcb_f:
        generate_header(vmcb_f)
        generate_body_structure(vmcb_f, vmsa, "mini_svm_vmcb_save_area")
        generate_body_structure(vmcb_f, vmcb, "mini_svm_vmcb_control")
        generate_vmcb(vmcb_f)
        generate_static_checks(vmcb_f)
        generate_footer(vmcb_f)

if __name__ == "__main__":
    main()
