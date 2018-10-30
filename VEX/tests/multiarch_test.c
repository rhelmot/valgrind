#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <string.h>

#include "libvex.h"

////////
// Globals related to controlling libVEX
////////

VexControl vc;
VexArchInfo vai_host;
VexArchInfo vai_guest;
VexArch arch_guest;
VexAbiInfo vbi;
VexGuestExtents vge;
VexTranslateArgs vta;
VexTranslateResult vtr;

char *msg_buffer = NULL;
size_t msg_capacity = 0, msg_current_size = 0;

jmp_buf jumpout;

////////
// libVEX callbacks
////////

__attribute__((noreturn))
static void failure_exit(void) {
    longjmp(jumpout, 1);
}

static void log_bytes(const HChar* bytes, SizeT nbytes) {
    if (msg_buffer == NULL) {
        msg_buffer = malloc(nbytes + 1);
        msg_capacity = nbytes + 1;
    }
    if (nbytes + 1 + msg_current_size > msg_capacity) {
        do {
            msg_capacity *= 2;
        } while (nbytes + 1 + msg_current_size > msg_capacity);
        msg_buffer = realloc(msg_buffer, msg_capacity);
    }

    memcpy(&msg_buffer[msg_current_size], bytes, nbytes);
    msg_buffer[msg_current_size + nbytes] = 0;
    msg_current_size += nbytes;
}

void clear_log() {
    if (msg_buffer != NULL) {
            free(msg_buffer);
            msg_buffer = NULL;
            msg_capacity = 0;
            msg_current_size = 0;
    }
}

void vex_dump(void) {
    if (msg_buffer == NULL) {
        puts("NO OUTPUT");
    } else {
        puts(msg_buffer);
        clear_log();
    }
}

static Bool chase_into_ok(void *closureV, Addr addr64) {
    return False;
}

static UInt needs_self_check(void *callback_opaque, VexRegisterUpdates* pxControl, const VexGuestExtents *guest_extents) {
    return 0;
}

static void *dispatch(void) {
    return NULL;
}

void vex_init() {
    LibVEX_default_VexControl(&vc);
    LibVEX_default_VexArchInfo(&vai_host);
    LibVEX_default_VexAbiInfo(&vbi);

    vc.iropt_verbosity = 0;
    vc.iropt_level = 0;
    vc.iropt_unroll_thresh = 0;
    vc.regalloc_version = 2;
	vc.guest_chase_thresh = 0;
    LibVEX_Init(&failure_exit, &log_bytes, 0, &vc);

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    vai_host.endness = VexEndnessLE;
#else
    vai_host.endness = VexEndnessBE;
#endif

    vbi.guest_stack_redzone_size = 0;
    vbi.guest_amd64_assume_fs_is_const = True;
    vbi.guest_amd64_assume_gs_is_const = True;

    vta.arch_guest          = VexArch_INVALID; // to be assigned later
#if __amd64__ || _WIN64
    vta.arch_host = VexArchAMD64;
#elif __i386__ || _WIN32
    vta.arch_host = VexArchX86;
#elif __arm__
    vta.arch_host = VexArchARM;
    vai_host.hwcaps = 7;
#elif __aarch64__
    vta.arch_host = VexArchARM64;
#elif __s390x__
    vta.arch_host = VexArchS390X;
    vai_host.hwcaps = VEX_HWCAPS_S390X_LDISP;
#else
#error "Unsupported host arch"
#endif

    vta.archinfo_host = vai_host;

    vta.guest_bytes         = NULL;
    vta.guest_bytes_addr    = 0;

    vta.callback_opaque     = NULL;
    vta.chase_into_ok       = chase_into_ok;
    vta.preamble_function   = NULL;
    vta.instrument1         = NULL;
    vta.instrument2         = NULL;
    vta.finaltidy            = NULL;
    vta.needs_self_check    = needs_self_check;

    vta.disp_cp_chain_me_to_slowEP = (void *)dispatch;
    vta.disp_cp_chain_me_to_fastEP = (void *)dispatch;
    vta.disp_cp_xindir = (void *)dispatch;
    vta.disp_cp_xassisted = (void *)dispatch;

    vta.guest_extents       = &vge;
    vta.host_bytes          = NULL;
    vta.host_bytes_size     = 0;
    vta.host_bytes_used     = NULL;
    vta.traceflags          = 0;
}

void set_guest(
        VexArch arch,
        VexEndness endness,
        UInt hwcaps) {
    arch_guest = arch;
    vai_guest.endness = endness;
    vai_guest.hwcaps = hwcaps;

    if (arch == VexArchAMD64) {
        vbi.guest_stack_redzone_size = 128;
    } else if (arch == VexArchPPC64) {
        vbi.guest_stack_redzone_size = 288;
    }
}

IRSB *vex_lift(
        const unsigned char *data,
        unsigned long long insn_addr,
        unsigned int max_insns,
        int opt_level,
        int traceflags) {

    VexRegisterUpdates pxControl;

    vta.archinfo_guest = vai_guest;
    vta.arch_guest = arch_guest;
    vta.abiinfo_both = vbi;
    vta.guest_bytes = (UChar *)data;
    vta.guest_bytes_addr = (Addr)insn_addr;
    vta.traceflags = traceflags;

    vc.guest_max_insns = max_insns;
    vc.iropt_level = opt_level;

    clear_log();

    if (setjmp(jumpout) == 0) {
        LibVEX_Update_Control(&vc);
        return LibVEX_FrontEnd(&vta, &vtr, &pxControl);
    } else {
        return NULL;
    }
}

int main() {
    vex_init();

    set_guest(VexArchAMD64, VexEndnessLE, VEX_HWCAPS_X86_MMXEXT |
                                          VEX_HWCAPS_X86_SSE1 |
                                          VEX_HWCAPS_X86_SSE2 |
                                          VEX_HWCAPS_X86_SSE3 |
                                          VEX_HWCAPS_X86_LZCNT);
    IRSB *irsb = vex_lift("\xc3", 0x1000, 1, 0, 0);
    if (irsb == NULL) {
        vex_dump();
    } else {
        ppIRSB(irsb);
        vex_dump();
    }
}
