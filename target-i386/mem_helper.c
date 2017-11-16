/*
 *  x86 memory access helpers
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "qemu/int128.h"
#include "tcg.h"

#include "qsim-vm.h"
#include "qsim-context.h"

extern bool atomic_flag;
static int atomic_locked;
int nonatomic_locked = 0;

extern uint64_t qsim_icount;
uint64_t qsim_eip, qsim_locked_addr;
extern inst_cb_t    qsim_inst_cb;
extern mem_cb_t     qsim_mem_cb;
extern atomic_cb_t  qsim_atomic_cb;
extern int_cb_t     qsim_int_cb;
extern reg_cb_t     qsim_reg_cb;

extern bool qsim_gen_callbacks;
extern bool qsim_sys_callbacks;

extern int qsim_id;
extern int qsim_memop_flag;
extern uint64_t qsim_tpid, curr_tpid[32];

extern qsim_ucontext_t main_context, qemu_context;

extern int get_cpuidx(CPUX86State *env);

extern CPUX86State* get_env(int cpu_idx);

void helper_cmpxchg8b_unlocked(CPUX86State *env, target_ulong a0)
{
    uintptr_t ra = GETPC();
    uint64_t oldv, cmpv, newv;
    int eflags;

    eflags = cpu_cc_compute_all(env, CC_OP);

    cmpv = deposit64(env->regs[R_EAX], 32, 32, env->regs[R_EDX]);
    newv = deposit64(env->regs[R_EBX], 32, 32, env->regs[R_ECX]);

    oldv = cpu_ldq_data_ra(env, a0, ra);
    newv = (cmpv == oldv ? newv : oldv);
    /* always do the store */
    cpu_stq_data_ra(env, a0, newv, ra);

    if (oldv == cmpv) {
        eflags |= CC_Z;
    } else {
        env->regs[R_EAX] = (uint32_t)oldv;
        env->regs[R_EDX] = (uint32_t)(oldv >> 32);
        eflags &= ~CC_Z;
    }
    CC_SRC = eflags;
}

void helper_cmpxchg8b(CPUX86State *env, target_ulong a0)
{
#ifdef CONFIG_ATOMIC64
    uint64_t oldv, cmpv, newv;
    int eflags;

    eflags = cpu_cc_compute_all(env, CC_OP);

    cmpv = deposit64(env->regs[R_EAX], 32, 32, env->regs[R_EDX]);
    newv = deposit64(env->regs[R_EBX], 32, 32, env->regs[R_ECX]);

#ifdef CONFIG_USER_ONLY
    {
        uint64_t *haddr = g2h(a0);
        cmpv = cpu_to_le64(cmpv);
        newv = cpu_to_le64(newv);
        oldv = atomic_cmpxchg__nocheck(haddr, cmpv, newv);
        oldv = le64_to_cpu(oldv);
    }
#else
    {
        uintptr_t ra = GETPC();
        int mem_idx = cpu_mmu_index(env, false);
        TCGMemOpIdx oi = make_memop_idx(MO_TEQ, mem_idx);
        oldv = helper_atomic_cmpxchgq_le_mmu(env, a0, cmpv, newv, oi, ra);
    }
#endif

    if (oldv == cmpv) {
        eflags |= CC_Z;
    } else {
        env->regs[R_EAX] = (uint32_t)oldv;
        env->regs[R_EDX] = (uint32_t)(oldv >> 32);
        eflags &= ~CC_Z;
    }
    CC_SRC = eflags;
#else
    cpu_loop_exit_atomic(ENV_GET_CPU(env), GETPC());
#endif /* CONFIG_ATOMIC64 */
}

#ifdef TARGET_X86_64
void helper_cmpxchg16b_unlocked(CPUX86State *env, target_ulong a0)
{
    uintptr_t ra = GETPC();
    Int128 oldv, cmpv, newv;
    uint64_t o0, o1;
    int eflags;
    bool success;

    if ((a0 & 0xf) != 0) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }
    eflags = cpu_cc_compute_all(env, CC_OP);

    cmpv = int128_make128(env->regs[R_EAX], env->regs[R_EDX]);
    newv = int128_make128(env->regs[R_EBX], env->regs[R_ECX]);

    o0 = cpu_ldq_data_ra(env, a0 + 0, ra);
    o1 = cpu_ldq_data_ra(env, a0 + 8, ra);

    oldv = int128_make128(o0, o1);
    success = int128_eq(oldv, cmpv);
    if (!success) {
        newv = oldv;
    }

    cpu_stq_data_ra(env, a0 + 0, int128_getlo(newv), ra);
    cpu_stq_data_ra(env, a0 + 8, int128_gethi(newv), ra);

    if (success) {
        eflags |= CC_Z;
    } else {
        env->regs[R_EAX] = int128_getlo(oldv);
        env->regs[R_EDX] = int128_gethi(oldv);
        eflags &= ~CC_Z;
    }
    CC_SRC = eflags;
}

void helper_cmpxchg16b(CPUX86State *env, target_ulong a0)
{
    uintptr_t ra = GETPC();

    if ((a0 & 0xf) != 0) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    } else {
#ifndef CONFIG_ATOMIC128
        cpu_loop_exit_atomic(ENV_GET_CPU(env), ra);
#else
        int eflags = cpu_cc_compute_all(env, CC_OP);

        Int128 cmpv = int128_make128(env->regs[R_EAX], env->regs[R_EDX]);
        Int128 newv = int128_make128(env->regs[R_EBX], env->regs[R_ECX]);

        int mem_idx = cpu_mmu_index(env, false);
        TCGMemOpIdx oi = make_memop_idx(MO_TEQ | MO_ALIGN_16, mem_idx);
        Int128 oldv = helper_atomic_cmpxchgo_le_mmu(env, a0, cmpv,
                                                    newv, oi, ra);

        if (int128_eq(oldv, cmpv)) {
            eflags |= CC_Z;
        } else {
            env->regs[R_EAX] = int128_getlo(oldv);
            env->regs[R_EDX] = int128_gethi(oldv);
            eflags &= ~CC_Z;
        }
        CC_SRC = eflags;
#endif
    }
}
#endif

void helper_boundw(CPUX86State *env, target_ulong a0, int v)
{
    int low, high;

    low = cpu_ldsw_data_ra(env, a0, GETPC());
    high = cpu_ldsw_data_ra(env, a0 + 2, GETPC());
    v = (int16_t)v;
    if (v < low || v > high) {
        if (env->hflags & HF_MPX_EN_MASK) {
            env->bndcs_regs.sts = 0;
        }
        raise_exception_ra(env, EXCP05_BOUND, GETPC());
    }
}

void helper_boundl(CPUX86State *env, target_ulong a0, int v)
{
    int low, high;

    low = cpu_ldl_data_ra(env, a0, GETPC());
    high = cpu_ldl_data_ra(env, a0 + 4, GETPC());
    if (v < low || v > high) {
        if (env->hflags & HF_MPX_EN_MASK) {
            env->bndcs_regs.sts = 0;
        }
        raise_exception_ra(env, EXCP05_BOUND, GETPC());
    }
}

#if !defined(CONFIG_USER_ONLY)
/* try to fill the TLB and return an exception if error. If retaddr is
 * NULL, it means that the function was called in C code (i.e. not
 * from generated code or from helper.c)
 */
/* XXX: fix it to restore all registers */
void tlb_fill(CPUState *cs, target_ulong addr, MMUAccessType access_type,
              int mmu_idx, uintptr_t retaddr)
{
    int ret;

    ret = x86_cpu_handle_mmu_fault(cs, addr, access_type, mmu_idx);
    if (ret) {
        X86CPU *cpu = X86_CPU(cs);
        CPUX86State *env = &cpu->env;

        raise_exception_err_ra(env, cs->exception_index, env->error_code, retaddr);
    }
}
#endif

#include "qsim-vm.h"
#include "qsim-func.h"

#include "qsim-context.h"
#include "qsim-x86-regs.h"

extern void *qemu_get_ram_ptr(ram_addr_t addr);

void helper_atomic_callback(void)
{
    atomic_flag = !atomic_flag;
    // pid based callbacks
    if (!qsim_sys_callbacks && curr_tpid[qsim_id] != qsim_tpid)
        return;

    /* if atomic callback returns non-zero, suspend execution */
    if (qsim_gen_callbacks && qsim_atomic_cb && qsim_atomic_cb(qsim_id))
        swapcontext(&qemu_context, &main_context);

    return;
}

uint8_t mem_rd(CPUX86State *env, uint64_t paddr);
void mem_wr(CPUX86State *env, uint64_t paddr, uint8_t value);
uint8_t mem_rd_virt(CPUX86State *env, uint64_t vaddr);
void mem_wr_virt(CPUX86State *env, uint64_t vaddr, uint8_t val);
uint64_t get_reg(CPUX86State *env, int r);
void set_reg(int r, uint64_t val);

void helper_reg_read_callback(CPUX86State *env, uint32_t reg, uint32_t size)
{
    // pid based callbacks
    if (!qsim_sys_callbacks && curr_tpid[get_cpuid(env)] != qsim_tpid)
        return;

	if (qsim_gen_callbacks && qsim_reg_cb)
		qsim_reg_cb(get_cpuid(env), reg, size, 0);
	return;
}

void helper_reg_write_callback(CPUX86State *env, uint32_t reg, uint32_t size)
{
    // pid based callbacks
    if (!qsim_sys_callbacks && curr_tpid[get_cpuid(env)] != qsim_tpid)
        return;

    if (qsim_gen_callbacks && qsim_reg_cb)
        qsim_reg_cb(get_cpuid(env), reg, size, 1);
    return;
}

uint64_t get_reg(CPUX86State *env, int r) {
    return 0;
    CPUX86State *cpu = (CPUX86State *)first_cpu;
    switch (r) {
        case QSIM_RAX:    return cpu->regs[R_EAX];
        case QSIM_RCX:    return cpu->regs[R_ECX];
        case QSIM_RDX:    return cpu->regs[R_EDX];
        case QSIM_RBX:    return cpu->regs[R_EBX];
        case QSIM_RSP:    return cpu->regs[R_ESP];
        case QSIM_RBP:    return cpu->regs[R_EBP];
        case QSIM_RSI:    return cpu->regs[R_ESI];
        case QSIM_RDI:    return cpu->regs[R_EDI];
        case QSIM_FP0:    return cpu->fpregs[0].mmx.q;
        case QSIM_FP1:    return cpu->fpregs[1].mmx.q;
        case QSIM_FP2:    return cpu->fpregs[2].mmx.q;
        case QSIM_FP3:    return cpu->fpregs[3].mmx.q;
        case QSIM_FP4:    return cpu->fpregs[4].mmx.q;
        case QSIM_FP5:    return cpu->fpregs[5].mmx.q;
        case QSIM_FP6:    return cpu->fpregs[6].mmx.q;
        case QSIM_FP7:    return cpu->fpregs[7].mmx.q;
        case QSIM_FPSP:   return cpu->fpstt;
        case QSIM_ES :    return cpu->segs[R_ES ].selector;
        case QSIM_ESB:    return cpu->segs[R_ES ].base;
        case QSIM_ESL:    return cpu->segs[R_ES ].limit;
        case QSIM_ESF:    return cpu->segs[R_ES ].flags;
        case QSIM_CS :    return cpu->segs[R_CS ].selector;
        case QSIM_CSB:    return cpu->segs[R_CS ].base;
        case QSIM_CSL:    return cpu->segs[R_CS ].limit;
        case QSIM_CSF:    return cpu->segs[R_CS ].flags;
        case QSIM_SS :    return cpu->segs[R_SS ].selector;
        case QSIM_SSB:    return cpu->segs[R_SS ].base;
        case QSIM_SSL:    return cpu->segs[R_SS ].limit;
        case QSIM_SSF:    return cpu->segs[R_SS ].flags;
        case QSIM_DS :    return cpu->segs[R_DS ].selector;
        case QSIM_DSB:    return cpu->segs[R_DS ].base;
        case QSIM_DSL:    return cpu->segs[R_DS ].limit;
        case QSIM_DSF:    return cpu->segs[R_DS ].flags;
        case QSIM_FS :    return cpu->segs[R_FS ].selector;
        case QSIM_FSB:    return cpu->segs[R_FS ].base;
        case QSIM_FSL:    return cpu->segs[R_FS ].limit;
        case QSIM_FSF:    return cpu->segs[R_FS ].flags;
        case QSIM_GS :    return cpu->segs[R_GS ].selector;
        case QSIM_GSB:    return cpu->segs[R_GS ].base;
        case QSIM_GSL:    return cpu->segs[R_GS ].limit;
        case QSIM_GSF:    return cpu->segs[R_GS ].flags;
        case QSIM_RIP:    return qsim_eip;
        case QSIM_CR0:    return cpu->cr  [0    ];
        case QSIM_CR2:    return cpu->cr  [2    ];
        case QSIM_CR3:    return cpu->cr  [3    ];
        case QSIM_CR4:    return cpu->cr  [4    ];
        case QSIM_RFLAGS: return cpu_compute_eflags(cpu);
        case QSIM_GDTB:   return cpu->gdt.base;
        case QSIM_IDTB:   return cpu->idt.base;
        case QSIM_GDTL:   return cpu->gdt.limit;
        case QSIM_IDTL:   return cpu->idt.limit;
        case QSIM_TR:     return cpu->tr.selector;
        case QSIM_TRB:    return cpu->tr.base;
        case QSIM_TRL:    return cpu->tr.limit;
        case QSIM_TRF:    return cpu->tr.flags;
        case QSIM_LDT:    return cpu->ldt.selector;
        case QSIM_LDTB:   return cpu->ldt.base;
        case QSIM_LDTL:   return cpu->ldt.limit;
        case QSIM_LDTF:   return cpu->ldt.flags;
        case QSIM_DR6:    return cpu->dr[6];
        case QSIM_DR7:    return cpu->dr[7];
        case QSIM_HFLAGS: return cpu->hflags;
        case QSIM_HFLAGS2:return cpu->hflags2;
        case QSIM_SE_CS:  return cpu->sysenter_cs;
        case QSIM_SE_SP:  return cpu->sysenter_esp;
        case QSIM_SE_IP:  return cpu->sysenter_eip;
        default       :   return 0xbadbadbadbadbadbULL;
    }
} 

static inline void qsim_update_seg(int seg) {
    CPUX86State *cpu = (CPUX86State *)first_cpu;
    cpu_x86_load_seg_cache(cpu, seg, 
            cpu->segs[seg].selector,
            cpu->segs[seg].base,
            cpu->segs[seg].limit,
            cpu->segs[seg].flags);
}

void set_reg(int r, uint64_t val) {

    return;
    CPUX86State *cpu = (CPUX86State *)first_cpu;

    switch (r) {
        case QSIM_RAX:    cpu->regs[R_EAX]          = val;      break;
        case QSIM_RCX:    cpu->regs[R_ECX]          = val;      break;
        case QSIM_RDX:    cpu->regs[R_EDX]          = val;      break;
        case QSIM_RBX:    cpu->regs[R_EBX]          = val;      break;
        case QSIM_RSP:    cpu->regs[R_ESP]          = val;      break;
        case QSIM_RBP:    cpu->regs[R_EBP]          = val;      break;
        case QSIM_RSI:    cpu->regs[R_ESI]          = val;      break;
        case QSIM_RDI:    cpu->regs[R_EDI]          = val;      break;
        case QSIM_FP0:    cpu->fpregs[0].mmx.q      = val;      break;
        case QSIM_FP1:    cpu->fpregs[1].mmx.q      = val;      break;
        case QSIM_FP2:    cpu->fpregs[2].mmx.q      = val;      break;
        case QSIM_FP3:    cpu->fpregs[3].mmx.q      = val;      break;
        case QSIM_FP4:    cpu->fpregs[4].mmx.q      = val;      break;
        case QSIM_FP5:    cpu->fpregs[5].mmx.q      = val;      break;
        case QSIM_FP6:    cpu->fpregs[6].mmx.q      = val;      break;
        case QSIM_FP7:    cpu->fpregs[7].mmx.q      = val;      break;
        case QSIM_FPSP:   cpu->fpstt                = val;      break;
        case QSIM_ES :    cpu->segs[R_ES ].selector = val;      break;
        case QSIM_ESB:    cpu->segs[R_ES ].base     = val;      break;
        case QSIM_ESL:    cpu->segs[R_ES ].limit    = val;      break;
        case QSIM_ESF:    cpu->segs[R_ES ].flags    = val;
                          qsim_update_seg(R_ES);                      break;
        case QSIM_CS :    cpu->segs[R_CS ].selector = val;
                          cpu->segs[R_CS ].base     = val << 4; break;
        case QSIM_CSB:    cpu->segs[R_CS ].base     = val;      break;
        case QSIM_CSL:    cpu->segs[R_CS ].limit    = val;      break;
        case QSIM_CSF:    cpu->segs[R_CS ].flags    = val;
                          qsim_update_seg(R_CS);                      break;
        case QSIM_SS :    cpu->segs[R_SS ].selector = val;
                          cpu->segs[R_SS ].base     = val << 4; break;
        case QSIM_SSB:    cpu->segs[R_SS ].base     = val;      break;
        case QSIM_SSL:    cpu->segs[R_SS ].limit    = val;      break;
        case QSIM_SSF:    cpu->segs[R_SS ].flags    = val;
                          qsim_update_seg(R_SS);                      break;
        case QSIM_DS :    cpu->segs[R_DS ].selector = val;
                          cpu->segs[R_DS ].base     = val << 4; break;
        case QSIM_DSB:    cpu->segs[R_DS ].base     = val;      break;
        case QSIM_DSL:    cpu->segs[R_DS ].limit    = val;      break;
        case QSIM_DSF:    cpu->segs[R_DS ].flags    = val;
                          qsim_update_seg(R_DS);                      break;
        case QSIM_FS :    cpu->segs[R_FS ].selector = val;
                          cpu->segs[R_FS ].base     = val << 4; break;
        case QSIM_FSB:    cpu->segs[R_FS ].base     = val;      break;
        case QSIM_FSL:    cpu->segs[R_FS ].limit    = val;      break;
        case QSIM_FSF:    cpu->segs[R_FS ].flags    = val;
                          qsim_update_seg(R_FS);                      break;
        case QSIM_GS :    cpu->segs[R_GS ].selector = val;
                          cpu->segs[R_GS ].base     = val << 4; break;
        case QSIM_GSB:    cpu->segs[R_GS ].base     = val;      break;
        case QSIM_GSL:    cpu->segs[R_GS ].limit    = val;      break;
        case QSIM_GSF:    cpu->segs[R_GS ].flags    = val;
                          qsim_update_seg(R_GS);                      break;
        case QSIM_RIP:    cpu->eip                  = val;      break;
        case QSIM_CR0:    helper_write_crN(cpu, 0, val);                   break;
        case QSIM_CR2:
                          helper_write_crN(cpu, 2, val);                   break;
        case QSIM_CR3:
                          helper_write_crN(cpu, 3, val);                   break;
        case QSIM_CR4:
                          helper_write_crN(cpu, 4, val);                   break;
        case QSIM_GDTB:   cpu->gdt.base             = val;      break;
        case QSIM_GDTL:   cpu->gdt.limit            = val;      break;
        case QSIM_IDTB:   cpu->idt.base             = val;      break;
        case QSIM_IDTL:   cpu->idt.limit            = val;      break;
        case QSIM_RFLAGS: cpu_load_eflags(cpu, val, ~(CC_O | CC_S | CC_Z | CC_A |
                                                      CC_P | CC_C | DF_MASK));
                          break;
        case QSIM_TR:     cpu->tr.selector          = val;      break;
        case QSIM_TRB:    cpu->tr.base              = val;      break;
        case QSIM_TRL:    cpu->tr.limit             = val;      break;
        case QSIM_TRF:    cpu->tr.flags             = val;      break;
        case QSIM_LDT:    cpu->ldt.selector         = val;      break;
        case QSIM_LDTB:   cpu->ldt.base             = val;      break;
        case QSIM_LDTL:   cpu->ldt.limit            = val;      break;
        case QSIM_LDTF:   cpu->ldt.flags            = val;      break;
        case QSIM_DR6:    cpu->dr[6]                = val;      break;
        case QSIM_DR7:    cpu->dr[7]                = val;      break;
        case QSIM_HFLAGS: cpu->hflags               = val;      break;
        case QSIM_HFLAGS2:cpu->hflags2              = val;      break;
        case QSIM_SE_CS:  cpu->sysenter_cs          = val;      break;
        case QSIM_SE_SP:  cpu->sysenter_esp         = val;      break;
        case QSIM_SE_IP:  cpu->sysenter_eip         = val;      break;
        default:          break;
    }
}

static uint8_t *get_host_vaddr(CPUX86State *env, uint64_t vaddr, uint32_t length)
{
    hwaddr phys_addr, addr1, l = length;
    target_ulong page;
    MemoryRegion *mr;
    uint8_t *ptr = NULL;

    CPUState *cs = CPU(x86_env_get_cpu(env));

    page = vaddr & TARGET_PAGE_MASK;
    phys_addr = cpu_get_phys_page_debug(cs, page);

    /* ensure that the physical page is mapped
     */
    if (phys_addr == -1)
        goto done;

    phys_addr += (vaddr & ~TARGET_PAGE_MASK);
    mr = address_space_translate(cs->as, phys_addr, &addr1, &l, false);

    /* Skip device I/O
     */
    if (mr->ram_addr != -1)
        ptr = qemu_get_ram_ptr(mr->ram_addr + addr1);

done:
    return ptr;
}

void helper_inst_callback(CPUX86State *env, target_ulong vaddr,
        uint32_t length, uint32_t type)
{
    CPUState *cs = CPU(x86_env_get_cpu(env));
    qsim_id = cs->cpu_index;
    if (atomic_flag || nonatomic_locked) {
        printf("!!!! %p: Inst helper while holding lock. !!!!\n", (void*)qsim_eip);
    }

    if (atomic_flag && atomic_locked) {
        atomic_flag = 0;
        atomic_locked = 0;
    }

    if (nonatomic_locked) {
        nonatomic_locked = 0;
    }

    qsim_icount--;
    while (qsim_icount == 0) {
        swapcontext(&qemu_context, &main_context);
    }

    // pid based callbacks
    if (!qsim_sys_callbacks && curr_tpid[qsim_id] != qsim_tpid)
        return;

    // for now, only enable userspace instruction callbacks
    if (vaddr & 0xffffffff00000000)
        return;

    qsim_eip = vaddr;

    if (qsim_inst_cb != NULL) {
        uint8_t *buf;

        buf = get_host_vaddr(env, vaddr, length);
        qsim_inst_cb(qsim_id, vaddr, (uint64_t)buf, length, buf, type);
    }

    return;
}

static void memop_callback(CPUX86State *env, target_ulong vaddr,
        target_ulong size, int type)
{
    // pid based callbacks
    if (!qsim_sys_callbacks && curr_tpid[get_cpuidx(env)] != qsim_tpid)
        return;

	if (!qsim_mem_cb)
		return;

	// Handle unaligned page-crossing accessess as a series of aligned accesses.
	if ((size-1)&vaddr && (vaddr&0xfff)+size >= 0x1000) {
		memop_callback(env, vaddr,          size/2, type);
		memop_callback(env, vaddr + size/2, size/2, type);
	} else {
		CPUState *cs = CPU(x86_env_get_cpu(env));
		uint8_t *buf;

		qsim_id = cs->cpu_index;
		buf = get_host_vaddr(env, vaddr, size);
		qsim_mem_cb(qsim_id, vaddr, (uint64_t)buf, size, type);
	}
}

void helper_store_callback_pre(CPUX86State *env, uint64_t vaddr,
        uint32_t size, target_ulong data)
{
    memop_callback(env, vaddr, size, 1);
    return;
}

void helper_load_callback_pre(CPUX86State *env, target_ulong vaddr, uint32_t size, uint32_t type) 
{
    memop_callback(env, vaddr, size, type);

    return;
}

void helper_store_callback_post(CPUX86State *env,  uint64_t vaddr,
        uint32_t size, target_ulong data)
{
    memop_callback(env, vaddr, size, 1);

    return;
}

void helper_load_callback_post(CPUX86State *env, uint64_t vaddr, uint32_t size, uint32_t type)
{
    return;
}


uint8_t mem_rd(CPUX86State *env, uint64_t paddr) {
    CPUState *cs = CPU(x86_env_get_cpu(env));
    int bak = qsim_memop_flag;
    qsim_memop_flag = 1;
    uint8_t b = ldub_phys(cs->as, paddr); // ldub_kernel(vaddr)*/0;
    qsim_memop_flag = bak;
    return b;
}

void mem_wr(CPUX86State *env, uint64_t paddr, uint8_t value) {
    CPUState *cs = CPU(x86_env_get_cpu(env));
    int bak = qsim_memop_flag;
    qsim_memop_flag = 1;
    stb_phys(cs->as, paddr, value);
    qsim_memop_flag = bak;
}

uint8_t mem_rd_virt(CPUX86State *env, uint64_t vaddr) {
    // This is known to fail on guest operating systems that support the NX bit.
    int bak = qsim_memop_flag;
    qsim_memop_flag = 1;
    char b = cpu_ldub_code(env, vaddr);
    qsim_memop_flag = bak;
    return b;
}

void mem_wr_virt(CPUX86State *env, uint64_t vaddr, uint8_t value) {
    // This is known to fail on guest operating systems that support the NX bit.
    int bak = qsim_memop_flag;
    qsim_memop_flag = 1;
    cpu_ldub_code(env, vaddr); // discard result but get the host address
    (*(uint8_t *)qsim_host_addr) = value;
    qsim_memop_flag = bak;
}
