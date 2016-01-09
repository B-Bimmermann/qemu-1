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

#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"

#include "qsim-vm.h"
#include "qsim-context.h"
/* broken thread support */

static spinlock_t global_cpu_lock = SPIN_LOCK_UNLOCKED;
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
extern uint64_t qsim_tpid, curr_tpid[32];

extern qsim_ucontext_t main_context, qemu_context;

extern int get_cpuidx(CPUX86State *env);
extern CPUX86State* get_env(int cpu_idx);

void helper_lock(void)
{
    spin_lock(&global_cpu_lock);
    atomic_flag = 1;
    atomic_locked = 0;
    // Suspend execution immediately if the atomic callback returns nonzero
    if (qsim_gen_callbacks && qsim_atomic_cb && qsim_atomic_cb(qsim_id))
        swapcontext(&qemu_context, &main_context);
}

void helper_unlock(void)
{
    spin_unlock(&global_cpu_lock);
    atomic_flag = 0;
}

void helper_cmpxchg8b(CPUX86State *env, target_ulong a0)
{
    uint64_t d;
    int eflags;

    eflags = cpu_cc_compute_all(env, CC_OP);
    d = cpu_ldq_data(env, a0);
    if (d == (((uint64_t)env->regs[R_EDX] << 32) | (uint32_t)env->regs[R_EAX])) {
        cpu_stq_data(env, a0, ((uint64_t)env->regs[R_ECX] << 32) | (uint32_t)env->regs[R_EBX]);
        eflags |= CC_Z;
    } else {
        /* always do the store */
        cpu_stq_data(env, a0, d);
        env->regs[R_EDX] = (uint32_t)(d >> 32);
        env->regs[R_EAX] = (uint32_t)d;
        eflags &= ~CC_Z;
    }
    CC_SRC = eflags;
}

#ifdef TARGET_X86_64
void helper_cmpxchg16b(CPUX86State *env, target_ulong a0)
{
    uint64_t d0, d1;
    int eflags;

    if ((a0 & 0xf) != 0) {
        raise_exception(env, EXCP0D_GPF);
    }
    eflags = cpu_cc_compute_all(env, CC_OP);
    d0 = cpu_ldq_data(env, a0);
    d1 = cpu_ldq_data(env, a0 + 8);
    if (d0 == env->regs[R_EAX] && d1 == env->regs[R_EDX]) {
        cpu_stq_data(env, a0, env->regs[R_EBX]);
        cpu_stq_data(env, a0 + 8, env->regs[R_ECX]);
        eflags |= CC_Z;
    } else {
        /* always do the store */
        cpu_stq_data(env, a0, d0);
        cpu_stq_data(env, a0 + 8, d1);
        env->regs[R_EDX] = d1;
        env->regs[R_EAX] = d0;
        eflags &= ~CC_Z;
    }
    CC_SRC = eflags;
}
#endif

void helper_boundw(CPUX86State *env, target_ulong a0, int v)
{
    int low, high;

    low = cpu_ldsw_data(env, a0);
    high = cpu_ldsw_data(env, a0 + 2);
    v = (int16_t)v;
    if (v < low || v > high) {
        raise_exception(env, EXCP05_BOUND);
    }
}

void helper_boundl(CPUX86State *env, target_ulong a0, int v)
{
    int low, high;

    low = cpu_ldl_data(env, a0);
    high = cpu_ldl_data(env, a0 + 4);
    if (v < low || v > high) {
        raise_exception(env, EXCP05_BOUND);
    }
}

#if !defined(CONFIG_USER_ONLY)
/* try to fill the TLB and return an exception if error. If retaddr is
 * NULL, it means that the function was called in C code (i.e. not
 * from generated code or from helper.c)
 */
/* XXX: fix it to restore all registers */
void tlb_fill(CPUState *cs, target_ulong addr, int is_write, int mmu_idx,
              uintptr_t retaddr)
{
    int ret;

    ret = x86_cpu_handle_mmu_fault(cs, addr, is_write, mmu_idx);
    if (ret) {
        X86CPU *cpu = X86_CPU(cs);
        CPUX86State *env = &cpu->env;

        if (retaddr) {
            /* now we have a real cpu fault */
            cpu_restore_state(cs, retaddr);
        }
        raise_exception_err(env, cs->exception_index, env->error_code);
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

uint8_t mem_rd(uint64_t paddr);
void mem_wr(uint64_t paddr, uint8_t value);
uint8_t mem_rd_virt(int cpu_idx, uint64_t vaddr);
void mem_wr_virt(int cpu_idx, uint64_t vaddr, uint8_t val);
uint64_t get_reg(int cpu_idx, int r);
void set_reg(int cpu_idx, int r, uint64_t val);

void helper_reg_read_callback(CPUX86State *env, uint32_t reg, uint32_t size)
{
    // pid based callbacks
    if (!qsim_sys_callbacks && curr_tpid[get_cpuidx(env)] != qsim_tpid)
        return;

    if (qsim_gen_callbacks && qsim_reg_cb)
      qsim_reg_cb(get_cpuidx(env), reg, size, 0);

    return;
}

void helper_reg_write_callback(CPUX86State *env, uint32_t reg, uint32_t size)
{
    // pid based callbacks
    if (!qsim_sys_callbacks && curr_tpid[get_cpuidx(env)] != qsim_tpid)
        return;

    if (qsim_gen_callbacks && qsim_reg_cb)
        qsim_reg_cb(get_cpuidx(env), reg, size, 1);

    return;
}

uint64_t get_reg(int cpu_idx, int r) {
    CPUX86State *cpu = get_env(cpu_idx);
    switch (r) {
        case X86_REG_RAX:    return cpu->regs[R_EAX];
        case X86_REG_RCX:    return cpu->regs[R_ECX];
        case X86_REG_RDX:    return cpu->regs[R_EDX];
        case X86_REG_RBX:    return cpu->regs[R_EBX];
        case X86_REG_RSP:    return cpu->regs[R_ESP];
        case X86_REG_RBP:    return cpu->regs[R_EBP];
        case X86_REG_RSI:    return cpu->regs[R_ESI];
        case X86_REG_RDI:    return cpu->regs[R_EDI];
        case X86_REG_R8 :    return cpu->regs[8];
        case X86_REG_R9 :    return cpu->regs[9];
        case X86_REG_R10:    return cpu->regs[10];
        case X86_REG_R11:    return cpu->regs[11];
        case X86_REG_R12:    return cpu->regs[12];
        case X86_REG_R13:    return cpu->regs[13];
        case X86_REG_R14:    return cpu->regs[14];
        case X86_REG_R15:    return cpu->regs[15];
        case X86_REG_FP0:    return cpu->fpregs[0].mmx.q;
        case X86_REG_FP1:    return cpu->fpregs[1].mmx.q;
        case X86_REG_FP2:    return cpu->fpregs[2].mmx.q;
        case X86_REG_FP3:    return cpu->fpregs[3].mmx.q;
        case X86_REG_FP4:    return cpu->fpregs[4].mmx.q;
        case X86_REG_FP5:    return cpu->fpregs[5].mmx.q;
        case X86_REG_FP6:    return cpu->fpregs[6].mmx.q;
        case X86_REG_FP7:    return cpu->fpregs[7].mmx.q;
	      /* TODO: Implement the following
        case X86_REG_FPSP:   return cpu->fpstt;
        case X86_REG_ES :    return cpu->segs[R_ES ].selector;
        case X86_REG_ESB:    return cpu->segs[R_ES ].base;
        case X86_REG_ESL:    return cpu->segs[R_ES ].limit;
        case X86_REG_ESF:    return cpu->segs[R_ES ].flags;
        case X86_REG_CS :    return cpu->segs[R_CS ].selector;
        case X86_REG_CSB:    return cpu->segs[R_CS ].base;
        case X86_REG_CSL:    return cpu->segs[R_CS ].limit;
        case X86_REG_CSF:    return cpu->segs[R_CS ].flags;
        case X86_REG_SS :    return cpu->segs[R_SS ].selector;
        case X86_REG_SSB:    return cpu->segs[R_SS ].base;
        case X86_REG_SSL:    return cpu->segs[R_SS ].limit;
        case X86_REG_SSF:    return cpu->segs[R_SS ].flags;
        case X86_REG_DS :    return cpu->segs[R_DS ].selector;
        case X86_REG_DSB:    return cpu->segs[R_DS ].base;
        case X86_REG_DSL:    return cpu->segs[R_DS ].limit;
        case X86_REG_DSF:    return cpu->segs[R_DS ].flags;
        case X86_REG_FS :    return cpu->segs[R_FS ].selector;
        case X86_REG_FSB:    return cpu->segs[R_FS ].base;
        case X86_REG_FSL:    return cpu->segs[R_FS ].limit;
        case X86_REG_FSF:    return cpu->segs[R_FS ].flags;
        case X86_REG_GS :    return cpu->segs[R_GS ].selector;
        case X86_REG_GSB:    return cpu->segs[R_GS ].base;
        case X86_REG_GSL:    return cpu->segs[R_GS ].limit;
        case X86_REG_GSF:    return cpu->segs[R_GS ].flags;
        case X86_REG_RIP:    return X86_REG_eip;
        case X86_REG_CR0:    return cpu->cr  [0    ];
        case X86_REG_CR2:    return cpu->cr  [2    ];
        case X86_REG_CR3:    return cpu->cr  [3    ];
        case X86_REG_CR4:    return cpu->cr  [4    ];
        case X86_REG_RFLAGS: return cpu_compute_eflags(cpu);
        case X86_REG_GDTB:   return cpu->gdt.base;
        case X86_REG_IDTB:   return cpu->idt.base;
        case X86_REG_GDTL:   return cpu->gdt.limit;
        case X86_REG_IDTL:   return cpu->idt.limit;
        case X86_REG_TR:     return cpu->tr.selector;
        case X86_REG_TRB:    return cpu->tr.base;
        case X86_REG_TRL:    return cpu->tr.limit;
        case X86_REG_TRF:    return cpu->tr.flags;
        case X86_REG_LDT:    return cpu->ldt.selector;
        case X86_REG_LDTB:   return cpu->ldt.base;
        case X86_REG_LDTL:   return cpu->ldt.limit;
        case X86_REG_LDTF:   return cpu->ldt.flags;
        case X86_REG_DR6:    return cpu->dr[6];
        case X86_REG_DR7:    return cpu->dr[7];
        case X86_REG_HFLAGS: return cpu->hflags;
        case X86_REG_HFLAGS2:return cpu->hflags2;
        case X86_REG_SE_CS:  return cpu->sysenter_cs;
        case X86_REG_SE_SP:  return cpu->sysenter_esp;
        case X86_REG_SE_IP:  return cpu->sysenter_eip;
        */
        default       :   return 0xbadbadbadbadbadbULL;
    }
} 

/*
static inline void qsim_update_seg(int seg) {
    CPUX86State *cpu = (CPUX86State *)first_cpu;
    cpu_x86_load_seg_cache(cpu, seg, 
            cpu->segs[seg].selector,
            cpu->segs[seg].base,
            cpu->segs[seg].limit,
            cpu->segs[seg].flags);
}
*/

void set_reg(int c, int r, uint64_t val) {

    CPUX86State *cpu = get_env(c);

    switch (r) {
        case X86_REG_RAX:    cpu->regs[R_EAX]          = val;      break;
        case X86_REG_RCX:    cpu->regs[R_ECX]          = val;      break;
        case X86_REG_RDX:    cpu->regs[R_EDX]          = val;      break;
        case X86_REG_RBX:    cpu->regs[R_EBX]          = val;      break;
        case X86_REG_RSP:    cpu->regs[R_ESP]          = val;      break;
        case X86_REG_RBP:    cpu->regs[R_EBP]          = val;      break;
        case X86_REG_RSI:    cpu->regs[R_ESI]          = val;      break;
        case X86_REG_RDI:    cpu->regs[R_EDI]          = val;      break;
        case X86_REG_R8 :    cpu->regs[8]              = val;      break;
        case X86_REG_R9 :    cpu->regs[9]              = val;      break;
        case X86_REG_R10:    cpu->regs[10]             = val;      break;
        case X86_REG_R11:    cpu->regs[11]             = val;      break;
        case X86_REG_R12:    cpu->regs[12]             = val;      break;
        case X86_REG_R13:    cpu->regs[13]             = val;      break;
        case X86_REG_R14:    cpu->regs[14]             = val;      break;
        case X86_REG_R15:    cpu->regs[15]             = val;      break;
        case X86_REG_FP0:    cpu->fpregs[0].mmx.q      = val;      break;
        case X86_REG_FP1:    cpu->fpregs[1].mmx.q      = val;      break;
        case X86_REG_FP2:    cpu->fpregs[2].mmx.q      = val;      break;
        case X86_REG_FP3:    cpu->fpregs[3].mmx.q      = val;      break;
        case X86_REG_FP4:    cpu->fpregs[4].mmx.q      = val;      break;
        case X86_REG_FP5:    cpu->fpregs[5].mmx.q      = val;      break;
        case X86_REG_FP6:    cpu->fpregs[6].mmx.q      = val;      break;
        case X86_REG_FP7:    cpu->fpregs[7].mmx.q      = val;      break;
        /*
        case X86_REG_FPSP:   cpu->fpstt                = val;      break;
        case X86_REG_ES :    cpu->segs[R_ES ].selector = val;      break;
        case X86_REG_ESB:    cpu->segs[R_ES ].base     = val;      break;
        case X86_REG_ESL:    cpu->segs[R_ES ].limit    = val;      break;
        case X86_REG_ESF:    cpu->segs[R_ES ].flags    = val;
                          X86_REG_update_seg(R_ES);                      break;
        case X86_REG_CS :    cpu->segs[R_CS ].selector = val;
                          cpu->segs[R_CS ].base     = val << 4; break;
        case X86_REG_CSB:    cpu->segs[R_CS ].base     = val;      break;
        case X86_REG_CSL:    cpu->segs[R_CS ].limit    = val;      break;
        case X86_REG_CSF:    cpu->segs[R_CS ].flags    = val;
                          X86_REG_update_seg(R_CS);                      break;
        case X86_REG_SS :    cpu->segs[R_SS ].selector = val;
                          cpu->segs[R_SS ].base     = val << 4; break;
        case X86_REG_SSB:    cpu->segs[R_SS ].base     = val;      break;
        case X86_REG_SSL:    cpu->segs[R_SS ].limit    = val;      break;
        case X86_REG_SSF:    cpu->segs[R_SS ].flags    = val;
                          X86_REG_update_seg(R_SS);                      break;
        case X86_REG_DS :    cpu->segs[R_DS ].selector = val;
                          cpu->segs[R_DS ].base     = val << 4; break;
        case X86_REG_DSB:    cpu->segs[R_DS ].base     = val;      break;
        case X86_REG_DSL:    cpu->segs[R_DS ].limit    = val;      break;
        case X86_REG_DSF:    cpu->segs[R_DS ].flags    = val;
                          X86_REG_update_seg(R_DS);                      break;
        case X86_REG_FS :    cpu->segs[R_FS ].selector = val;
                          cpu->segs[R_FS ].base     = val << 4; break;
        case X86_REG_FSB:    cpu->segs[R_FS ].base     = val;      break;
        case X86_REG_FSL:    cpu->segs[R_FS ].limit    = val;      break;
        case X86_REG_FSF:    cpu->segs[R_FS ].flags    = val;
                          X86_REG_update_seg(R_FS);                      break;
        case X86_REG_GS :    cpu->segs[R_GS ].selector = val;
                          cpu->segs[R_GS ].base     = val << 4; break;
        case X86_REG_GSB:    cpu->segs[R_GS ].base     = val;      break;
        case X86_REG_GSL:    cpu->segs[R_GS ].limit    = val;      break;
        case X86_REG_GSF:    cpu->segs[R_GS ].flags    = val;
                          X86_REG_update_seg(R_GS);                      break;
        case X86_REG_RIP:    cpu->eip                  = val;      break;
        case X86_REG_CR0:    helper_write_crN(cpu, 0, val);                   break;
        case X86_REG_CR2:
                          helper_write_crN(cpu, 2, val);                   break;
        case X86_REG_CR3:
                          helper_write_crN(cpu, 3, val);                   break;
        case X86_REG_CR4:
                          helper_write_crN(cpu, 4, val);                   break;
        case X86_REG_GDTB:   cpu->gdt.base             = val;      break;
        case X86_REG_GDTL:   cpu->gdt.limit            = val;      break;
        case X86_REG_IDTB:   cpu->idt.base             = val;      break;
        case X86_REG_IDTL:   cpu->idt.limit            = val;      break;
        case X86_REG_RFLAGS: cpu_load_eflags(cpu, val, ~(CC_O | CC_S | CC_Z | CC_A |
                                                      CC_P | CC_C | DF_MASK));
                          break;
        case X86_REG_TR:     cpu->tr.selector          = val;      break;
        case X86_REG_TRB:    cpu->tr.base              = val;      break;
        case X86_REG_TRL:    cpu->tr.limit             = val;      break;
        case X86_REG_TRF:    cpu->tr.flags             = val;      break;
        case X86_REG_LDT:    cpu->ldt.selector         = val;      break;
        case X86_REG_LDTB:   cpu->ldt.base             = val;      break;
        case X86_REG_LDTL:   cpu->ldt.limit            = val;      break;
        case X86_REG_LDTF:   cpu->ldt.flags            = val;      break;
        case X86_REG_DR6:    cpu->dr[6]                = val;      break;
        case X86_REG_DR7:    cpu->dr[7]                = val;      break;
        case X86_REG_HFLAGS: cpu->hflags               = val;      break;
        case X86_REG_HFLAGS2:cpu->hflags2              = val;      break;
        case X86_REG_SE_CS:  cpu->sysenter_cs          = val;      break;
        case X86_REG_SE_SP:  cpu->sysenter_esp         = val;      break;
        case X86_REG_SE_IP:  cpu->sysenter_eip         = val;      break;
        */
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
        printf("!!!! %llu: Inst helper while holding lock. !!!!\n", qsim_eip);
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

    // enable userspace instruction callbacks based on sys_callbacks flag
    if (!qsim_sys_callbacks && (vaddr & 0xffffffff00000000))
        return;

    qsim_eip = vaddr;

    if (qsim_inst_cb != NULL) {
        uint8_t *buf;

        buf = get_host_vaddr(env, vaddr, length);
        qsim_inst_cb(qsim_id, vaddr, (uintptr_t)buf, length, buf, type);
    }

    return;
}

static void memop_callback(CPUX86State *env, target_ulong vaddr,
        target_ulong size, int type)
{
    if (!qsim_mem_cb)
      return;

    // pid based callbacks
    if (!qsim_sys_callbacks && curr_tpid[get_cpuidx(env)] != qsim_tpid)
        return;

    int32_t vaddr_hi = ((uint64_t)vaddr >> 32) & 0xffffffff;
    if (!qsim_sys_callbacks && (vaddr_hi == 0xffffffff ||
                               vaddr_hi == 0xffff8800))
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
      qsim_mem_cb(qsim_id, vaddr, (uintptr_t)buf, size, type);
    }
}

void helper_store_callback_pre(CPUX86State *env, uint64_t vaddr,
        uint32_t size, target_ulong data)
{
    // disabled pre-store callbacks for now
    // memop_callback(env, vaddr, size, 1);
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
    // disabled post-load callbacks for now
    // memop_callback(env, vaddr, size, type);
    return;
}


uint8_t mem_rd(uint64_t paddr)
{
    CPUX86State *env = get_env(0);
    CPUState *cs = CPU(x86_env_get_cpu(env));
    uint8_t b = ldub_phys(cs->as, paddr); // ldub_kernel(vaddr)*/0;
    return b;
}

void mem_wr(uint64_t paddr, uint8_t value)
{
    CPUX86State *env = get_env(0);
    CPUState *cs = CPU(x86_env_get_cpu(env));
    stb_phys(cs->as, paddr, value);
}

uint8_t mem_rd_virt(int cpu_idx, uint64_t vaddr) {
    CPUX86State *env = get_env(cpu_idx);
    uint8_t *buf;
    buf = get_host_vaddr(env, vaddr, 1);
    return *buf;
}

void mem_wr_virt(int cpu_idx, uint64_t vaddr, uint8_t value) {
    uint8_t *buf;
    CPUX86State *env = get_env(cpu_idx);
    buf = get_host_vaddr(env, vaddr, 1);
    *buf = value;
}
