/*
 *  Software MMU support (esclusive load/store operations)
 *
 * Generate helpers used by TCG for qemu_ldlink/stcond ops.
 *
 * Included from softmmu_template.h only.
 *
 * Copyright (c) 2015 Virtual Open Systems
 *
 * Authors:
 *  Alvise Rigo <a.rigo@virtualopensystems.com>
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

/* This template does not generate together the le and be version, but only one
 * of the two depending on whether BIGENDIAN_EXCLUSIVE_HELPERS has been set.
 * The same nomenclature as softmmu_template.h is used for the exclusive
 * helpers.  */

#ifdef BIGENDIAN_EXCLUSIVE_HELPERS

#define helper_ldlink_name  glue(glue(helper_be_ldlink, USUFFIX), MMUSUFFIX)
#define helper_stcond_name  glue(glue(helper_be_stcond, SUFFIX), MMUSUFFIX)
#define helper_ld glue(glue(helper_be_ld, USUFFIX), MMUSUFFIX)
#define helper_st glue(glue(helper_be_st, SUFFIX), MMUSUFFIX)

#else /* LE helpers + 8bit helpers (generated only once for both LE end BE) */

#if DATA_SIZE > 1
#define helper_ldlink_name  glue(glue(helper_le_ldlink, USUFFIX), MMUSUFFIX)
#define helper_stcond_name  glue(glue(helper_le_stcond, SUFFIX), MMUSUFFIX)
#define helper_ld glue(glue(helper_le_ld, USUFFIX), MMUSUFFIX)
#define helper_st glue(glue(helper_le_st, SUFFIX), MMUSUFFIX)
#else /* DATA_SIZE <= 1 */
#define helper_ldlink_name  glue(glue(helper_ret_ldlink, USUFFIX), MMUSUFFIX)
#define helper_stcond_name  glue(glue(helper_ret_stcond, SUFFIX), MMUSUFFIX)
#define helper_ld glue(glue(helper_ret_ld, USUFFIX), MMUSUFFIX)
#define helper_st glue(glue(helper_ret_st, SUFFIX), MMUSUFFIX)
#endif

#endif

#define is_read_tlb_entry_set(env, page, index)                              \
({                                                                           \
    (addr & TARGET_PAGE_MASK)                                                \
         == ((env->tlb_table[mmu_idx][index].addr_read) &                    \
                 (TARGET_PAGE_MASK | TLB_INVALID_MASK));                     \
})
/* Whenever a SC operation fails, we add a small delay to reduce the
 * concurrency among the atomic instruction emulation code. Without this delay,
 * in very congested situation where plain stores make all the pending LLs
 * fail, the code could reach a stalling situation in which all the SCs happen
 * to fail.
 * */
#define TCG_ATOMIC_INSN_EMUL_DELAY 100

WORD_TYPE helper_ldlink_name(CPUArchState *env, target_ulong addr,
                                TCGMemOpIdx oi, uintptr_t retaddr)
{
    WORD_TYPE ret;
    int index;
    CPUState *cpu;
    hwaddr hw_addr;
    unsigned mmu_idx = get_mmuidx(oi);

    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);

    if (!is_read_tlb_entry_set(env, addr, index) ||
                        !VICTIM_TLB_HIT(addr_read)) {
        tlb_fill(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
    }

    /* hw_addr = hwaddr of the page (i.e. section->mr->ram_addr + xlat)
     * plus the offset (i.e. addr & ~TARGET_PAGE_MASK) */
    hw_addr = (env->iotlb[mmu_idx][index].addr & TARGET_PAGE_MASK) + addr;

    qemu_mutex_lock(&tcg_excl_access_lock);
    /* If all the vCPUs have the EXCL bit set for this page there is no need
     * to request any flush. */
    if (unlikely(!atomic_xchg(&exit_flush_request, 1) &&
        cpu_physical_memory_excl_is_dirty(hw_addr, smp_cpus))) {
        CPU_FOREACH(cpu) {
            if (cpu->thread_id != qemu_get_thread_id()) {
                if (cpu_physical_memory_excl_is_dirty(hw_addr,
                                                      cpu->cpu_index)) {
                    tlb_query_flush_cpu(cpu, 1);
                }
            }
        }

        cpu_physical_memory_clear_excl_dirty(hw_addr, smp_cpus);
        atomic_set(&exit_flush_request, 0);
    }

    env->ll_sc_context = true;

    /* Use the proper load helper from cpu_ldst.h */
    ret = helper_ld(env, addr, mmu_idx, retaddr);

    env->excl_protected_range.begin = hw_addr;
    env->excl_protected_range.end = hw_addr + DATA_SIZE;

    qemu_mutex_unlock(&tcg_excl_access_lock);

    /* For this vCPU, just update the TLB entry, no need to flush. */
    env->tlb_table[mmu_idx][index].addr_write |= TLB_EXCL;

    return ret;
}

WORD_TYPE helper_stcond_name(CPUArchState *env, target_ulong addr,
                             DATA_TYPE val, TCGMemOpIdx oi,
                             uintptr_t retaddr)
{
    WORD_TYPE ret;
    unsigned mmu_idx = get_mmuidx(oi);

    /* We set it preventively to true to distinguish the following legacy
     * access as one made by the store conditional wrapper. If the store
     * conditional does not succeed, the value will be set to 0.*/
    env->excl_succeeded = 1;
    helper_st(env, addr, val, mmu_idx, retaddr);

    if (env->excl_succeeded) {
        env->excl_succeeded = 0;
        ret = 0;
    } else {
        g_usleep(TCG_ATOMIC_INSN_EMUL_DELAY);
        ret = 1;
    }

    return ret;
}

#undef helper_ldlink_name
#undef helper_stcond_name
#undef helper_ld
#undef helper_st
