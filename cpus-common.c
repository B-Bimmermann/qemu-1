/*
 * CPU thread main loop - common bits for user and system mode emulation
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
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
#include "sysemu/cpus.h"
#include "exec/memory-internal.h"

static QemuMutex qemu_cpu_list_mutex;

void qemu_init_cpu_list(void)
{
    qemu_mutex_init(&qemu_cpu_list_mutex);
}

void cpu_list_lock(void)
{
    qemu_mutex_lock(&qemu_cpu_list_mutex);
}

void cpu_list_unlock(void)
{
    qemu_mutex_unlock(&qemu_cpu_list_mutex);
}

static int cpu_get_free_index(void)
{
    CPUState *some_cpu;
    int cpu_index = 0;

    CPU_FOREACH(some_cpu) {
        cpu_index++;
    }
    return cpu_index;
}

void cpu_list_add(CPUState *cpu)
{
    qemu_mutex_lock(&qemu_cpu_list_mutex);
    if (cpu->cpu_index == UNASSIGNED_CPU_INDEX) {
        cpu->cpu_index = cpu_get_free_index();
        assert(cpu->cpu_index != UNASSIGNED_CPU_INDEX);
    }

    QTAILQ_INSERT_TAIL(&cpus, cpu, node);
    qemu_mutex_unlock(&qemu_cpu_list_mutex);
}

void cpu_list_remove(CPUState *cpu)
{
    /* ??? How is this serialized against CPU_FOREACH? */
    qemu_mutex_lock(&qemu_cpu_list_mutex);
    if (QTAILQ_IN_USE(cpu, node)) {
        QTAILQ_REMOVE(&cpus, cpu, node);
    }
    cpu->cpu_index = UNASSIGNED_CPU_INDEX;
    qemu_mutex_unlock(&qemu_cpu_list_mutex);
}
