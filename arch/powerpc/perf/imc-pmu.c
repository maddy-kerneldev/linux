/*
 * Nest Performance Monitor counter support.
 *
 * Copyright (C) 2016 Madhavan Srinivasan, IBM Corporation.
 *	     (C) 2016 Hemant K Shaw, IBM Corporation.
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */
#include <linux/perf_event.h>
#include <linux/slab.h>
#include <asm/opal.h>
#include <asm/imc-pmu.h>
#include <asm/cputhreads.h>
#include <linux/string.h>

struct perchip_nest_info nest_perchip_info[IMC_MAX_CHIPS];
struct imc_pmu *per_nest_pmu_arr[IMC_MAX_PMUS];
static cpumask_t nest_imc_cpumask;

struct imc_pmu *core_imc_pmu;

/* Needed for sanity check */
extern u64 nest_max_offset;
extern u64 core_max_offset;

PMU_FORMAT_ATTR(event, "config:0-20");
static struct attribute *imc_format_attrs[] = {
	&format_attr_event.attr,
	NULL,
};

static struct attribute_group imc_format_group = {
	.name = "format",
	.attrs = imc_format_attrs,
};

/* Get the cpumask printed to a buffer "buf" */
static ssize_t imc_pmu_cpumask_get_attr(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	cpumask_t *active_mask;

	active_mask = &nest_imc_cpumask;
	return cpumap_print_to_pagebuf(true, buf, active_mask);
}

static DEVICE_ATTR(cpumask, S_IRUGO, imc_pmu_cpumask_get_attr, NULL);

static struct attribute *imc_pmu_cpumask_attrs[] = {
	&dev_attr_cpumask.attr,
	NULL,
};

static struct attribute_group imc_pmu_cpumask_attr_group = {
	.attrs = imc_pmu_cpumask_attrs,
};

/*
 * nest_init : Initializes the nest imc engine for the current chip.
 */
static void nest_init(int *loc)
{
	int rc;

	rc = opal_nest_imc_counters_control(NEST_IMC_PRODUCTION_MODE,
					    NEST_IMC_ENGINE_START, 0, 0);
	if (rc)
		loc[smp_processor_id()] = 1;
}

static void nest_change_cpu_context(int old_cpu, int new_cpu)
{
	int i;

	for (i = 0;
	     (per_nest_pmu_arr[i] != NULL) && (i < IMC_MAX_PMUS); i++)
		perf_pmu_migrate_context(&per_nest_pmu_arr[i]->pmu,
							old_cpu, new_cpu);
}

static int ppc_nest_imc_cpu_online(unsigned int cpu)
{
	int nid, fcpu, ncpu;
	struct cpumask *l_cpumask, tmp_mask;

	/* Fint the cpumask of this node */
	nid = cpu_to_node(cpu);
	l_cpumask = cpumask_of_node(nid);

	/*
	 * If any of the cpu from this node is already present in the mask,
	 * just return, if not, then set this cpu in the mask.
	 */
	if (!cpumask_and(&tmp_mask, l_cpumask, &nest_imc_cpumask)) {
		cpumask_set_cpu(cpu, &nest_imc_cpumask);
		return 0;
	}

	fcpu = cpumask_first(l_cpumask);
	ncpu = cpumask_next(cpu, l_cpumask);
	if (cpu == fcpu) {
		if (cpumask_test_and_clear_cpu(ncpu, &nest_imc_cpumask)) {
			cpumask_set_cpu(cpu, &nest_imc_cpumask);
			nest_change_cpu_context(ncpu, cpu);
		}
	}

	return 0;
}

static int ppc_nest_imc_cpu_offline(unsigned int cpu)
{
	int nid, target = -1;
	struct cpumask *l_cpumask;

	/*
	 * Check in the designated list for this cpu. Dont bother
	 * if not one of them.
	 */
	if (!cpumask_test_and_clear_cpu(cpu, &nest_imc_cpumask))
		return 0;

	/*
	 * Now that this cpu is one of the designated,
	 * find a next cpu a) which is online and b) in same chip.
	 */
	nid = cpu_to_node(cpu);
	l_cpumask = cpumask_of_node(nid);
	target = cpumask_next(cpu, l_cpumask);

	/*
	 * Update the cpumask with the target cpu and
	 * migrate the context if needed
	 */
	if (target >= 0 && target <= nr_cpu_ids) {
		cpumask_set_cpu(target, &nest_imc_cpumask);
		nest_change_cpu_context(cpu, target);
	}
	return 0;
}

static int nest_pmu_cpumask_init(void)
{
	const struct cpumask *l_cpumask;
	int cpu, nid;
	int *cpus_opal_rc;

	if (!cpumask_empty(&nest_imc_cpumask))
		return 0;

	/*
	 * Nest PMUs are per-chip counters. So designate a cpu
	 * from each chip for counter collection.
	 */
	for_each_online_node(nid) {
		l_cpumask = cpumask_of_node(nid);

		/* designate first online cpu in this node */
		cpu = cpumask_first(l_cpumask);
		cpumask_set_cpu(cpu, &nest_imc_cpumask);
	}

	/*
	 * Memory for OPAL call return value.
	 */
	cpus_opal_rc = kzalloc((sizeof(int) * nr_cpu_ids), GFP_KERNEL);
	if (!cpus_opal_rc)
		goto fail;

	/* Initialize Nest PMUs in each node using designated cpus */
	on_each_cpu_mask(&nest_imc_cpumask, (smp_call_func_t)nest_init,
						(void *)cpus_opal_rc, 1);

	/* Check return value array for any OPAL call failure */
	for_each_cpu(cpu, &nest_imc_cpumask) {
		if (cpus_opal_rc[cpu])
			goto fail;
	}

	cpuhp_setup_state(CPUHP_AP_PERF_POWERPC_NEST_ONLINE,
			  "POWER_NEST_IMC_ONLINE",
			  ppc_nest_imc_cpu_online,
			  ppc_nest_imc_cpu_offline);

	return 0;

fail:
	return -ENODEV;
}

static int nest_imc_event_init(struct perf_event *event)
{
	int chip_id;
	u32 config = event->attr.config;
	struct perchip_nest_info *pcni;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	/* Sampling not supported */
	if (event->hw.sample_period)
		return -EINVAL;

	/* unsupported modes and filters */
	if (event->attr.exclude_user   ||
	    event->attr.exclude_kernel ||
	    event->attr.exclude_hv     ||
	    event->attr.exclude_idle   ||
	    event->attr.exclude_host   ||
	    event->attr.exclude_guest)
		return -EINVAL;

	if (event->cpu < 0)
		return -EINVAL;

	/* Sanity check for config (event offset) */
	if (config > nest_max_offset)
		return -EINVAL;

	chip_id = topology_physical_package_id(event->cpu);
	pcni = &nest_perchip_info[chip_id];
	event->hw.event_base = pcni->vbase[config/PAGE_SIZE] +
		(config & ~PAGE_MASK);

	return 0;
}

static void imc_read_counter(struct perf_event *event)
{
	u64 *addr, data;

	addr = (u64 *)event->hw.event_base;
	data = __be64_to_cpu(*addr);
	local64_set(&event->hw.prev_count, data);
}

static void imc_perf_event_update(struct perf_event *event)
{
	u64 counter_prev, counter_new, final_count, *addr;

	addr = (u64 *)event->hw.event_base;
	counter_prev = local64_read(&event->hw.prev_count);
	counter_new = __be64_to_cpu(*addr);
	final_count = counter_new - counter_prev;

	local64_set(&event->hw.prev_count, counter_new);
	local64_add(final_count, &event->count);
}

static void imc_event_start(struct perf_event *event, int flags)
{
	imc_read_counter(event);
}

static void imc_event_stop(struct perf_event *event, int flags)
{
	imc_perf_event_update(event);
}

static int imc_event_add(struct perf_event *event, int flags)
{
	if (flags & PERF_EF_START)
		imc_event_start(event, flags);

	return 0;
}

/* update_pmu_ops : Populate the appropriate operations for "pmu" */
static int update_pmu_ops(struct imc_pmu *pmu)
{
	if (!pmu)
		return -EINVAL;

	pmu->pmu.task_ctx_nr = perf_invalid_context;
	pmu->pmu.event_init = nest_imc_event_init;
	pmu->pmu.add = imc_event_add;
	pmu->pmu.del = imc_event_stop;
	pmu->pmu.start = imc_event_start;
	pmu->pmu.stop = imc_event_stop;
	pmu->pmu.read = imc_perf_event_update;
	pmu->attr_groups[1] = &imc_format_group;
	pmu->attr_groups[2] = &imc_pmu_cpumask_attr_group;
	pmu->pmu.attr_groups = pmu->attr_groups;

	return 0;
}

/* dev_str_attr : Populate event "name" and string "str" in attribute */
static struct attribute *dev_str_attr(const char *name, const char *str)
{
	struct perf_pmu_events_attr *attr;

	attr = kzalloc(sizeof(*attr), GFP_KERNEL);

	sysfs_attr_init(&attr->attr.attr);

	attr->event_str = str;
	attr->attr.attr.name = name;
	attr->attr.attr.mode = 0444;
	attr->attr.show = perf_event_sysfs_show;

	return &attr->attr.attr;
}

/*
 * update_events_in_group: Update the "events" information in an attr_group
 *                         and assign the attr_group to the pmu "pmu".
 */
static int update_events_in_group(struct imc_events *events,
				  int idx, struct imc_pmu *pmu)
{
	struct attribute_group *attr_group;
	struct attribute **attrs;
	int i;

	/* Allocate memory for attribute group */
	attr_group = kzalloc(sizeof(*attr_group), GFP_KERNEL);
	if (!attr_group)
		return -ENOMEM;

	/* Allocate memory for attributes */
	attrs = kzalloc((sizeof(struct attribute *) * (idx + 1)), GFP_KERNEL);
	if (!attrs) {
		kfree(attr_group);
		return -ENOMEM;
	}

	attr_group->name = "events";
	attr_group->attrs = attrs;
	for (i = 0; i < idx; i++, events++) {
		attrs[i] = dev_str_attr((char *)events->ev_name,
					(char *)events->ev_value);
	}

	pmu->attr_groups[0] = attr_group;
	return 0;
}

/*
 * init_imc_pmu : Setup the IMC pmu device in "pmu_ptr" and its events
 *                "events".
 * Setup the cpu mask information for these pmus and setup the state machine
 * hotplug notifiers as well.
 */
int init_imc_pmu(struct imc_events *events, int idx,
		 struct imc_pmu *pmu_ptr)
{
	int ret = -ENODEV;

	/* Add cpumask and register for hotplug notification */
	ret = nest_pmu_cpumask_init();
	if (ret)
		return ret;

	ret = update_events_in_group(events, idx, pmu_ptr);
	if (ret)
		goto err_free;

	ret = update_pmu_ops(pmu_ptr);
	if (ret)
		goto err_free;

	ret = perf_pmu_register(&pmu_ptr->pmu, pmu_ptr->pmu.name, -1);
	if (ret)
		goto err_free;

	pr_info("%s performance monitor hardware support registered\n",
		pmu_ptr->pmu.name);

	return 0;

err_free:
	/* Only free the attr_groups which are dynamically allocated  */
	if (pmu_ptr->attr_groups[0]) {
		kfree(pmu_ptr->attr_groups[0]->attrs);
		kfree(pmu_ptr->attr_groups[0]);
	}

	return ret;
}
