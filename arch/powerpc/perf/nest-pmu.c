/*
 * Nest Performance Monitor counter support for POWER8 processors.
 *
 * Copyright (C) 2015 Madhavan Srinivasan, IBM Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#include "nest-pmu.h"

static struct perchip_nest_info p8_nest_perchip_info[P8_NEST_MAX_CHIPS];
static struct nest_pmu *per_nest_pmu_arr[P8_NEST_MAX_PMUS];
static cpumask_t nest_pmu_cpu_mask;

PMU_FORMAT_ATTR(event, "config:0-20");
static struct attribute *p8_nest_format_attrs[] = {
	&format_attr_event.attr,
	NULL,
};

static struct attribute_group p8_nest_format_group = {
	.name = "format",
	.attrs = p8_nest_format_attrs,
};

static ssize_t nest_pmu_cpumask_get_attr(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return cpumap_print_to_pagebuf(true, buf, &nest_pmu_cpu_mask);
}

static DEVICE_ATTR(cpumask, S_IRUGO, nest_pmu_cpumask_get_attr, NULL);

static struct attribute *nest_pmu_cpumask_attrs[] = {
	&dev_attr_cpumask.attr,
	NULL,
};

static struct attribute_group nest_pmu_cpumask_attr_group = {
	.attrs = nest_pmu_cpumask_attrs,
};

static void nest_change_cpu_context(int old_cpu, int new_cpu)
{
	int i;

	for (i = 0;
		(per_nest_pmu_arr[i] != NULL) && (i < P8_NEST_MAX_PMUS); i++)
		perf_pmu_migrate_context(&per_nest_pmu_arr[i]->pmu,
						old_cpu, new_cpu);
}

static void nest_exit_cpu(int cpu)
{
	int nid, target = -1;
	struct cpumask *l_cpumask;

	/*
	 * Check in the designated list for this cpu. Dont bother
	 * if not one of them.
	 */
	if (!cpumask_test_and_clear_cpu(cpu, &nest_pmu_cpu_mask))
		return;

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
		cpumask_set_cpu(target, &nest_pmu_cpu_mask);
		nest_change_cpu_context(cpu, target);
	}
}

static void nest_init_cpu(int cpu)
{
	int nid, fcpu, ncpu;
	struct cpumask *l_cpumask, tmp_mask;

	nid = cpu_to_node(cpu);
	l_cpumask = cpumask_of_node(nid);

	if (!cpumask_and(&tmp_mask, l_cpumask, &nest_pmu_cpu_mask)) {
		cpumask_set_cpu(cpu, &nest_pmu_cpu_mask);
		return;
	}

	fcpu = cpumask_first(l_cpumask);
	ncpu = cpumask_next(cpu, l_cpumask);
	if (cpu == fcpu) {
		if (cpumask_test_and_clear_cpu(ncpu, &nest_pmu_cpu_mask)) {
			cpumask_set_cpu(cpu, &nest_pmu_cpu_mask);
			nest_change_cpu_context(ncpu, cpu);
		}
	}
}

static int nest_pmu_cpu_notifier(struct notifier_block *self,
				unsigned long action, void *hcpu)
{
	long cpu = (long)hcpu;

	switch (action & ~CPU_TASKS_FROZEN) {
	case CPU_ONLINE:
		nest_init_cpu(cpu);
		break;
	case CPU_DOWN_PREPARE:
	       nest_exit_cpu(cpu);
	       break;
	default:
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block nest_pmu_cpu_nb = {
	.notifier_call  = nest_pmu_cpu_notifier,
	.priority       = CPU_PRI_PERF + 1,
};

static int nest_pmu_cpumask_init(void)
{
	const struct cpumask *l_cpumask;
	int cpu, nid;

	cpu_notifier_register_begin();

	/*
	 * Nest PMUs are per-chip counters. So designate a cpu
	 * from each chip for counter collection.
	 */
	for_each_online_node(nid) {
		l_cpumask = cpumask_of_node(nid);

		/* designate first online cpu in this node */
		cpu = cpumask_first(l_cpumask);
		cpumask_set_cpu(cpu, &nest_pmu_cpu_mask);
	}

	__register_cpu_notifier(&nest_pmu_cpu_nb);

	cpu_notifier_register_done();
	return 0;
}

static int p8_nest_event_init(struct perf_event *event)
{
	int chip_id;
	u32 config = event->attr.config;
	struct perchip_nest_info *p8ni;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	/* Sampling not supported yet */
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

	chip_id = topology_physical_package_id(event->cpu);
	p8ni = &p8_nest_perchip_info[chip_id];
	event->hw.event_base = p8ni->vbase[config/PAGE_SIZE] +
						(config & ~PAGE_MASK );

	return 0;
}

static void p8_nest_read_counter(struct perf_event *event)
{
	u64 *addr, data;

	addr = (u64 *)event->hw.event_base;
	data = __be64_to_cpu(*addr);
	local64_set(&event->hw.prev_count, data);
}

static void p8_nest_perf_event_update(struct perf_event *event)
{
	u64 counter_new, *addr;

	addr = (u64 *)event->hw.event_base;
	counter_new = __be64_to_cpu(*addr);

	local64_set(&event->hw.prev_count, counter_new);
	local64_add(counter_new, &event->count);
}

static void p8_nest_event_start(struct perf_event *event, int flags)
{
	p8_nest_read_counter(event);
}

static void p8_nest_event_stop(struct perf_event *event, int flags)
{
	if (flags & PERF_EF_UPDATE)
		p8_nest_perf_event_update(event);
}

static int p8_nest_event_add(struct perf_event *event, int flags)
{
	if (flags & PERF_EF_START)
		p8_nest_event_start(event, flags);

	return 0;
}

/*
 * Populate pmu ops in the structure
 */
static int update_pmu_ops(struct nest_pmu *pmu)
{
	if (!pmu)
		return -EINVAL;

	pmu->pmu.task_ctx_nr = perf_invalid_context;
	pmu->pmu.event_init = p8_nest_event_init;
	pmu->pmu.add = p8_nest_event_add;
	pmu->pmu.del = p8_nest_event_stop;
	pmu->pmu.start = p8_nest_event_start;
	pmu->pmu.stop = p8_nest_event_stop;
	pmu->pmu.read = p8_nest_perf_event_update;
	pmu->pmu.attr_groups = pmu->attr_groups;

	return 0;
}

static int nest_event_info(char *name, struct nest_ima_events *p8_events)
{
	char *buf;

	/* memory for content */
	buf = kzalloc(P8_NEST_MAX_PMU_NAME_LEN, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	p8_events->ev_name = name;
	p8_events->ev_value = buf;
	return 0;
}

static int nest_event_info_str(struct property *pp, char *name,
					struct nest_ima_events *p8_events)
{
	if (nest_event_info(name, p8_events))
		return -ENOMEM;

	if (!pp->value || (strnlen(pp->value, pp->length) == pp->length) ||
	    (pp->length > P8_NEST_MAX_PMU_NAME_LEN))
		return -EINVAL;

	strncpy(p8_events->ev_value, (const char *)pp->value, pp->length);
	return 0;
}

static int nest_event_info_val(char *name, u32 val,
					struct nest_ima_events *p8_events)
{
	if (nest_event_info(name, p8_events))
		return -ENOMEM;

	sprintf(p8_events->ev_value, "event=0x%x", val);
	return 0;
}

/*
 * Populate event name and string in attribute
 */
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

static int update_events_in_group(
	struct nest_ima_events *p8_events, int idx, struct nest_pmu *pmu)
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
	if (!attrs)
		return -ENOMEM;

	attr_group->name = "events";
	attr_group->attrs = attrs;

	for (i = 0; i < idx; i++, p8_events++)
		attrs[i] = dev_str_attr((char *)p8_events->ev_name,
					(char *)p8_events->ev_value);

	pmu->attr_groups[0] = attr_group;
	return 0;
}

static int nest_events_node_parser(struct device_node *dev,
					struct nest_ima_events *p8_events)
{
	struct property *name, *pp, *id;
	char *buf, *start, *ev_name;
	u32 val;
	int idx = 0, ret;

	if (!dev)
		return -EINVAL;

	/*
	 * Loop through each property
	 */
	name = of_find_property(dev, "name", NULL);
	if (!name) {
		printk(KERN_INFO "No property by name\n");
		return -1;
	}

	if (!name->value ||
	   (strnlen(name->value, name->length) == name->length) ||
	   (name->length > P8_NEST_MAX_PMU_NAME_LEN))
		return -EINVAL;

	ev_name = kzalloc(P8_NEST_MAX_PMU_NAME_LEN, GFP_KERNEL);
	if (!ev_name)
		return -ENOMEM;

	/* Now that we got the event name, look for id */
	id = of_find_property(dev, "id", NULL);
	if (!id) {
		strncpy(ev_name, name->value, (int)strlen(name->value));
		printk(KERN_INFO "No property by id = %s\n", ev_name);
	} else {
		if (!id->value ||
		   (strnlen(id->value, id->length) == id->length) ||
		   (id->length > P8_NEST_MAX_PMU_NAME_LEN))
			return -EINVAL;

		of_property_read_u32(dev, id->name, &val);
		sprintf(ev_name, "%s%x", (char *)name->value, val);
	}

	for_each_property_of_node(dev, pp) {
		start = pp->name;

		/* Skip these, we don't need it */
		if (!strcmp(pp->name, "phandle") ||
		    !strcmp(pp->name, "linux,phandle") ||
		    !strcmp(pp->name, "name"))
			continue;

		if (strncmp(pp->name, "reg", 3) == 0) {
			of_property_read_u32(dev, pp->name, &val);
			ret = nest_event_info_val(ev_name, val, &p8_events[idx]);
			idx++;
		} else if (strncmp(pp->name, "unit", 4) == 0) {
			buf = kzalloc(P8_NEST_MAX_PMU_NAME_LEN, GFP_KERNEL);
			if (!buf)
				return -ENOMEM;
			sprintf(buf,"%s.unit", ev_name);
			ret = nest_event_info_str(pp, buf, &p8_events[idx]);
			idx++;
		} else if (strncmp(pp->name, "scale", 5) == 0) {
			buf = kzalloc(P8_NEST_MAX_PMU_NAME_LEN, GFP_KERNEL);
			if (!buf)
				return -ENOMEM;
			sprintf(buf,"%s.scale", ev_name);
			ret = nest_event_info_str(pp, buf, &p8_events[idx]);
			idx++;
		}

		if (ret)
			return ret;

		/* book keeping */
	}

	return idx;
}

static int nest_pmu_create(struct device_node *parent, int pmu_index)
{
	struct device_node *ev_node;
	struct nest_ima_events *p8_events;
	struct nest_pmu *pmu_ptr;
	struct property *pp;
	char *buf;
	int idx = 0, ret;

	if (!parent)
		return -EINVAL;

	/* memory for nest pmus */
	pmu_ptr = kzalloc(sizeof(struct nest_pmu), GFP_KERNEL);
	if (!pmu_ptr)
		return -ENOMEM;

	/* Needed for hotplug/migration */
	per_nest_pmu_arr[pmu_index] = pmu_ptr;

	/* memory for nest pmu events */
	p8_events = kzalloc((sizeof(struct nest_ima_events) *
				P8_NEST_MAX_EVENTS_SUPPORTED), GFP_KERNEL);
	if (!p8_events)
		return -ENOMEM;

	pp = of_find_property(parent, "name", NULL);
	if (!pp) {
		printk(KERN_INFO "No property by name\n");
		return -1;
	}

	if (!pp->value ||
	   (strnlen(pp->value, pp->length) == pp->length) ||
	   (pp->length > P8_NEST_MAX_PMU_NAME_LEN))
		return -EINVAL;

	buf = kzalloc(P8_NEST_MAX_PMU_NAME_LEN, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Save the name to register it later */
	sprintf(buf, "nest_%s", (char *)pp->value);
	pmu_ptr->pmu.name = (char *)buf;
	pmu_ptr->attr_groups[1] = &p8_nest_format_group;
	pmu_ptr->attr_groups[2] = &nest_pmu_cpumask_attr_group;

	/* Loop through event nodes */
	for_each_child_of_node(parent, ev_node) {
		ret = nest_events_node_parser(ev_node, &p8_events[idx]);
		if (ret < 0)
			return -1;

		/*
		 * nest_event_node_parser will return number of
		 * event entried created for this. This could include
		 * event scale and unit files also.
		 */
		idx += ret;
	}

	update_events_in_group(p8_events, idx, pmu_ptr);

	update_pmu_ops(pmu_ptr);
	/* Register the pmu */
	ret = perf_pmu_register(&pmu_ptr->pmu, pmu_ptr->pmu.name, -1);
	if (ret) {
		pr_err("Nest PMU %s Register failed\n", pmu_ptr->pmu.name);
		return ret;
	}

	pr_info("%s performance monitor hardware support registered\n",
			pmu_ptr->pmu.name);

	return 0;
}

static int nest_ima_dt_parser(void)
{
	struct device_node *child, *parent, *unit;
	struct perchip_nest_info *p8ni;
	u32 idx, range[4], pages;
	int ret, i=0, pmu_count=0;

	/*
	 * "nest-ima" folder contains two things,
	 * a) per-chip reserved memory region for Nest PMU Counter data
	 * b) Support Nest PMU units and their event files
	 */
	parent = of_find_compatible_node(NULL, NULL, "ibm,opal-in-memory-counters");
	for_each_child_of_node(parent, child) {
		if (of_property_read_u32(child, "ibm,chip-id", &idx)) {
			pr_err("Nest_PMU: device %s missing property\n",
							child->full_name);
			return -ENODEV;
		}

                /*
                 *"ranges" property will have four u32 cells.
                 */
                if (of_property_read_u32_array(child, "ranges", range, 4)) {
                        printk(KERN_INFO "range property value wrong\n");
                        return -1;
                }

                p8ni = &p8_nest_perchip_info[idx];
                p8ni->pbase = range[1];
		p8ni->pbase = p8ni->pbase << 32 | range[2];
                p8ni->size = range[3];

		do
		{
			pages = PAGE_SIZE * i;
			p8ni->vbase[i++] = (u64)phys_to_virt(p8ni->pbase + pages);
		} while( i < (p8ni->size/PAGE_SIZE));

		/* iterate nest units only once */
		if (idx)
			continue;

		for_each_child_of_node(child, unit) {
			ret = nest_pmu_create(unit, pmu_count++);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int __init nest_pmu_init(void)
{
	int ret = -ENODEV;

	/*
	 * Lets do this only if we are hypervisor
	 */
	if (!cpu_has_feature(CPU_FTR_HVMODE))
		return ret;

	/*
	 * Nest PMU information is grouped under "nest-ima" node
	 * of the top-level device-tree directory. Detect Nest PMU
	 * by the "ibm,ima-chip" property.
	 */
        if (!of_find_compatible_node(NULL, NULL, "ibm,opal-in-memory-counters"))
                return -1;

	/*
	 * Parse device-tree for Nest PMU information
	 */
	ret = nest_ima_dt_parser();
	if (ret)
		return ret;

	/* Add cpumask and register for hotplug notification */
	if (nest_pmu_cpumask_init())
		return ret;

	return 0;
}
device_initcall(nest_pmu_init);
