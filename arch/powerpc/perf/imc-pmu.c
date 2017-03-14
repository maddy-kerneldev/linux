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

	ret = update_events_in_group(events, idx, pmu_ptr);
	if (ret)
		goto err_free;

	return 0;

err_free:
	/* Only free the attr_groups which are dynamically allocated  */
	if (pmu_ptr->attr_groups[0]) {
		kfree(pmu_ptr->attr_groups[0]->attrs);
		kfree(pmu_ptr->attr_groups[0]);
	}

	return ret;
}
