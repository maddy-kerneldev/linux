#ifndef PPC_POWERNV_IMC_PMU_DEF_H
#define PPC_POWERNV_IMC_PMU_DEF_H

/*
 * IMC Nest Performance Monitor counter support.
 *
 * Copyright (C) 2016 Madhavan Srinivasan, IBM Corporation.
 *           (C) 2016 Hemant K Shaw, IBM Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#include <linux/perf_event.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/io.h>
#include <asm/opal.h>

#define IMC_MAX_CHIPS			32
#define IMC_MAX_PMUS			32
#define IMC_MAX_PMU_NAME_LEN		256

#define NEST_IMC_ENGINE_START		1
#define NEST_IMC_ENGINE_STOP		0
#define NEST_MAX_PAGES			16

#define NEST_IMC_PRODUCTION_MODE	1

#define IMC_DTB_COMPAT		"ibm,opal-in-memory-counters"
#define IMC_DTB_NEST_COMPAT	"ibm,imc-counters-nest"

/*
 * Structure to hold per chip specific memory address
 * information for nest pmus. Nest Counter data are exported
 * in per-chip reserved memory region by the PORE Engine.
 */
struct perchip_nest_info {
	u32 chip_id;
	u64 pbase;
	u64 vbase[NEST_MAX_PAGES];
	u64 size;
};

/*
 * Place holder for nest pmu events and values.
 */
struct imc_events {
	char *ev_name;
	char *ev_value;
};

/*
 * Device tree parser code detects IMC pmu support and
 * registers new IMC pmus. This structure will
 * hold the pmu functions and attrs for each imc pmu and
 * will be referenced at the time of pmu registration.
 */
struct imc_pmu {
	struct pmu pmu;
	int domain;
	const struct attribute_group *attr_groups[4];
};

/*
 * Domains for IMC PMUs
 */
#define IMC_DOMAIN_NEST		1

#define UNKNOWN_DOMAIN		-1

#endif /* PPC_POWERNV_IMC_PMU_DEF_H */
