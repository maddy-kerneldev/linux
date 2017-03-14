/*
 * OPAL IMC interface detection driver
 * Supported on POWERNV platform
 *
 * Copyright	(C) 2016 Madhavan Srinivasan, IBM Corporation.
 *		(C) 2016 Hemant K Shaw, IBM Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/poll.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <asm/opal.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/cputable.h>
#include <asm/imc-pmu.h>

struct perchip_nest_info nest_perchip_info[IMC_MAX_CHIPS];

static int opal_imc_counters_probe(struct platform_device *pdev)
{
	struct device_node *child, *imc_dev, *rm_node = NULL;
	struct perchip_nest_info *pcni;
	u32 reg[4], pages, nest_offset, nest_size, idx;
	int i = 0;
	const char *node_name;

	if (!pdev || !pdev->dev.of_node)
		return -ENODEV;

	imc_dev = pdev->dev.of_node;

	/*
	 * nest_offset : where the nest-counters' data start.
	 * size : size of the entire nest-counters region
	 */
	if (of_property_read_u32(imc_dev, "imc-nest-offset", &nest_offset))
		goto err;
	if (of_property_read_u32(imc_dev, "imc-nest-size", &nest_size))
		goto err;

	/* Find the "homer region" for each chip */
	rm_node = of_find_node_by_path("/reserved-memory");
	if (!rm_node)
		goto err;

	for_each_child_of_node(rm_node, child) {
		if (of_property_read_string_index(child, "name", 0,
						  &node_name))
			continue;
		if (strncmp("ibm,homer-image", node_name,
			    strlen("ibm,homer-image")))
			continue;

		/* Get the chip id to which the above homer region belongs to */
		if (of_property_read_u32(child, "ibm,chip-id", &idx))
			goto err;

		/* reg property will have four u32 cells. */
		if (of_property_read_u32_array(child, "reg", reg, 4))
			goto err;

		pcni = &nest_perchip_info[idx];

		/* Fetch the homer region base address */
		pcni->pbase = reg[0];
		pcni->pbase = pcni->pbase << 32 | reg[1];
		/* Add the nest IMC Base offset */
		pcni->pbase = pcni->pbase + nest_offset;
		/* Fetch the size of the homer region */
		pcni->size = nest_size;

		do {
			pages = PAGE_SIZE * i;
			pcni->vbase[i++] = (u64)phys_to_virt(pcni->pbase +
							     pages);
		} while (i < (pcni->size / PAGE_SIZE));
	}

	return 0;
err:
	return -ENODEV;
}

static const struct of_device_id opal_imc_match[] = {
	{ .compatible = IMC_DTB_COMPAT },
	{},
};

static struct platform_driver opal_imc_driver = {
	.driver = {
		.name = "opal-imc-counters",
		.of_match_table = opal_imc_match,
	},
	.probe = opal_imc_counters_probe,
};

MODULE_DEVICE_TABLE(of, opal_imc_match);
module_platform_driver(opal_imc_driver);
MODULE_DESCRIPTION("PowerNV OPAL IMC driver");
MODULE_LICENSE("GPL");
