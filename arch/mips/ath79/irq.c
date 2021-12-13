/*
 *  Atheros AR71xx/AR724x/AR913x specific interrupt handling
 *
 *  Copyright (C) 2010-2011 Jaiganesh Narayanan <jnarayanan@atheros.com>
 *  Copyright (C) 2008-2011 Gabor Juhos <juhosg@openwrt.org>
 *  Copyright (C) 2008 Imre Kaloz <kaloz@openwrt.org>
 *
 *  Parts of this file are based on Atheros' 2.6.15/2.6.31 BSP
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License version 2 as published
 *  by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irqchip.h>
#include <linux/of_irq.h>

#include <asm/irq_cpu.h>
#include <asm/mipsregs.h>

#include <asm/mach-ath79/ath79.h>
#include <asm/mach-ath79/ar71xx_regs.h>
#include "common.h"
#include "machtypes.h"


static struct irq_chip ip2_chip;
static struct irq_chip ip3_chip;

static void ar934x_ip2_irq_dispatch(struct irq_desc *desc)
{
	u32 status;

	status = ath79_reset_rr(AR934X_RESET_REG_PCIE_WMAC_INT_STATUS);
	status &= AR934X_PCIE_WMAC_INT_PCIE_ALL | AR934X_PCIE_WMAC_INT_WMAC_ALL;

	if (status == 0) {
		spurious_interrupt();
		return;
	}

	if (status & AR934X_PCIE_WMAC_INT_PCIE_ALL) {
		ath79_ddr_wb_flush(3);
		generic_handle_irq(ATH79_IP2_IRQ(0));
	}

	if (status & AR934X_PCIE_WMAC_INT_WMAC_ALL) {
		ath79_ddr_wb_flush(4);
		generic_handle_irq(ATH79_IP2_IRQ(1));
	}
}

static void ar934x_ip2_irq_init(void)
{
	int i;

	for (i = ATH79_IP2_IRQ_BASE;
	     i < ATH79_IP2_IRQ_BASE + ATH79_IP2_IRQ_COUNT; i++)
		irq_set_chip_and_handler(i, &ip2_chip, handle_level_irq);

	irq_set_chained_handler(ATH79_CPU_IRQ(2), ar934x_ip2_irq_dispatch);
}

static void qca953x_ip2_irq_dispatch(struct irq_desc *desc)
{
	u32 status;

	status = ath79_reset_rr(QCA953X_RESET_REG_PCIE_WMAC_INT_STATUS);
	status &= QCA953X_PCIE_WMAC_INT_PCIE_ALL | QCA953X_PCIE_WMAC_INT_WMAC_ALL;

	if (status == 0) {
		spurious_interrupt();
		return;
	}

	if (status & QCA953X_PCIE_WMAC_INT_PCIE_ALL) {
		ath79_ddr_wb_flush(3);
		generic_handle_irq(ATH79_IP2_IRQ(0));
	}

	if (status & QCA953X_PCIE_WMAC_INT_WMAC_ALL) {
		ath79_ddr_wb_flush(4);
		generic_handle_irq(ATH79_IP2_IRQ(1));
	}
}

static void qca953x_irq_init(void)
{
	int i;

	for (i = ATH79_IP2_IRQ_BASE;
	     i < ATH79_IP2_IRQ_BASE + ATH79_IP2_IRQ_COUNT; i++)
		irq_set_chip_and_handler(i, &ip2_chip, handle_level_irq);

	irq_set_chained_handler(ATH79_CPU_IRQ(2), qca953x_ip2_irq_dispatch);
}

static void qca955x_ip2_irq_dispatch(struct irq_desc *desc)
{
	u32 status;

	status = ath79_reset_rr(QCA955X_RESET_REG_EXT_INT_STATUS);
	status &= QCA955X_EXT_INT_PCIE_RC1_ALL | QCA955X_EXT_INT_WMAC_ALL;

	if (status == 0) {
		spurious_interrupt();
		return;
	}

	if (status & QCA955X_EXT_INT_PCIE_RC1_ALL) {
		ath79_ddr_wb_flush(3);
		generic_handle_irq(ATH79_IP2_IRQ(0));
	}

	if (status & QCA955X_EXT_INT_WMAC_ALL) {
		ath79_ddr_wb_flush(4);
		generic_handle_irq(ATH79_IP2_IRQ(1));
	}
}

static void qca955x_ip3_irq_dispatch(struct irq_desc *desc)
{
	u32 status;

	status = ath79_reset_rr(QCA955X_RESET_REG_EXT_INT_STATUS);
	status &= QCA955X_EXT_INT_PCIE_RC2_ALL |
		  QCA955X_EXT_INT_USB1 |
		  QCA955X_EXT_INT_USB2;

	if (status == 0) {
		spurious_interrupt();
		return;
	}

	if (status & QCA955X_EXT_INT_USB1) {
		ath79_ddr_wb_flush(2);
		generic_handle_irq(ATH79_IP3_IRQ(0));
	}

	if (status & QCA955X_EXT_INT_USB2) {
		ath79_ddr_wb_flush(2);
		generic_handle_irq(ATH79_IP3_IRQ(1));
	}

	if (status & QCA955X_EXT_INT_PCIE_RC2_ALL) {
		ath79_ddr_wb_flush(3);
		generic_handle_irq(ATH79_IP3_IRQ(2));
	}
}

static void qca955x_irq_init(void)
{
	int i;

	for (i = ATH79_IP2_IRQ_BASE;
	     i < ATH79_IP2_IRQ_BASE + ATH79_IP2_IRQ_COUNT; i++)
		irq_set_chip_and_handler(i, &ip2_chip, handle_level_irq);

	irq_set_chained_handler(ATH79_CPU_IRQ(2), qca955x_ip2_irq_dispatch);

	for (i = ATH79_IP3_IRQ_BASE;
	     i < ATH79_IP3_IRQ_BASE + ATH79_IP3_IRQ_COUNT; i++)
		irq_set_chip_and_handler(i, &ip3_chip, handle_level_irq);

	irq_set_chained_handler(ATH79_CPU_IRQ(3), qca955x_ip3_irq_dispatch);
}

static void qca956x_ip2_irq_dispatch(struct irq_desc *desc)
{
	u32 status;

	status = ath79_reset_rr(QCA956X_RESET_REG_EXT_INT_STATUS);
	status &= QCA956X_EXT_INT_PCIE_RC1_ALL | QCA956X_EXT_INT_WMAC_ALL;

	if (status == 0) {
		spurious_interrupt();
		return;
	}

	if (status & QCA956X_EXT_INT_PCIE_RC1_ALL) {
		/* TODO: flush DDR? */
		generic_handle_irq(ATH79_IP2_IRQ(0));
	}

	if (status & QCA956X_EXT_INT_WMAC_ALL) {
		/* TODO: flsuh DDR? */
		generic_handle_irq(ATH79_IP2_IRQ(1));
	}
}

static void qca956x_ip3_irq_dispatch(struct irq_desc *desc)
{
	u32 status;

	status = ath79_reset_rr(QCA956X_RESET_REG_EXT_INT_STATUS);
	status &= QCA956X_EXT_INT_PCIE_RC2_ALL |
		  QCA956X_EXT_INT_USB1 | QCA956X_EXT_INT_USB2;

	if (status == 0) {
		spurious_interrupt();
		return;
	}

	if (status & QCA956X_EXT_INT_USB1) {
		/* TODO: flush DDR? */
		generic_handle_irq(ATH79_IP3_IRQ(0));
	}

	if (status & QCA956X_EXT_INT_USB2) {
		/* TODO: flush DDR? */
		generic_handle_irq(ATH79_IP3_IRQ(1));
	}

	if (status & QCA956X_EXT_INT_PCIE_RC2_ALL) {
		/* TODO: flush DDR? */
		generic_handle_irq(ATH79_IP3_IRQ(2));
	}
}

static void qca956x_enable_timer_cb(void) {
	u32 misc;

	misc = ath79_reset_rr(AR71XX_RESET_REG_MISC_INT_ENABLE);
	misc |= MISC_INT_MIPS_SI_TIMERINT_MASK;
	ath79_reset_wr(AR71XX_RESET_REG_MISC_INT_ENABLE, misc);
}

static void qca956x_irq_init(void)
{
	int i;

	for (i = ATH79_IP2_IRQ_BASE;
	     i < ATH79_IP2_IRQ_BASE + ATH79_IP2_IRQ_COUNT; i++)
		irq_set_chip_and_handler(i, &ip2_chip, handle_level_irq);

	irq_set_chained_handler(ATH79_CPU_IRQ(2), qca956x_ip2_irq_dispatch);

	for (i = ATH79_IP3_IRQ_BASE;
	     i < ATH79_IP3_IRQ_BASE + ATH79_IP3_IRQ_COUNT; i++)
		irq_set_chip_and_handler(i, &ip3_chip, handle_level_irq);

	irq_set_chained_handler(ATH79_CPU_IRQ(3), qca956x_ip3_irq_dispatch);

	/* QCA956x timer init workaround has to be applied right before setting
	 * up the clock. Else, there will be no jiffies */
	late_time_init = &qca956x_enable_timer_cb;
}

static void ath79_ip2_disable(struct irq_data *data)
{
	disable_irq(ATH79_CPU_IRQ(2));
}

static void ath79_ip2_enable(struct irq_data *data)
{
	enable_irq(ATH79_CPU_IRQ(2));
}

static void ath79_ip3_disable(struct irq_data *data)
{
	disable_irq(ATH79_CPU_IRQ(3));
}

static void ath79_ip3_enable(struct irq_data *data)
{
	enable_irq(ATH79_CPU_IRQ(3));
}

void __init arch_init_irq(void)
{
	unsigned irq_wb_chan2 = -1;
	unsigned irq_wb_chan3 = -1;
	bool misc_is_ar71xx;

	ip2_chip = dummy_irq_chip;
	ip2_chip.irq_disable = ath79_ip2_disable;
	ip2_chip.irq_enable = ath79_ip2_enable;

	ip3_chip = dummy_irq_chip;
	ip3_chip.irq_disable = ath79_ip3_disable;
	ip3_chip.irq_enable = ath79_ip3_enable;

	if (mips_machtype == ATH79_MACH_GENERIC_OF) {
		irqchip_init();
		return;
	}

	if (soc_is_ar71xx() || soc_is_ar724x() ||
	    soc_is_ar913x() || soc_is_ar933x()) {
		irq_wb_chan2 = 3;
		irq_wb_chan3 = 2;
	} else if (soc_is_ar934x() || soc_is_qca953x()) {
		irq_wb_chan3 = 2;
	}

	ath79_cpu_irq_init(irq_wb_chan2, irq_wb_chan3);

	if (soc_is_ar71xx() || soc_is_ar913x())
		misc_is_ar71xx = true;
	else if (soc_is_ar724x() ||
		 soc_is_ar933x() ||
		 soc_is_ar934x() ||
		 soc_is_qca953x() ||
		 soc_is_qca955x() ||
		 soc_is_qca956x() ||
		 soc_is_tp9343())
		misc_is_ar71xx = false;
	else
		BUG();
	ath79_misc_irq_init(
		ath79_reset_base + AR71XX_RESET_REG_MISC_INT_STATUS,
		ATH79_CPU_IRQ(6), ATH79_MISC_IRQ_BASE, misc_is_ar71xx);

	if (soc_is_ar934x())
		ar934x_ip2_irq_init();
	else if (soc_is_qca953x())
		qca953x_irq_init();
	else if (soc_is_qca955x())
		qca955x_irq_init();
	else if (soc_is_qca956x() || soc_is_tp9343())
		qca956x_irq_init();
}
