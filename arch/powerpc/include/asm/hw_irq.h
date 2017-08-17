/*
 * Copyright (C) 1999 Cort Dougan <cort@cs.nmt.edu>
 */
#ifndef _ASM_POWERPC_HW_IRQ_H
#define _ASM_POWERPC_HW_IRQ_H

#ifdef __KERNEL__

#include <linux/errno.h>
#include <linux/compiler.h>
#include <asm/ptrace.h>
#include <asm/processor.h>

#ifdef CONFIG_PPC64

/*
 * PACA flags in paca->irq_happened.
 *
 * This bits are set when interrupts occur while soft-disabled
 * and allow a proper replay. Additionally, PACA_IRQ_HARD_DIS
 * is set whenever we manually hard disable.
 */
#define PACA_IRQ_HARD_DIS	0x01
#define PACA_IRQ_DBELL		0x02
#define PACA_IRQ_EE		0x04
#define PACA_IRQ_DEC		0x08 /* Or FIT */
#define PACA_IRQ_EE_EDGE	0x10 /* BookE only */
#define PACA_IRQ_HMI		0x20
#define PACA_IRQ_PMI		0x40

/*
 * flags for paca->soft_disable_mask
 */
#define IRQ_DISABLE_MASK_NONE	0
#define IRQ_DISABLE_MASK_LINUX	1
#define IRQ_DISABLE_MASK_PMU	2
#define IRQ_DISABLE_MASK_ALL	3

#endif /* CONFIG_PPC64 */

#ifndef __ASSEMBLY__

extern void __replay_interrupt(unsigned int vector);

extern void timer_interrupt(struct pt_regs *);
extern void performance_monitor_exception(struct pt_regs *regs);
extern void WatchdogException(struct pt_regs *regs);
extern void unknown_exception(struct pt_regs *regs);

#ifdef CONFIG_PPC64
#include <asm/paca.h>

/*
 * The "memory" clobber acts as both a compiler barrier
 * for the critical section and as a clobber because
 * we changed paca->soft_disable_mask
 */
static inline notrace void soft_disable_mask_set(unsigned long enable)
{
	__asm__ __volatile__("stb %0,%1(13)"
	: : "r" (enable), "i" (offsetof(struct paca_struct, soft_disable_mask))
	: "memory");
}

static inline notrace unsigned long soft_disable_mask_return(void)
{
	unsigned long flags;

	asm volatile(
		"lbz %0,%1(13)"
		: "=r" (flags)
		: "i" (offsetof(struct paca_struct, soft_disable_mask)));

	return flags;
}

static inline notrace unsigned long soft_disable_mask_set_return(unsigned long enable)
{
	unsigned long flags, zero;

	asm volatile(
		"mr %1,%3; lbz %0,%2(13); stb %1,%2(13)"
		: "=r" (flags), "=&r" (zero)
		: "i" (offsetof(struct paca_struct, soft_disable_mask)),\
		  "r" (enable)
		: "memory");

	return flags;
}

static inline notrace unsigned long soft_disable_mask_or_return(unsigned long enable)
{
	unsigned long flags, zero;

	asm volatile(
		"mr %1,%3; lbz %0,%2(13); or %1,%0,%1; stb %1,%2(13)"
		: "=r" (flags), "=&r"(zero)
		: "i" (offsetof(struct paca_struct, soft_disable_mask)),\
		 "r" (enable)
		: "memory");

	return flags;
}

static inline unsigned long arch_local_save_flags(void)
{
	return soft_disable_mask_return();
}

extern void arch_local_irq_restore(unsigned long);

static inline void arch_local_irq_enable(void)
{
	arch_local_irq_restore(IRQ_DISABLE_MASK_NONE);
}

static inline unsigned long arch_local_irq_save(void)
{
	return soft_disable_mask_set_return(IRQ_DISABLE_MASK_LINUX);
}

static inline void arch_local_irq_disable(void)
{
	arch_local_irq_save();
}

static inline bool arch_irqs_disabled_flags(unsigned long flags)
{
	return flags & IRQ_DISABLE_MASK_LINUX;
}

static inline bool arch_irqs_disabled(void)
{
	return arch_irqs_disabled_flags(arch_local_save_flags());
}

/*
 * To support disabling and enabling of irq with PMI, set of
 * new powerpc_local_irq_pmu_save() and powerpc_local_irq_restore()
 * functions are added. These macros are implemented using generic
 * linux local_irq_* code from include/linux/irqflags.h.
 */
#define raw_local_irq_pmu_save(flags)					\
	do {								\
		typecheck(unsigned long, flags);			\
		flags = soft_disable_mask_or_return(IRQ_DISABLE_MASK_LINUX | \
				IRQ_DISABLE_MASK_PMU);			\
	} while(0)

#define raw_local_irq_pmu_restore(flags)				\
	do {								\
		typecheck(unsigned long, flags);			\
		arch_local_irq_restore(flags);				\
	} while(0)

#ifdef CONFIG_TRACE_IRQFLAGS
#define powerpc_local_irq_pmu_save(flags)			\
	 do {							\
		raw_local_irq_pmu_save(flags);			\
		trace_hardirqs_off();				\
	} while(0)
#define powerpc_local_irq_pmu_restore(flags)			\
	do {							\
		if (raw_irqs_disabled_flags(flags)) {		\
			raw_local_irq_pmu_restore(flags);	\
			trace_hardirqs_off();			\
		} else {					\
			trace_hardirqs_on();			\
			raw_local_irq_pmu_restore(flags);	\
		}						\
	} while(0)
#else
#define powerpc_local_irq_pmu_save(flags)			\
	do {							\
		raw_local_irq_pmu_save(flags);			\
	} while(0)
#define powerpc_local_irq_pmu_restore(flags)			\
	do {							\
		raw_local_irq_pmu_restore(flags);		\
	} while (0)
#endif  /* CONFIG_TRACE_IRQFLAGS */

#ifdef CONFIG_PPC_BOOK3E
#define __hard_irq_enable()	asm volatile("wrteei 1" : : : "memory")
#define __hard_irq_disable()	asm volatile("wrteei 0" : : : "memory")
#else
#define __hard_irq_enable()	__mtmsrd(local_paca->kernel_msr | MSR_EE, 1)
#define __hard_irq_disable()	__mtmsrd(local_paca->kernel_msr, 1)
#endif

#define hard_irq_disable()	do {			\
	unsigned long flags;				\
	__hard_irq_disable();				\
	flags = soft_disable_mask_set_return(IRQ_DISABLE_MASK_ALL);\
	local_paca->irq_happened |= PACA_IRQ_HARD_DIS;	\
	if (!arch_irqs_disabled_flags(flags))		\
		trace_hardirqs_off();			\
} while(0)

static inline bool lazy_irq_pending(void)
{
	return !!(get_paca()->irq_happened & ~PACA_IRQ_HARD_DIS);
}

/*
 * This is called by asynchronous interrupts to conditionally
 * re-enable hard interrupts when soft-disabled after having
 * cleared the source of the interrupt
 */
static inline void may_hard_irq_enable(void)
{
	get_paca()->irq_happened &= ~PACA_IRQ_HARD_DIS;
	if (!(get_paca()->irq_happened & PACA_IRQ_EE))
		__hard_irq_enable();
}

static inline bool arch_irq_disabled_regs(struct pt_regs *regs)
{
	return (regs->softe & IRQ_DISABLE_MASK_LINUX);
}

extern bool prep_irq_for_idle(void);
extern bool prep_irq_for_idle_irqsoff(void);
extern void irq_set_pending_from_srr1(unsigned long srr1);

#define fini_irq_for_idle_irqsoff() trace_hardirqs_off();

extern void force_external_irq_replay(void);

#else /* CONFIG_PPC64 */

#define SET_MSR_EE(x)	mtmsr(x)

static inline unsigned long arch_local_save_flags(void)
{
	return mfmsr();
}

static inline void arch_local_irq_restore(unsigned long flags)
{
#if defined(CONFIG_BOOKE)
	asm volatile("wrtee %0" : : "r" (flags) : "memory");
#else
	mtmsr(flags);
#endif
}

static inline unsigned long arch_local_irq_save(void)
{
	unsigned long flags = arch_local_save_flags();
#ifdef CONFIG_BOOKE
	asm volatile("wrteei 0" : : : "memory");
#elif defined(CONFIG_PPC_8xx)
	wrtspr(SPRN_EID);
#else
	SET_MSR_EE(flags & ~MSR_EE);
#endif
	return flags;
}

static inline void arch_local_irq_disable(void)
{
#ifdef CONFIG_BOOKE
	asm volatile("wrteei 0" : : : "memory");
#elif defined(CONFIG_PPC_8xx)
	wrtspr(SPRN_EID);
#else
	arch_local_irq_save();
#endif
}

static inline void arch_local_irq_enable(void)
{
#ifdef CONFIG_BOOKE
	asm volatile("wrteei 1" : : : "memory");
#elif defined(CONFIG_PPC_8xx)
	wrtspr(SPRN_EIE);
#else
	unsigned long msr = mfmsr();
	SET_MSR_EE(msr | MSR_EE);
#endif
}

static inline bool arch_irqs_disabled_flags(unsigned long flags)
{
	return (flags & MSR_EE) == 0;
}

static inline bool arch_irqs_disabled(void)
{
	return arch_irqs_disabled_flags(arch_local_save_flags());
}

#define hard_irq_disable()		arch_local_irq_disable()

static inline bool arch_irq_disabled_regs(struct pt_regs *regs)
{
	return !(regs->msr & MSR_EE);
}

static inline void may_hard_irq_enable(void) { }

#endif /* CONFIG_PPC64 */

#define ARCH_IRQ_INIT_FLAGS	IRQ_NOREQUEST

/*
 * interrupt-retrigger: should we handle this via lost interrupts and IPIs
 * or should we not care like we do now ? --BenH.
 */
struct irq_chip;

#endif  /* __ASSEMBLY__ */
#endif	/* __KERNEL__ */
#endif	/* _ASM_POWERPC_HW_IRQ_H */
