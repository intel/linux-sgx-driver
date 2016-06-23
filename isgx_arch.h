/*
 * (C) Copyright 2015 Intel Corporation
 *
 * Authors:
 *
 * Jarkko Sakkinen <jarkko.sakkinen@intel.com>
 * Suresh Siddha <suresh.b.siddha@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#ifndef _X86_ISGX_ARCH_H
#define _X86_ISGX_ARCH_H

#include <asm/asm.h>
#include <linux/bitops.h>
#include <linux/types.h>

#define MSR_ISGX_PRMRR		0x01f4
#define SGX_CPUID		0x12

enum {
	PAGE_TYPE_SECS,
	PAGE_TYPE_TCS,
	PAGE_TYPE_REG,
	PAGE_TYPE_VA,
	};

/* Workaround for kernel versions < 3.13 */
#undef BIT_ULL
#undef GENMASK_ULL
#define BIT_ULL(nr)		(1ULL << (nr))
#define GENMASK_ULL(h, l)	(((U64_C(1) << ((h) - (l) + 1)) - 1) << (l))

enum isgx_secs_attributes {
	ISGX_SECS_A_DEBUG		= BIT_ULL(1),
	ISGX_SECS_A_MODE64BIT		= BIT_ULL(2),
	ISGX_SECS_A_PROVISION_KEY	= BIT_ULL(4),
	ISGX_SECS_A_LICENSE_KEY		= BIT_ULL(5),
	ISGX_SECS_A_RESERVED_MASK	= (BIT_ULL(0) |
					   BIT_ULL(3) |
					   GENMASK_ULL(63, 6)),
};

#define ISGX_SECS_RESERVED1_SIZE 28
#define ISGX_SECS_RESERVED2_SIZE 32
#define ISGX_SECS_RESERVED3_SIZE 96
#define ISGX_SECS_RESERVED4_SIZE 3836

struct isgx_secs {
	u64	size;
	u64	base;
	u32	ssaframesize;
	uint8_t reserved1[ISGX_SECS_RESERVED1_SIZE];
	u64	flags;
	u64	xfrm;
	u32	mrenclave[8];
	uint8_t	reserved2[ISGX_SECS_RESERVED2_SIZE];
	u32	mrsigner[8];
	uint8_t	reserved3[ISGX_SECS_RESERVED3_SIZE];
	u16	isvvprodid;
	u16	isvsvn;
	uint8_t	reserved[ISGX_SECS_RESERVED4_SIZE];
};

struct isgx_tcs {
	u64 state;
	u64 flags;
	u64 ossa;
	u32 cssa;
	u32 nssa;
	u64 oentry;
	u64 aep;
	u64 ofsbase;
	u64 ogsbase;
	u32 fslimit;
	u32 gslimit;
	u64 reserved[503];
};

enum isgx_secinfo_masks {
	ISGX_SECINFO_PERMISSION_MASK	= GENMASK_ULL(2, 0),
	ISGX_SECINFO_PAGE_TYPE_MASK	= GENMASK_ULL(15, 8),
	ISGX_SECINFO_RESERVED_MASK	= (GENMASK_ULL(7, 3) |
					   GENMASK_ULL(63, 16)),
};

struct pcmd {
	struct isgx_secinfo secinfo;
	u64 enclave_id;
	u8 reserved[40];
	u8 mac[16];
};

struct page_info {
	u64 linaddr;
	u64 srcpge;
	union {
		u64 secinfo;
		u64 pcmd;
	};
	u64 secs;
} __attribute__((aligned(32)));

#define SIGSTRUCT_SIZE 1808
#define EINITTOKEN_SIZE 304

enum {
	ECREATE	= 0x0,
	EADD	= 0x1,
	EINIT	= 0x2,
	EREMOVE	= 0x3,
	EDGBRD	= 0x4,
	EDGBWR	= 0x5,
	EEXTEND	= 0x6,
	ELDU	= 0x8,
	EBLOCK	= 0x9,
	EPA	= 0xA,
	EWB	= 0xB,
	ETRACK	= 0xC,
};

#define __encls_ret(rax, rbx, rcx, rdx)	\
	({				\
	int ret;			\
	asm volatile("1: .byte 0x0f, 0x01, 0xcf;\n\t"	\
		     "2: \n"					\
		     ".section .fixup,\"ax\"\n"			\
		     "3:   jmp 2b\n"				\
		     ".previous\n"				\
		     _ASM_EXTABLE(1b, 3b)			\
		     : "=a"(ret)				\
		     : "a"(rax), "b"(rbx), "c"(rcx), "d"(rdx)	\
		     : "memory");				\
	ret;	\
	})

#ifdef CONFIG_X86_64
#define __encls(rax, rbx, rcx, rdx...)	\
	({				\
	int ret;			\
	asm volatile("1: .byte 0x0f, 0x01, 0xcf;\n\t"	\
		     " xor %%eax,%%eax;\n"		\
		     "2: \n"					\
		     ".section .fixup,\"ax\"\n"			\
		     "3: movq $-1,%%rax\n"			\
		     "   jmp 2b\n"				\
		     ".previous\n"				\
		     _ASM_EXTABLE(1b, 3b)			\
		     : "=a"(ret), "=b"(rbx), "=c"(rcx)		\
		     : "a"(rax), "b"(rbx), "c"(rcx), rdx	\
		     : "memory");				\
	ret;	\
	})
#else
#define __encls(rax, rbx, rcx, rdx...)	\
	({				\
	int ret;			\
	asm volatile("1: .byte 0x0f, 0x01, 0xcf;\n\t"	\
		     " xor %%eax,%%eax;\n"		\
		     "2: \n"					\
		     ".section .fixup,\"ax\"\n"			\
		     "3: mov $-1,%%eax\n"			\
		     "   jmp 2b\n"				\
		     ".previous\n"				\
		     _ASM_EXTABLE(1b, 3b)			\
		     : "=a"(ret), "=b"(rbx), "=c"(rcx)		\
		     : "a"(rax), "b"(rbx), "c"(rcx), rdx	\
		     : "memory");				\
	ret;	\
	})
#endif

static inline unsigned long __ecreate(struct page_info *pginfo, void *secs)
{
	return __encls(ECREATE, pginfo, secs, "d"(0));
}

static inline int __eextend(void *secs, void *epc)
{
	return __encls(EEXTEND, secs, epc, "d"(0));
}

static inline int __eadd(struct page_info *pginfo, void *epc)
{
	return __encls(EADD, pginfo, epc, "d"(0));
}

static inline int __einit(void *sigstruct, struct isgx_einittoken *einittoken,
			  void *secs)
{
	return __encls_ret(EINIT, sigstruct, secs, einittoken);
}

static inline int __eremove(void *epc)
{
	unsigned long rbx = 0;
	unsigned long rdx = 0;

	return __encls_ret(EREMOVE, rbx, epc, rdx);
}

static inline int __edbgwr(void *epc, unsigned long *data)
{
	return __encls(EDGBWR, *data, epc, "d"(0));
}

static inline int __edbgrd(void *epc, unsigned long *data)
{
	unsigned long rbx = 0;
	int ret;

	ret = __encls(EDGBRD, rbx, epc, "d"(0));
	if (!ret)
		*(unsigned long *) data = rbx;

	return ret;
}

static inline int __etrack(void *epc)
{
	unsigned long rbx = 0;
	unsigned long rdx = 0;

	return __encls_ret(ETRACK, rbx, epc, rdx);
}

static inline int __eldu(unsigned long rbx, unsigned long rcx,
			 unsigned long rdx)
{
	return __encls_ret(ELDU, rbx, rcx, rdx);
}

static inline int __eblock(unsigned long rcx)
{
	unsigned long rbx = 0;
	unsigned long rdx = 0;

	return __encls_ret(EBLOCK, rbx, rcx, rdx);
}

static inline int __epa(void *epc)
{
	unsigned long rbx = PAGE_TYPE_VA;

	return __encls(EPA, rbx, epc, "d"(0));
}

static inline int __ewb(struct page_info *pginfo, void *epc, void *va)
{
	return __encls_ret(EWB, pginfo, epc, va);
}

#endif /* _X86_ISGX_ARCH_H */
