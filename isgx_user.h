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

#ifndef _X86_ISGX_USER_H
#define _X86_ISGX_USER_H

#include <linux/bitops.h>
#include <linux/ioctl.h>
#include <linux/stddef.h>
#include <linux/types.h>

#define ISGX_IOCTL_ENCLAVE_CREATE	_IOWR('p', 0x02, struct isgx_create_param)
#define ISGX_IOCTL_ENCLAVE_ADD_PAGE	_IOW('p', 0x03, struct isgx_add_param)
#define ISGX_IOCTL_ENCLAVE_INIT		_IOW('p', 0x04, struct isgx_init_param)
#define ISGX_IOCTL_ENCLAVE_DESTROY	_IOW('p', 0x06, struct isgx_destroy_param)

#define SECS_SIZE_OFFSET		0
#define SECS_BASE_OFFSET		(SECS_SIZE_OFFSET + 8)
#define SECS_FLAGS_OFFSET		(SECS_BASE_OFFSET + 8)
#define SECS_SSAFRAMESIZE_OFFSET	(SECS_SIZE_OFFSET + 164)

/* SGX leaf instruction return values */
#define ISGX_SUCCESS			0
#define ISGX_INVALID_SIG_STRUCT		1
#define ISGX_INVALID_ATTRIBUTE		2
#define ISGX_BLKSTATE			3
#define ISGX_INVALID_MEASUREMENT	4
#define ISGX_NOTBLOCKABLE		5
#define ISGX_PG_INVLD			6
#define ISGX_LOCKFAIL			7
#define ISGX_INVALID_SIGNATURE		8
#define ISGX_MAC_COMPARE_FAIL		9
#define ISGX_PAGE_NOT_BLOCKED		10
#define ISGX_NOT_TRACKED		11
#define ISGX_VA_SLOT_OCCUPIED		12
#define ISGX_CHILD_PRESENT		13
#define ISGX_ENCLAVE_ACT		14
#define ISGX_ENTRYEPOCH_LOCKED		15
#define ISGX_INVALID_LICENSE		16
#define ISGX_PREV_TRK_INCMPL 		17
#define ISGX_PG_IS_SECS 		18
#define ISGX_INVALID_CPUSVN		32
#define ISGX_INVALID_ISVSVN		64
#define ISGX_UNMASKED_EVENT		128
#define ISGX_INVALID_KEYNAME		256

/* IOCTL return values */
#define ISGX_POWER_LOST_ENCLAVE		0xc0000002
#define ISGX_LE_ROLLBACK		0xc0000003

/* SECINFO flags */
enum isgx_secinfo_flags {
	ISGX_SECINFO_R		= BIT_ULL(0),
	ISGX_SECINFO_W		= BIT_ULL(1),
	ISGX_SECINFO_X		= BIT_ULL(2),
};

/* SECINFO page types */
enum isgx_secinfo_pt {
	ISGX_SECINFO_SECS	= 0x000ULL,
	ISGX_SECINFO_TCS	= 0x100ULL,
	ISGX_SECINFO_REG	= 0x200ULL,
};

struct isgx_secinfo {
	__u64 flags;
	__u64 reserved[7];
} __attribute__((aligned(128)));

struct isgx_einittoken {
	__u32	valid;
	__u8	reserved1[206];
	__u16	isvsvnle;
	__u8	reserved2[92];
} __attribute__((aligned(512)));

struct isgx_create_param {
	void *secs;
	unsigned long addr;
};

#define ISGX_ADD_SKIP_EEXTEND 0x1

struct isgx_add_param {
	unsigned long		addr;
	unsigned long		user_addr;
	struct isgx_secinfo	*secinfo;
	unsigned int		flags;
};

struct isgx_init_param {
	unsigned long		addr;
	void			*sigstruct;
	struct isgx_einittoken	*einittoken;
};

struct isgx_destroy_param {
	unsigned long addr;
};

#endif /* _X86_ISGX_USER_H */
