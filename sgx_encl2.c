/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2016-2017 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * Contact Information:
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 * Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
 *
 * BSD LICENSE
 *
 * Copyright(c) 2016-2017 Intel Corporation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors:
 *
 * Serge Ayoun <serge.ayoun@intel.com>
 * Angie Chinchilla <angie.v.chinchilla@intel.com>
 * Shay Katz-zamir <shay.katz-zamir@intel.com>
 * Cedric Xing <cedric.xing@intel.com>
 */

#include "sgx.h"
#include <linux/ratelimit.h>
#include <linux/slab.h>

#define SGX_NR_MOD_CHUNK_PAGES 16

int sgx_init_page(struct sgx_encl *encl, struct sgx_encl_page *entry,
		  unsigned long addr, unsigned int alloc_flags,
		  struct sgx_epc_page **va_src, bool already_locked);
/**
 * sgx_encl_augment() - adds a page to an enclave
 * @addr:	virtual address where the page should be added
 *
 * the address is checked against the dynamic ranges defined for
 * the enclave. If it matches one, a page is added at the
 * corresponding location
 *
 * Note: Invoking function must already hold the encl->lock
 */
struct sgx_encl_page *sgx_encl_augment(struct vm_area_struct *vma,
				       unsigned long addr,
				       bool write)
{
	struct sgx_pageinfo pginfo;
	struct sgx_epc_page *epc_page, *va_page = NULL;
	struct sgx_epc_page *secs_epc_page = NULL;
	struct sgx_encl_page *encl_page;
	struct sgx_encl *encl = (struct sgx_encl *) vma->vm_private_data;
	void *epc_va;
	void *secs_va;
	int ret = -EFAULT;

	if (!sgx_has_sgx2)
		return ERR_PTR(-EFAULT);

	/* if vma area is not writable then we will not eaug */
	if (unlikely(!(vma->vm_flags & VM_WRITE)))
		return ERR_PTR(-EFAULT);

	addr &= ~(PAGE_SIZE-1);

	/* Note: Invoking function holds the encl->lock */

	epc_page = sgx_alloc_page(SGX_ALLOC_ATOMIC);
	if (IS_ERR(epc_page)) {
		return ERR_PTR(PTR_ERR(epc_page));
	}

	va_page = sgx_alloc_page(SGX_ALLOC_ATOMIC);
	if (IS_ERR(va_page)) {
		sgx_free_page(epc_page, encl);
		return ERR_PTR(PTR_ERR(va_page));
	}

	encl_page = kzalloc(sizeof(struct sgx_encl_page), GFP_KERNEL);
	if (!encl_page) {
		sgx_free_page(epc_page, encl);
		sgx_free_page(va_page, encl);
		return ERR_PTR(-EFAULT);
	}

	if (!(encl->flags & SGX_ENCL_INITIALIZED))
		goto out;

	if (encl->flags & (SGX_ENCL_SUSPEND | SGX_ENCL_DEAD))
		goto out;

	/*
	if ((rg->rg_desc.flags & SGX_GROW_DOWN_FLAG) && !write)
		goto out;
	*/

	/* Start the augmenting process */
	ret = sgx_init_page(encl, encl_page, addr, 0, &va_page, true);
	if (ret)
		goto out;

	/* If SECS is evicted then reload it first */
	/* Same steps as in sgx_do_fault */
	if (encl->flags & SGX_ENCL_SECS_EVICTED) {
		secs_epc_page = sgx_alloc_page(SGX_ALLOC_ATOMIC);
		if (IS_ERR(secs_epc_page)) {
			ret = PTR_ERR(secs_epc_page);
			secs_epc_page = NULL;
			goto out;
		}

		ret = sgx_eldu(encl, &encl->secs, secs_epc_page, true);
		if (ret)
			goto out;

		encl->secs.epc_page = secs_epc_page;
		encl->flags &= ~SGX_ENCL_SECS_EVICTED;

		/* Do not free */
		secs_epc_page = NULL;
	}

	secs_va = sgx_get_page(encl->secs.epc_page);
	epc_va = sgx_get_page(epc_page);

	pginfo.srcpge = 0;
	pginfo.secinfo = 0;
	pginfo.linaddr = addr;
	pginfo.secs = (unsigned long) secs_va;

	ret = __eaug(&pginfo, epc_va);
	if (ret) {
		pr_err("sgx: eaug failure with ret=%d\n", ret);
		goto out;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
	ret = vmf_insert_pfn(vma, encl_page->addr, PFN_DOWN(epc_page->pa));
	sgx_put_page(epc_va);
	sgx_put_page(secs_va);
	if (ret != VM_FAULT_NOPAGE) {
#else
	ret = vm_insert_pfn(vma, encl_page->addr, PFN_DOWN(epc_page->pa));
	sgx_put_page(epc_va);
	sgx_put_page(secs_va);
	if (ret) {
#endif
		pr_err("sgx: vm_insert_pfn failure with ret=%d\n", ret);
		goto out;
	}

	epc_page->encl_page = encl_page;
	encl_page->epc_page = epc_page;
	encl->secs_child_cnt++;

	ret = radix_tree_insert(&encl->page_tree, encl_page->addr >> PAGE_SHIFT,
			        encl_page);
	if (ret) {
		pr_err("sgx: radix_tree_insert failed with ret=%d\n", ret);
		goto out;
	}
	sgx_test_and_clear_young(encl_page, encl);
	list_add_tail(&encl_page->epc_page->list, &encl->load_list);
	encl_page->flags |= SGX_ENCL_PAGE_ADDED;

	if (va_page)
		sgx_free_page(va_page, encl);
	if (secs_epc_page)
		sgx_free_page(secs_epc_page, encl);

	/*
	 * Write operation corresponds to stack extension
	 * In this case the #PF is caused by a write operation,
	 * most probably a push.
	 * We return SIGBUS such that the OS invokes the enclave's exception
	 * handler which will execute eaccept.
	 */
	if (write)
		return ERR_PTR(-EFAULT);

	return encl_page;

out:
	if (encl_page->va_offset)
		sgx_free_va_slot(encl_page->va_page, encl_page->va_offset);
	sgx_free_page(epc_page, encl);
	if (va_page)
		sgx_free_page(va_page, encl);
	kfree(encl_page);
	if (secs_epc_page)
		sgx_free_page(secs_epc_page, encl);

	if ((ret == -EBUSY)||(ret == -ERESTARTSYS))
		return ERR_PTR(ret);

	return ERR_PTR(-EFAULT);
}

static int isolate_range(struct sgx_encl *encl,
			 struct sgx_range *rg, struct list_head *list)
{
	unsigned long address, end;
	struct sgx_encl_page *encl_page;
	struct vm_area_struct *vma;
	int ret;

	address = rg->start_addr;
	end = address + rg->nr_pages * PAGE_SIZE;
	down_read(&encl->mm->mmap_sem);

	for (; address < end; address += PAGE_SIZE) {
		ret = sgx_encl_find(encl->mm, address, &vma);
		if (ret || encl != vma->vm_private_data) {
			up_read(&encl->mm->mmap_sem);
			return -EINVAL;
		}

		encl_page = ERR_PTR(-EBUSY);
		while (encl_page == ERR_PTR(-EBUSY))
			/* bring back page in case it was evicted */
			encl_page = sgx_fault_page(vma, address,
						   SGX_FAULT_RESERVE, NULL);

		if (IS_ERR(encl_page)) {
			up_read(&encl->mm->mmap_sem);
			sgx_err(encl, "sgx: No page found at address 0x%lx\n",
				 address);
			return PTR_ERR(encl_page);
		}

		/* We do not need the reserved bit anymore as page
		 * is removed from the load list
		 */
		mutex_lock(&encl->lock);
		list_move_tail(&encl_page->epc_page->list, list);
		encl_page->flags &= ~SGX_ENCL_PAGE_RESERVED;
		mutex_unlock(&encl->lock);
	}

	up_read(&encl->mm->mmap_sem);
	return 0;
}

static int __modify_range(struct sgx_encl *encl,
			  struct sgx_range *rg, struct sgx_secinfo *secinfo)
{
	struct sgx_encl_page *encl_page;
	struct sgx_epc_page *epc_page, *tmp;
	LIST_HEAD(list);
	bool emodt = secinfo->flags & (SGX_SECINFO_TRIM | SGX_SECINFO_TCS);
	unsigned int epoch = 0;
	void *epc_va;
	int ret = 0, cnt, status = 0;

	ret = isolate_range(encl, rg, &list);
	if (ret)
		goto out;

	if (list_empty(&list))
		goto out;

	/* EMODT / EMODPR */
	list_for_each_entry_safe(epc_page, tmp, &list, list) {
		encl_page = epc_page->encl_page;
		if (!emodt && (encl_page->flags & SGX_ENCL_PAGE_TCS)) {
			sgx_err(encl, "sgx: illegal request: page at\
				address=0x%lx is a TCS, req flags=0x%llx\n",
				encl_page->addr, secinfo->flags);
			ret = -EINVAL;
			continue;
		}
		mutex_lock(&encl->lock);
		epc_va = sgx_get_page(epc_page);
		status = SGX_LOCKFAIL;
		cnt = 0;
		while (SGX_LOCKFAIL == status && cnt < SGX_EDMM_SPIN_COUNT) {
			if (emodt) {
				status = __emodt(secinfo, epc_va);
				if (!status)
					encl_page->flags |= SGX_ENCL_PAGE_TCS;
			} else
				status = __emodpr(secinfo, epc_va);
			cnt++;
		}

		epoch = encl->shadow_epoch;
		sgx_put_page(epc_va);
		mutex_unlock(&encl->lock);

		if (status) {
			sgx_err(encl, "sgx: Page at address=0x%lx \
				can't be modified err=%d req flags=0x%llx\n",
				encl_page->addr, status, secinfo->flags);
			ret = (ret) ? ret : status;
		} else {
			if (SGX_SECINFO_TRIM == secinfo->flags)
				encl_page->flags |= SGX_ENCL_PAGE_TRIM;
		}
	}

	/* ETRACK */
	mutex_lock(&encl->lock);
	sgx_etrack(encl, epoch);
	mutex_unlock(&encl->lock);

	smp_call_function(sgx_ipi_cb, NULL, 1);

out:
	if (!list_empty(&list)) {
		mutex_lock(&encl->lock);
		list_splice(&list, &encl->load_list);
		mutex_unlock(&encl->lock);
	}

	return ret;
}

long modify_range(struct sgx_range *rg, unsigned long flags)
{
	struct sgx_encl *encl;
	struct sgx_secinfo secinfo;
	struct sgx_range _rg;
	unsigned long end = rg->start_addr + rg->nr_pages * PAGE_SIZE;
	int ret = 0;

	if (!sgx_has_sgx2)
		return -ENOSYS;

	if (rg->start_addr & (PAGE_SIZE - 1))
		return -EINVAL;

	if (!rg->nr_pages)
		return -EINVAL;

	ret = sgx_get_encl(rg->start_addr, &encl);
	if (ret) {
		pr_warn("sgx: No enclave found at start addr 0x%lx ret=%d\n",
			rg->start_addr, ret);
		return ret;
	}

	if (end > encl->base + encl->size) {
		ret = -EINVAL;
		goto out;
	}

	memset(&secinfo, 0, sizeof(secinfo));
	secinfo.flags = flags;

	/*
	 * Modifying the range by chunks of 16 pages:
	 * these pages are removed from the load list. Bigger chunks
	 * may empty EPC load lists and stall SGX.
	 */
	for (_rg.start_addr = rg->start_addr;
	     _rg.start_addr < end;
	     rg->nr_pages -= SGX_NR_MOD_CHUNK_PAGES,
	     _rg.start_addr += SGX_NR_MOD_CHUNK_PAGES*PAGE_SIZE) {
		_rg.nr_pages = rg->nr_pages > 0x10 ? 0x10 : rg->nr_pages;
		ret = __modify_range(encl, &_rg, &secinfo);
		if (ret)
			break;
	}

out:
	kref_put(&encl->refcount, sgx_encl_release);
	return ret;
}

int remove_page(struct sgx_encl *encl, unsigned long address, bool trim)
{
	struct sgx_encl_page *encl_page;
	struct vm_area_struct *vma;
	struct sgx_va_page *va_page;
	int ret;

	ret = sgx_encl_find(encl->mm, address, &vma);
	if (ret || encl != vma->vm_private_data)
		return -EINVAL;

	encl_page = sgx_fault_page(vma, address, SGX_FAULT_RESERVE, NULL);
	if (IS_ERR(encl_page))
		return (PTR_ERR(encl_page) == -EBUSY) ? -EBUSY : -EINVAL;

	if (trim && !(encl_page->flags & SGX_ENCL_PAGE_TRIM)) {
		encl_page->flags &= ~SGX_ENCL_PAGE_RESERVED;
		return -EINVAL;
	}

	if (!(encl_page->flags & SGX_ENCL_PAGE_ADDED)) {
		encl_page->flags &= ~SGX_ENCL_PAGE_RESERVED;
		return -EINVAL;
	}

	mutex_lock(&encl->lock);

	radix_tree_delete(&encl->page_tree, encl_page->addr >> PAGE_SHIFT);
	va_page = encl_page->va_page;

	if (va_page) {
		sgx_free_va_slot(va_page, encl_page->va_offset);

		if (sgx_va_slots_empty(va_page)) {
			list_del(&va_page->list);
			sgx_free_page(va_page->epc_page, encl);
			kfree(va_page);
		}
	}

	if (encl_page->epc_page) {
		list_del(&encl_page->epc_page->list);
		encl_page->epc_page->encl_page = NULL;
		zap_vma_ptes(vma, encl_page->addr, PAGE_SIZE);
		sgx_free_page(encl_page->epc_page, encl);
		encl->secs_child_cnt--;
	}

	mutex_unlock(&encl->lock);

	kfree(encl_page);

	return 0;
}
