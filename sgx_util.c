/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2016 Intel Corporation.
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
 * Copyright(c) 2016 Intel Corporation.
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
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 * Suresh Siddha <suresh.b.siddha@intel.com>
 * Serge Ayoun <serge.ayoun@intel.com>
 * Shay Katz-zamir <shay.katz-zamir@intel.com>
 * Sean Christopherson <sean.j.christopherson@intel.com>
 */

#include "sgx.h"
#include <linux/highmem.h>
#include <linux/shmem_fs.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
	#include <linux/sched/signal.h>
#else
	#include <linux/signal.h>
#endif
#include "linux/file.h"

struct page *sgx_get_backing(struct sgx_encl *encl,
			     struct sgx_encl_page *entry,
			     bool pcmd)
{
	struct inode *inode;
	struct address_space *mapping;
	gfp_t gfpmask;
	pgoff_t index;

	if (pcmd)
		inode = encl->pcmd->f_path.dentry->d_inode;
	else
		inode = encl->backing->f_path.dentry->d_inode;

	mapping = inode->i_mapping;
	gfpmask = mapping_gfp_mask(mapping);

	if (pcmd)
		index = (entry->addr - encl->base) >> (PAGE_SHIFT + 5);
	else
		index = (entry->addr - encl->base) >> PAGE_SHIFT;

	return shmem_read_mapping_page_gfp(mapping, index, gfpmask);
}

void sgx_put_backing(struct page *backing_page, bool write)
{
	if (write)
		set_page_dirty(backing_page);

	put_page(backing_page);
}

struct vm_area_struct *sgx_find_vma(struct sgx_encl *encl, unsigned long addr)
{
	struct vm_area_struct *vma;

	vma = find_vma(encl->mm, addr);
	if (vma && encl == vma->vm_private_data)
		return vma;

	sgx_dbg(encl, "cannot find VMA at 0x%lx\n", addr);
	return NULL;
}

void sgx_zap_tcs_ptes(struct sgx_encl *encl, struct vm_area_struct *vma)
{
	struct sgx_encl_page *entry;

	list_for_each_entry(entry, &encl->load_list, load_list) {
		if ((entry->flags & SGX_ENCL_PAGE_TCS) &&
		    entry->addr >= vma->vm_start &&
		    entry->addr < vma->vm_end)
			zap_vma_ptes(vma, entry->addr, PAGE_SIZE);
	}
}

void sgx_invalidate(struct sgx_encl *encl, bool flush_cpus)
{
	struct vm_area_struct *vma;
	unsigned long addr;

	for (addr = encl->base; addr < (encl->base + encl->size);
	     addr = vma->vm_end) {
		vma = sgx_find_vma(encl, addr);
		if (vma)
			sgx_zap_tcs_ptes(encl, vma);
		else
			break;
	}

	encl->flags |= SGX_ENCL_DEAD;

	if (flush_cpus)
		sgx_flush_cpus(encl);
}

static void sgx_ipi_cb(void *info)
{
}

void sgx_flush_cpus(struct sgx_encl *encl)
{
	on_each_cpu_mask(mm_cpumask(encl->mm), sgx_ipi_cb, NULL, 1);
}

/**
 * sgx_find_encl - find an enclave
 * @mm:		mm struct of the current process
 * @addr:	address in the ELRANGE
 * @vma:	the VMA that is located in the given address
 *
 * Finds an enclave identified by the given address. Gives back the VMA, that is
 * part of the enclave, located in that address.
 */
int sgx_find_encl(struct mm_struct *mm, unsigned long addr,
		  struct vm_area_struct **vma)
{
	struct sgx_encl *encl;

	*vma = find_vma(mm, addr);
	if (!(*vma) || (*vma)->vm_ops != &sgx_vm_ops ||
	    addr < (*vma)->vm_start)
		return -EINVAL;

	encl = (*vma)->vm_private_data;
	if (!encl) {
		pr_debug("%s: VMA exists but there is no enclave at 0x%p\n",
			 __func__, (void *)addr);
		return -EINVAL;
	}

	if (encl->flags & SGX_ENCL_SUSPEND)
		return SGX_POWER_LOST_ENCLAVE;

	return 0;
}

static int sgx_eldu(struct sgx_encl *encl,
		    struct sgx_encl_page *encl_page,
		    struct sgx_epc_page *epc_page,
		    bool is_secs)
{
	struct page *backing;
	struct page *pcmd;
	unsigned long pcmd_offset;
	struct sgx_page_info pginfo;
	void *secs_ptr = NULL;
	void *epc_ptr;
	void *va_ptr;
	int ret;

	pcmd_offset = ((encl_page->addr >> PAGE_SHIFT) & 31) * 128;

	backing = sgx_get_backing(encl, encl_page, false);
	if (IS_ERR(backing)) {
		ret = PTR_ERR(backing);
		sgx_warn(encl, "pinning the backing page for ELDU failed with %d\n",
			 ret);
		return ret;
	}

	pcmd = sgx_get_backing(encl, encl_page, true);
	if (IS_ERR(pcmd)) {
		ret = PTR_ERR(pcmd);
		sgx_warn(encl, "pinning the pcmd page for EWB failed with %d\n",
			 ret);
		goto out;
	}

	if (!is_secs)
		secs_ptr = sgx_get_page(encl->secs_page.epc_page);

	epc_ptr = sgx_get_page(epc_page);
	va_ptr = sgx_get_page(encl_page->va_page->epc_page);
	pginfo.srcpge = (unsigned long)kmap_atomic(backing);
	pginfo.pcmd = (unsigned long)kmap_atomic(pcmd) + pcmd_offset;
	pginfo.linaddr = is_secs ? 0 : encl_page->addr;
	pginfo.secs = (unsigned long)secs_ptr;

	ret = __eldu((unsigned long)&pginfo,
		     (unsigned long)epc_ptr,
		     (unsigned long)va_ptr +
		     encl_page->va_offset);
	if (ret) {
		sgx_err(encl, "ELDU returned %d\n", ret);
		ret = -EFAULT;
	}

	kunmap_atomic((void *)(unsigned long)(pginfo.pcmd - pcmd_offset));
	kunmap_atomic((void *)(unsigned long)pginfo.srcpge);
	sgx_put_page(va_ptr);
	sgx_put_page(epc_ptr);

	if (!is_secs)
		sgx_put_page(secs_ptr);

	sgx_put_backing(pcmd, false);

out:
	sgx_put_backing(backing, false);
	return ret;
}

static struct sgx_encl_page *sgx_do_fault(struct vm_area_struct *vma,
					  unsigned long addr, unsigned int flags)
{
	struct sgx_encl *encl = vma->vm_private_data;
	struct sgx_encl_page *entry;
	struct sgx_epc_page *epc_page = NULL;
	struct sgx_epc_page *secs_epc_page = NULL;
	bool reserve = (flags & SGX_FAULT_RESERVE) != 0;
	int rc = 0;

	/* If process was forked, VMA is still there but vm_private_data is set
	 * to NULL.
	 */
	if (!encl)
		return ERR_PTR(-EFAULT);

	mutex_lock(&encl->lock);

	entry = radix_tree_lookup(&encl->page_tree, addr >> PAGE_SHIFT);
	if (!entry) {
		rc = -EFAULT;
		goto out;
	}

	if (encl->flags & SGX_ENCL_DEAD) {
		rc = -EFAULT;
		goto out;
	}

	if (!(encl->flags & SGX_ENCL_INITIALIZED)) {
		sgx_dbg(encl, "cannot fault, unitialized\n");
		rc = -EFAULT;
		goto out;
	}

	if (reserve && (entry->flags & SGX_ENCL_PAGE_RESERVED)) {
		sgx_dbg(encl, "cannot fault, 0x%p is reserved\n",
			(void *)entry->addr);
		rc = -EBUSY;
		goto out;
	}

	/* Legal race condition, page is already faulted. */
	if (entry->epc_page) {
		if (reserve)
			entry->flags |= SGX_ENCL_PAGE_RESERVED;
		goto out;
	}

	epc_page = sgx_alloc_page(encl, SGX_ALLOC_ATOMIC);
	if (IS_ERR(epc_page)) {
		rc = PTR_ERR(epc_page);
		epc_page = NULL;
		goto out;
	}

	/* If SECS is evicted then reload it first */
	if (encl->flags & SGX_ENCL_SECS_EVICTED) {
		secs_epc_page = sgx_alloc_page(encl, SGX_ALLOC_ATOMIC);
		if (IS_ERR(secs_epc_page)) {
			rc = PTR_ERR(secs_epc_page);
			secs_epc_page = NULL;
			goto out;
		}

		rc = sgx_eldu(encl, &encl->secs_page, secs_epc_page, true);
		if (rc)
			goto out;

		encl->secs_page.epc_page = secs_epc_page;
		encl->flags &= ~SGX_ENCL_SECS_EVICTED;

		/* Do not free */
		secs_epc_page = NULL;
	}

	rc = sgx_eldu(encl, entry, epc_page, false /* is_secs */);
	if (rc)
		goto out;

	/* Track the EPC page even if vm_insert_pfn fails; we need to ensure
	 * the EPC page is properly freed and we can't do EREMOVE right away
	 * because EREMOVE may fail due to an active cpu in the enclave.  We
	 * can't call vm_insert_pfn before sgx_eldu because SKL signals #GP
	 * instead of #PF if the EPC page is invalid.
	 */
	encl->secs_child_cnt++;

	entry->epc_page = epc_page;

	if (reserve)
		entry->flags |= SGX_ENCL_PAGE_RESERVED;

	/* Do not free */
	epc_page = NULL;
	list_add_tail(&entry->load_list, &encl->load_list);

	rc = vm_insert_pfn(vma, entry->addr, PFN_DOWN(entry->epc_page->pa));
	if (rc) {
		/* Kill the enclave if vm_insert_pfn fails; failure only occurs
		 * if there is a driver bug or an unrecoverable issue, e.g. OOM.
		 */
		sgx_crit(encl, "vm_insert_pfn returned %d\n", rc);
		sgx_invalidate(encl, true);
		goto out;
	}

	sgx_test_and_clear_young(entry, encl);
out:
	mutex_unlock(&encl->lock);
	if (epc_page)
		sgx_free_page(epc_page, encl);
	if (secs_epc_page)
		sgx_free_page(secs_epc_page, encl);
	return rc ? ERR_PTR(rc) : entry;
}

struct sgx_encl_page *sgx_fault_page(struct vm_area_struct *vma,
				     unsigned long addr,
				     unsigned int flags)
{
	struct sgx_encl_page *entry;

	do {
		entry = sgx_do_fault(vma, addr, flags);
		if (!(flags & SGX_FAULT_RESERVE))
			break;
	} while (PTR_ERR(entry) == -EBUSY);

	return entry;
}

void sgx_encl_release(struct kref *ref)
{
	struct sgx_encl_page *entry;
	struct sgx_va_page *va_page;
	struct sgx_encl *encl = container_of(ref, struct sgx_encl, refcount);
	struct radix_tree_iter iter;
	void **slot;

	mutex_lock(&sgx_tgid_ctx_mutex);
	if (!list_empty(&encl->encl_list))
		list_del(&encl->encl_list);
	mutex_unlock(&sgx_tgid_ctx_mutex);

	if (encl->mmu_notifier.ops)
		mmu_notifier_unregister_no_release(&encl->mmu_notifier,
						   encl->mm);

	radix_tree_for_each_slot(slot, &encl->page_tree, &iter, 0) {
		entry = *slot;
		if (entry->epc_page) {
			list_del(&entry->load_list);
			sgx_free_page(entry->epc_page, encl);
		}
		radix_tree_delete(&encl->page_tree, entry->addr >> PAGE_SHIFT);
		kfree(entry);
	}

	while (!list_empty(&encl->va_pages)) {
		va_page = list_first_entry(&encl->va_pages,
					   struct sgx_va_page, list);
		list_del(&va_page->list);
		sgx_free_page(va_page->epc_page, encl);
		kfree(va_page);
	}

	if (encl->secs_page.epc_page)
		sgx_free_page(encl->secs_page.epc_page, encl);

	encl->secs_page.epc_page = NULL;

	if (encl->tgid_ctx)
		kref_put(&encl->tgid_ctx->refcount, sgx_tgid_ctx_release);

	if (encl->backing)
		fput(encl->backing);

	if (encl->pcmd)
		fput(encl->pcmd);

	kfree(encl);
}
