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
#include <asm/mman.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/ratelimit.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
	#include <linux/sched/signal.h>
#else
	#include <linux/signal.h>
#endif
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/shmem_fs.h>

#define SGX_NR_MOD_CHUNK_PAGES 16

struct sgx_add_page_req {
	struct sgx_encl *encl;
	struct sgx_encl_page *encl_page;
	struct sgx_secinfo secinfo;
	u16 mrmask;
	struct list_head list;
};

static u16 sgx_isvsvnle_min;
atomic_t sgx_nr_pids = ATOMIC_INIT(0);

static struct sgx_tgid_ctx *sgx_find_tgid_ctx(struct pid *tgid)
{
	struct sgx_tgid_ctx *ctx;

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list)
		if (pid_nr(ctx->tgid) == pid_nr(tgid))
			return ctx;

	return NULL;
}

static int sgx_add_to_tgid_ctx(struct sgx_encl *encl)
{
	struct sgx_tgid_ctx *ctx;
	struct pid *tgid = get_pid(task_tgid(current));

	mutex_lock(&sgx_tgid_ctx_mutex);

	ctx = sgx_find_tgid_ctx(tgid);
	if (ctx) {
		if (kref_get_unless_zero(&ctx->refcount)) {
			encl->tgid_ctx = ctx;
			mutex_unlock(&sgx_tgid_ctx_mutex);
			put_pid(tgid);
			return 0;
		}
		else
			list_del_init(&ctx->list);
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		mutex_unlock(&sgx_tgid_ctx_mutex);
		put_pid(tgid);
		return -ENOMEM;
	}

	ctx->tgid = tgid;
	kref_init(&ctx->refcount);
	INIT_LIST_HEAD(&ctx->encl_list);

	list_add(&ctx->list, &sgx_tgid_ctx_list);
	atomic_inc(&sgx_nr_pids);

	encl->tgid_ctx = ctx;

	mutex_unlock(&sgx_tgid_ctx_mutex);
	return 0;
}

void sgx_tgid_ctx_release(struct kref *ref)
{
	struct sgx_tgid_ctx *pe =
		container_of(ref, struct sgx_tgid_ctx, refcount);
	mutex_lock(&sgx_tgid_ctx_mutex);
	list_del(&pe->list);
	atomic_dec(&sgx_nr_pids);
	mutex_unlock(&sgx_tgid_ctx_mutex);
	put_pid(pe->tgid);
	kfree(pe);
}

static int sgx_find_and_get_encl(unsigned long addr, struct sgx_encl **encl)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	int ret;

	down_read(&mm->mmap_sem);

	ret = sgx_find_encl(mm, addr, &vma);
	if (!ret) {
		*encl = vma->vm_private_data;
		kref_get(&(*encl)->refcount);
	}

	up_read(&mm->mmap_sem);

	return ret;
}

static int sgx_measure(struct sgx_epc_page *secs_page,
		       struct sgx_epc_page *epc_page,
		       u16 mrmask)
{
	void *secs;
	void *epc;
	int ret = 0;
	int i, j;

	for (i = 0, j = 1; i < 0x1000 && !ret; i += 0x100, j <<= 1) {
		if (!(j & mrmask))
			continue;

		secs = sgx_get_page(secs_page);
		epc = sgx_get_page(epc_page);

		ret = __eextend(secs, (void *)((unsigned long)epc + i));

		sgx_put_page(epc);
		sgx_put_page(secs);
	}

	return ret;
}

static int sgx_add_page(struct sgx_epc_page *secs_page,
			struct sgx_epc_page *epc_page,
			unsigned long linaddr,
			struct sgx_secinfo *secinfo,
			struct page *backing)
{
	struct sgx_page_info pginfo;
	void *epc_page_vaddr;
	int ret;

	pginfo.srcpge = (unsigned long)kmap_atomic(backing);
	pginfo.secs = (unsigned long)sgx_get_page(secs_page);
	epc_page_vaddr = sgx_get_page(epc_page);

	pginfo.linaddr = linaddr;
	pginfo.secinfo = (unsigned long)secinfo;
	ret = __eadd(&pginfo, epc_page_vaddr);

	sgx_put_page(epc_page_vaddr);
	sgx_put_page((void *)(unsigned long)pginfo.secs);
	kunmap_atomic((void *)(unsigned long)pginfo.srcpge);

	return ret;
}

static bool sgx_process_add_page_req(struct sgx_add_page_req *req)
{
	struct page *backing;
	struct sgx_epc_page *epc_page;
	struct sgx_encl_page *encl_page = req->encl_page;
	struct sgx_encl *encl = req->encl;
	struct vm_area_struct *vma;
	int ret;

	epc_page = sgx_alloc_page(0);
	if (IS_ERR(epc_page))
		return false;

	down_read(&encl->mm->mmap_sem);

	mutex_lock(&encl->lock);

	if (encl->flags & SGX_ENCL_DEAD)
		goto out;

	if (sgx_find_encl(encl->mm, encl_page->addr, &vma))
		goto out;

	backing = sgx_get_backing(encl, encl_page, false);
	if (IS_ERR(backing))
		goto out;

	/* Do not race with do_exit() */
	if (!atomic_read(&encl->mm->mm_users)) {
		sgx_put_backing(backing, 0);
		goto out;
	}

	ret = vm_insert_pfn(vma, encl_page->addr, PFN_DOWN(epc_page->pa));
	if (ret)
		goto out;

	ret = sgx_add_page(encl->secs_page.epc_page, epc_page,
			   encl_page->addr, &req->secinfo, backing);

	sgx_put_backing(backing, 0);
	if (ret) {
		sgx_warn(encl, "EADD returned %d\n", ret);
		zap_vma_ptes(vma, encl_page->addr, PAGE_SIZE);
		goto out;
	}

	encl->secs_child_cnt++;

	ret = sgx_measure(encl->secs_page.epc_page, epc_page, req->mrmask);
	if (ret) {
		sgx_warn(encl, "EEXTEND returned %d\n", ret);
		zap_vma_ptes(vma, encl_page->addr, PAGE_SIZE);
		goto out;
	}

	encl_page->epc_page = epc_page;
	sgx_test_and_clear_young(encl_page, encl);
	list_add_tail(&encl_page->load_list, &encl->load_list);
	encl_page->flags |= SGX_ENCL_PAGE_ADDED;

	mutex_unlock(&encl->lock);
	up_read(&encl->mm->mmap_sem);
	return true;
out:
	sgx_free_page(epc_page, encl);
	mutex_unlock(&encl->lock);
	up_read(&encl->mm->mmap_sem);
	return false;
}

static void sgx_add_page_worker(struct work_struct *work)
{
	struct sgx_encl *encl;
	struct sgx_add_page_req *req;
	bool skip_rest = false;
	bool is_empty = false;

	encl = container_of(work, struct sgx_encl, add_page_work);

	do {
		schedule();

		if (encl->flags & SGX_ENCL_DEAD)
			skip_rest = true;

		mutex_lock(&encl->lock);
		req = list_first_entry(&encl->add_page_reqs,
				       struct sgx_add_page_req, list);
		list_del(&req->list);
		is_empty = list_empty(&encl->add_page_reqs);
		mutex_unlock(&encl->lock);

		if (!skip_rest) {
			if (!sgx_process_add_page_req(req)) {
				skip_rest = true;
				sgx_dbg(encl, "EADD failed 0x%p\n",
					(void *)req->encl_page->addr);
			}
		}

		kfree(req);
	} while (!kref_put(&encl->refcount, sgx_encl_release) &&
		 !is_empty);
}

static int sgx_validate_secs(const struct sgx_secs *secs)
{
	u32 needed_ssaframesize = 1;
	u32 tmp;
	int i;

	if (secs->flags & SGX_SECS_A_RESERVED_MASK)
		return -EINVAL;

	if (secs->flags & SGX_SECS_A_MODE64BIT) {
#ifdef CONFIG_X86_64
		if (secs->size > sgx_encl_size_max_64)
			return -EINVAL;
#else
		return -EINVAL;
#endif
	} else {
		/* On 64-bit architecture allow 32-bit encls only in
		 * the compatibility mode.
		 */
#ifdef CONFIG_X86_64
		if (!test_thread_flag(TIF_ADDR32))
			return -EINVAL;
#endif
		if (secs->size > sgx_encl_size_max_32)
			return -EINVAL;
	}

	if ((secs->xfrm & 0x3) != 0x3 || (secs->xfrm & ~sgx_xfrm_mask))
		return -EINVAL;

	/* Check that BNDREGS and BNDCSR are equal. */
	if (((secs->xfrm >> 3) & 1) != ((secs->xfrm >> 4) & 1))
		return -EINVAL;

	for (i = 2; i < 64; i++) {
		tmp = sgx_ssaframesize_tbl[i];
		if (((1 << i) & secs->xfrm) && (tmp > needed_ssaframesize))
			needed_ssaframesize = tmp;
	}

	if (!secs->ssaframesize || !needed_ssaframesize ||
	    needed_ssaframesize > secs->ssaframesize)
		return -EINVAL;

	/* Must be power of two  */
	if (secs->size == 0 || (secs->size & (secs->size - 1)) != 0)
		return -EINVAL;

	for (i = 0; i < SGX_SECS_RESERVED1_SIZE; i++)
		if (secs->reserved1[i])
			return -EINVAL;

	for (i = 0; i < SGX_SECS_RESERVED2_SIZE; i++)
		if (secs->reserved2[i])
			return -EINVAL;

	for (i = 0; i < SGX_SECS_RESERVED3_SIZE; i++)
		if (secs->reserved3[i])
			return -EINVAL;

	for (i = 0; i < SGX_SECS_RESERVED4_SIZE; i++)
		if (secs->reserved[i])
			return -EINVAL;

	return 0;
}

static int sgx_init_page(struct sgx_encl *encl,
			 struct sgx_encl_page *entry,
			 unsigned long addr,
			 struct sgx_epc_page **va_src,
			 bool already_locked)
{
	struct sgx_va_page *va_page;
	struct sgx_epc_page *epc_page = NULL;
	unsigned int va_offset = PAGE_SIZE;
	void *vaddr;
	int ret = 0;

	list_for_each_entry(va_page, &encl->va_pages, list) {
		va_offset = sgx_alloc_va_slot(va_page);
		if (va_offset < PAGE_SIZE)
			break;
	}

	if (va_offset == PAGE_SIZE) {
		va_page = kzalloc(sizeof(*va_page), GFP_KERNEL);
		if (!va_page)
			return -ENOMEM;

		if (va_src) {
			epc_page = *va_src;
			*va_src = NULL;
		} else {
			epc_page = sgx_alloc_page(0);
			if (IS_ERR(epc_page)) {
				kfree(va_page);
				return PTR_ERR(epc_page);
			}
		}

		vaddr = sgx_get_page(epc_page);
		if (!vaddr) {
			sgx_warn(encl, "kmap of a new VA page failed %d\n",
				 ret);
			sgx_free_page(epc_page, encl);
			kfree(va_page);
			return -EFAULT;
		}

		ret = __epa(vaddr);
		sgx_put_page(vaddr);

		if (ret) {
			sgx_warn(encl, "EPA returned %d\n", ret);
			sgx_free_page(epc_page, encl);
			kfree(va_page);
			return -EFAULT;
		}

		va_page->epc_page = epc_page;
		va_offset = sgx_alloc_va_slot(va_page);

		if (!already_locked)
			mutex_lock(&encl->lock);
		list_add(&va_page->list, &encl->va_pages);
		if (!already_locked)
			mutex_unlock(&encl->lock);
	}

	entry->va_page = va_page;
	entry->va_offset = va_offset;
	entry->addr = addr;

	return 0;
}

static void sgx_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
	struct sgx_encl *encl =
		container_of(mn, struct sgx_encl, mmu_notifier);

	mutex_lock(&encl->lock);
	encl->flags |= SGX_ENCL_DEAD;
	mutex_unlock(&encl->lock);
}

static const struct mmu_notifier_ops sgx_mmu_notifier_ops = {
	.release	= sgx_mmu_notifier_release,
};

/**
 * sgx_ioc_enclave_create - handler for SGX_IOC_ENCLAVE_CREATE
 * @filep:	open file to /dev/sgx
 * @cmd:	the command value
 * @arg:	pointer to the struct sgx_enclave_create
 *
 * Creates meta-data for an enclave and executes ENCLS(ECREATE)
 */
static long sgx_ioc_enclave_create(struct file *filep, unsigned int cmd,
				   unsigned long arg)
{
	struct sgx_enclave_create *createp = (struct sgx_enclave_create *)arg;
	unsigned long src = (unsigned long)createp->src;
	struct sgx_page_info pginfo;
	struct sgx_secinfo secinfo;
	struct sgx_encl *encl = NULL;
	struct sgx_secs *secs = NULL;
	struct sgx_epc_page *secs_epc;
	struct vm_area_struct *vma;
	void *secs_vaddr = NULL;
	struct file *backing;
	struct file *pcmd;
	long ret;

	secs = kzalloc(sizeof(*secs),  GFP_KERNEL);
	if (!secs)
		return -ENOMEM;

	ret = copy_from_user(secs, (void __user *)src, sizeof(*secs));
	if (ret) {
		kfree(secs);
		return ret;
	}

	if (sgx_validate_secs(secs)) {
		kfree(secs);
		return -EINVAL;
	}

	backing = shmem_file_setup("dev/sgx", secs->size + PAGE_SIZE,
				   VM_NORESERVE);
	if (IS_ERR(backing)) {
		ret = PTR_ERR(backing);
		goto out;
	}

	pcmd = shmem_file_setup("dev/sgx",
				(secs->size + PAGE_SIZE) >> 5,
				VM_NORESERVE);
	if (IS_ERR(pcmd)) {
		fput(backing);
		ret = PTR_ERR(pcmd);
		goto out;
	}

	encl = kzalloc(sizeof(*encl), GFP_KERNEL);
	if (!encl) {
		fput(backing);
		fput(pcmd);
		ret = -ENOMEM;
		goto out;
	}

	kref_init(&encl->refcount);
	INIT_LIST_HEAD(&encl->add_page_reqs);
	INIT_LIST_HEAD(&encl->va_pages);
	INIT_RADIX_TREE(&encl->page_tree, GFP_KERNEL);
	INIT_LIST_HEAD(&encl->load_list);
	INIT_LIST_HEAD(&encl->encl_list);
	mutex_init(&encl->lock);
	INIT_WORK(&encl->add_page_work, sgx_add_page_worker);

	encl->mm = current->mm;
	encl->base = secs->base;
	encl->size = secs->size;
	encl->backing = backing;
	encl->pcmd = pcmd;

	secs_epc = sgx_alloc_page(0);
	if (IS_ERR(secs_epc)) {
		ret = PTR_ERR(secs_epc);
		secs_epc = NULL;
		goto out;
	}

	encl->secs_page.epc_page = secs_epc;

	ret = sgx_add_to_tgid_ctx(encl);
	if (ret)
		goto out;

	ret = sgx_init_page(encl, &encl->secs_page,
			    encl->base + encl->size, NULL, false);
	if (ret)
		goto out;

	secs_vaddr = sgx_get_page(secs_epc);

	pginfo.srcpge = (unsigned long)secs;
	pginfo.linaddr = 0;
	pginfo.secinfo = (unsigned long)&secinfo;
	pginfo.secs = 0;
	memset(&secinfo, 0, sizeof(secinfo));
	ret = __ecreate((void *)&pginfo, secs_vaddr);

	sgx_put_page(secs_vaddr);

	if (ret) {
		sgx_dbg(encl, "ECREATE returned %ld\n", ret);
		ret = -EFAULT;
		goto out;
	}

	createp->src = (unsigned long)encl->base;

	if (secs->flags & SGX_SECS_A_DEBUG)
		encl->flags |= SGX_ENCL_DEBUG;


	encl->mmu_notifier.ops = &sgx_mmu_notifier_ops;
	ret = mmu_notifier_register(&encl->mmu_notifier, encl->mm);
	if (ret) {
		if (ret == -EINTR)
			ret = -ERESTARTSYS;
		encl->mmu_notifier.ops = NULL;
		goto out;
	}

	down_write(&current->mm->mmap_sem);
	vma = find_vma(current->mm, secs->base);
	if (!vma || vma->vm_ops != &sgx_vm_ops ||
	    vma->vm_start != secs->base ||
	    vma->vm_end != (secs->base + secs->size)) {
		ret = -EINVAL;
		up_write(&current->mm->mmap_sem);
		goto out;
	}
	vma->vm_private_data = encl;
	up_write(&current->mm->mmap_sem);

	mutex_lock(&sgx_tgid_ctx_mutex);
	list_add_tail(&encl->encl_list, &encl->tgid_ctx->encl_list);
	mutex_unlock(&sgx_tgid_ctx_mutex);

out:
	if (ret && encl)
		kref_put(&encl->refcount, sgx_encl_release);
	kfree(secs);
	return ret;
}

static int sgx_validate_secinfo(struct sgx_secinfo *secinfo)
{
	u64 perm = secinfo->flags & SGX_SECINFO_PERMISSION_MASK;
	u64 page_type = secinfo->flags & SGX_SECINFO_PAGE_TYPE_MASK;
	int i;

	if ((secinfo->flags & SGX_SECINFO_RESERVED_MASK) ||
	    ((perm & SGX_SECINFO_W) && !(perm & SGX_SECINFO_R)) ||
	    (page_type != SGX_SECINFO_TCS &&
	     page_type != SGX_SECINFO_REG))
		return -EINVAL;

	for (i = 0; i < sizeof(secinfo->reserved) / sizeof(u64); i++)
		if (secinfo->reserved[i])
			return -EINVAL;

	return 0;
}

static int sgx_validate_tcs(struct sgx_tcs *tcs)
{
	int i;

	/* If FLAGS is not zero, ECALL will fail. */
	if ((tcs->flags != 0) ||
	    (tcs->ossa & (PAGE_SIZE - 1)) ||
	    (tcs->ofsbase & (PAGE_SIZE - 1)) ||
	    (tcs->ogsbase & (PAGE_SIZE - 1)) ||
	    ((tcs->fslimit & 0xFFF) != 0xFFF) ||
	    ((tcs->gslimit & 0xFFF) != 0xFFF))
		return -EINVAL;

	for (i = 0; i < sizeof(tcs->reserved) / sizeof(u64); i++)
		if (tcs->reserved[i])
			return -EINVAL;

	return 0;
}

static int __encl_add_page(struct sgx_encl *encl,
			   struct sgx_encl_page *encl_page,
			   struct sgx_enclave_add_page *addp,
			   struct sgx_secinfo *secinfo)
{
	u64 page_type = secinfo->flags & SGX_SECINFO_PAGE_TYPE_MASK;
	unsigned long src = (unsigned long)addp->src;
	struct sgx_tcs *tcs;
	struct page *backing;
	struct sgx_add_page_req *req = NULL;
	int ret;
	int empty;
	void *user_vaddr;
	void *tmp_vaddr;
	struct page *tmp_page;

	tmp_page = alloc_page(GFP_HIGHUSER);
	if (!tmp_page)
		return -ENOMEM;

	tmp_vaddr = kmap(tmp_page);
	ret = copy_from_user((void *)tmp_vaddr, (void __user *)src, PAGE_SIZE);
	kunmap(tmp_page);
	if (ret) {
		__free_page(tmp_page);
		return -EFAULT;
	}

	if (sgx_validate_secinfo(secinfo)) {
		__free_page(tmp_page);
		return -EINVAL;
	}

	if (page_type == SGX_SECINFO_TCS) {
		tcs = (struct sgx_tcs *)kmap(tmp_page);
		ret = sgx_validate_tcs(tcs);
		kunmap(tmp_page);
		if (ret) {
			__free_page(tmp_page);
			return ret;
		}
	}

	ret = sgx_init_page(encl, encl_page, addp->addr, NULL, false);
	if (ret) {
		__free_page(tmp_page);
		return -EINVAL;
	}

	mutex_lock(&encl->lock);

	if (encl->flags & (SGX_ENCL_INITIALIZED | SGX_ENCL_DEAD)) {
		ret = -EINVAL;
		goto out;
	}

	if (radix_tree_lookup(&encl->page_tree, addp->addr >> PAGE_SHIFT)) {
		ret = -EEXIST;
		goto out;
	}

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out;
	}

	backing = sgx_get_backing(encl, encl_page, false);
	if (IS_ERR((void *)backing)) {
		ret = PTR_ERR((void *)backing);
		goto out;
	}

	ret = radix_tree_insert(&encl->page_tree, encl_page->addr >> PAGE_SHIFT,
				encl_page);
	if (ret) {
		sgx_put_backing(backing, false /* write */);
		goto out;
	}

	user_vaddr = kmap(backing);
	tmp_vaddr = kmap(tmp_page);
	memcpy(user_vaddr, tmp_vaddr, PAGE_SIZE);
	kunmap(backing);
	kunmap(tmp_page);

	if (page_type == SGX_SECINFO_TCS)
		encl_page->flags |= SGX_ENCL_PAGE_TCS;

	memcpy(&req->secinfo, secinfo, sizeof(*secinfo));

	req->encl = encl;
	req->encl_page = encl_page;
	req->mrmask = addp->mrmask;
	empty = list_empty(&encl->add_page_reqs);
	kref_get(&encl->refcount);
	list_add_tail(&req->list, &encl->add_page_reqs);
	if (empty)
		queue_work(sgx_add_page_wq, &encl->add_page_work);

	sgx_put_backing(backing, true /* write */);
out:

	if (ret) {
		kfree(req);
		sgx_free_va_slot(encl_page->va_page,
				 encl_page->va_offset);
	}

	mutex_unlock(&encl->lock);
	__free_page(tmp_page);
	return ret;
}

/**
 * sgx_ioc_enclave_add_page - handler for SGX_IOC_ENCLAVE_ADD_PAGE
 *
 * @filep:	open file to /dev/sgx
 * @cmd:	the command value
 * @arg:	pointer to the struct sgx_enclave_add_page
 *
 * Creates meta-data for an enclave page and enqueues ENCLS(EADD) that will
 * be processed by a worker thread later on.
 */
static long sgx_ioc_enclave_add_page(struct file *filep, unsigned int cmd,
				     unsigned long arg)
{
	struct sgx_enclave_add_page *addp = (void *)arg;
	unsigned long secinfop = (unsigned long)addp->secinfo;
	struct sgx_encl *encl;
	struct sgx_encl_page *page;
	struct sgx_secinfo secinfo;
	int ret;

	if (addp->addr & (PAGE_SIZE - 1))
		return -EINVAL;

	if (copy_from_user(&secinfo, (void __user *)secinfop, sizeof(secinfo)))
		return -EFAULT;

	ret = sgx_find_and_get_encl(addp->addr, &encl);
	if (ret)
		return ret;

	if (addp->addr < encl->base ||
	    addp->addr > (encl->base + encl->size - PAGE_SIZE)) {
		kref_put(&encl->refcount, sgx_encl_release);
		return -EINVAL;
	}

	page = kzalloc(sizeof(*page), GFP_KERNEL);
	if (!page) {
		kref_put(&encl->refcount, sgx_encl_release);
		return -ENOMEM;
	}

	ret = __encl_add_page(encl, page, addp, &secinfo);
	kref_put(&encl->refcount, sgx_encl_release);

	if (ret)
		kfree(page);

	return ret;
}

static int __sgx_encl_init(struct sgx_encl *encl, char *sigstruct,
			   struct sgx_einittoken *einittoken)
{
	int ret = SGX_UNMASKED_EVENT;
	struct sgx_epc_page *secs_epc = encl->secs_page.epc_page;
	void *secs_va = NULL;
	int i;
	int j;

	if (einittoken->valid && einittoken->isvsvnle < sgx_isvsvnle_min)
		return SGX_LE_ROLLBACK;

	for (i = 0; i < SGX_EINIT_SLEEP_COUNT; i++) {
		for (j = 0; j < SGX_EINIT_SPIN_COUNT; j++) {
			mutex_lock(&encl->lock);
			secs_va = sgx_get_page(secs_epc);
			ret = __einit(sigstruct, einittoken, secs_va);
			sgx_put_page(secs_va);
			mutex_unlock(&encl->lock);
			if (ret == SGX_UNMASKED_EVENT)
				continue;
			else
				break;
		}

		if (ret != SGX_UNMASKED_EVENT)
			goto out;

		msleep_interruptible(SGX_EINIT_SLEEP_TIME);
		if (signal_pending(current))
			return -ERESTARTSYS;
	}

out:
	if (ret) {
		sgx_dbg(encl, "EINIT returned %d\n", ret);
	} else {
		encl->flags |= SGX_ENCL_INITIALIZED;

		if (einittoken->isvsvnle > sgx_isvsvnle_min)
			sgx_isvsvnle_min = einittoken->isvsvnle;
	}

	return ret;
}

/**
 * sgx_ioc_enclave_init - handler for SGX_IOC_ENCLAVE_INIT
 *
 * @filep:	open file to /dev/sgx
 * @cmd:	the command value
 * @arg:	pointer to the struct sgx_enclave_init
 *
 * Flushes the remaining enqueued ENCLS(EADD) operations and executes
 * ENCLS(EINIT). Does a number of retries because EINIT might fail because of an
 * interrupt storm.
 */
static long sgx_ioc_enclave_init(struct file *filep, unsigned int cmd,
				 unsigned long arg)
{
	struct sgx_enclave_init *initp = (struct sgx_enclave_init *)arg;
	unsigned long sigstructp = (unsigned long)initp->sigstruct;
	unsigned long einittokenp = (unsigned long)initp->einittoken;
	unsigned long encl_id = initp->addr;
	char *sigstruct;
	struct sgx_einittoken *einittoken;
	struct sgx_encl *encl;
	struct page *initp_page;
	int ret;

	initp_page = alloc_page(GFP_HIGHUSER);
	if (!initp_page)
		return -ENOMEM;

	sigstruct = kmap(initp_page);
	einittoken = (struct sgx_einittoken *)
		((unsigned long)sigstruct + PAGE_SIZE / 2);

	ret = copy_from_user(sigstruct, (void __user *)sigstructp,
			     SIGSTRUCT_SIZE);
	if (ret)
		goto out_free_page;

	ret = copy_from_user(einittoken, (void __user *)einittokenp,
			     EINITTOKEN_SIZE);
	if (ret)
		goto out_free_page;

	ret = sgx_find_and_get_encl(encl_id, &encl);
	if (ret)
		goto out_free_page;

	mutex_lock(&encl->lock);
	if (encl->flags & SGX_ENCL_INITIALIZED) {
		ret = -EINVAL;
		mutex_unlock(&encl->lock);
		goto out;
	}
	mutex_unlock(&encl->lock);

	flush_work(&encl->add_page_work);

	ret = __sgx_encl_init(encl, sigstruct, einittoken);
out:
	kref_put(&encl->refcount, sgx_encl_release);
out_free_page:
	kunmap(initp_page);
	__free_page(initp_page);
	return ret;
}

/**
 * sgx_augment_encl() - adds a page to an enclave
 * @addr:	virtual address where the page should be added
 *
 * the address is checked against the dynamic ranges defined for
 * the enclave. If it matches one, a page is added at the
 * corresponding location
 *
 * Note: Invoking function must already hold the encl->lock
 */
struct sgx_encl_page *sgx_augment_encl(struct vm_area_struct *vma,
				       unsigned long addr,
				       bool write)
{
	struct sgx_page_info pginfo;
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

	if (encl->flags & SGX_ENCL_DEAD)
		goto out;

	/*
	if ((rg->rg_desc.flags & SGX_GROW_DOWN_FLAG) && !write)
		goto out;
	*/

	/* Start the augmenting process */
	ret = sgx_init_page(encl, encl_page, addr, &va_page, true);
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

		ret = sgx_eldu(encl, &encl->secs_page, secs_epc_page, true);
		if (ret)
			goto out;

		encl->secs_page.epc_page = secs_epc_page;
		encl->flags &= ~SGX_ENCL_SECS_EVICTED;

		/* Do not free */
		secs_epc_page = NULL;
	}

	secs_va = sgx_get_page(encl->secs_page.epc_page);
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

	ret = vm_insert_pfn(vma, encl_page->addr, PFN_DOWN(epc_page->pa));
	sgx_put_page(epc_va);
	sgx_put_page(secs_va);
	if (ret) {
		pr_err("sgx: vm_insert_pfn failure with ret=%d\n", ret);
		goto out;
	}

	encl_page->epc_page = epc_page;
	encl->secs_child_cnt++;

	ret = radix_tree_insert(&encl->page_tree, encl_page->addr >> PAGE_SHIFT,
			        encl_page);
	if (ret) {
		pr_err("sgx: radix_tree_insert failed with ret=%d\n", ret);
		goto out;
	}
	sgx_test_and_clear_young(encl_page, encl);

	list_add_tail(&encl_page->load_list, &encl->load_list);
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

	address = rg->start_addr;
	end = address + rg->nr_pages * PAGE_SIZE;

	vma = sgx_find_vma(encl, address);
	if (!vma)
		return -EINVAL;

	for (; address < end; address += PAGE_SIZE) {
		encl_page = ERR_PTR(-EBUSY);
		while (encl_page == ERR_PTR(-EBUSY))
			/* bring back page in case it was evicted */
			encl_page = sgx_fault_page(vma, address,
						   SGX_FAULT_RESERVE, NULL);

		if (IS_ERR(encl_page)) {
			sgx_err(encl, "sgx: No page found at address 0x%lx\n",
				 address);
			return PTR_ERR(encl_page);
		}

		/* We do not need the reserved bit anymore as page
		 * is removed from the load list
		 */
		mutex_lock(&encl->lock);
		list_move_tail(&encl_page->load_list, list);
		encl_page->flags &= ~SGX_ENCL_PAGE_RESERVED;
		mutex_unlock(&encl->lock);
	}

	return 0;
}

static int __modify_range(struct sgx_encl *encl,
			  struct sgx_range *rg, struct sgx_secinfo *secinfo)
{
	struct sgx_encl_page *encl_page, *tmp;
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
	list_for_each_entry_safe(encl_page, tmp, &list, load_list) {
		if (!emodt && (encl_page->flags & SGX_ENCL_PAGE_TCS)) {
			sgx_err(encl, "sgx: illegal request: page at\
				address=0x%lx is a TCS, req flags=0x%llx\n",
				encl_page->addr, secinfo->flags);
			ret = -EINVAL;
			continue;
		}
		mutex_lock(&encl->lock);
		epc_va = sgx_get_page(encl_page->epc_page);
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

static long modify_range(struct sgx_range *rg, unsigned long flags)
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

	ret = sgx_find_and_get_encl(rg->start_addr, &encl);
	if (ret) {
		pr_debug("sgx: No enclave found at start addr 0x%lx ret=%d\n",
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

long sgx_ioc_page_modpr(struct file *filep, unsigned int cmd,
			unsigned long arg)
{
	struct sgx_modification_param *p =
		(struct sgx_modification_param *) arg;

	/*
	 * Only RWX flags in mask are allowed
	 * Restricting WR w/o RD is not allowed
	 */
	if (p->flags & ~(SGX_SECINFO_R | SGX_SECINFO_W | SGX_SECINFO_X))
		return -EINVAL;
	if (!(p->flags & SGX_SECINFO_R) &&
	    (p->flags & SGX_SECINFO_W))
		return -EINVAL;
	return modify_range(&p->range, p->flags);
}

/**
 * sgx_ioc_page_to_tcs() - Pages defined in range are switched to TCS.
 * These pages should be of type REG.
 * eaccept need to be invoked after that.
 * @arg range address of pages to be switched
 */
long sgx_ioc_page_to_tcs(struct file *filep, unsigned int cmd,
			 unsigned long arg)
{
	return modify_range((struct sgx_range *)arg, SGX_SECINFO_TCS);
}

/**
 * sgx_ioc_trim_page() - Pages defined in range are being trimmed.
 * These pages still belong to the enclave and can not be removed until
 * eaccept has been invoked
 * @arg range address of pages to be trimmed
 */
long sgx_ioc_trim_page(struct file *filep, unsigned int cmd,
		       unsigned long arg)
{
	return modify_range((struct sgx_range *)arg, SGX_SECINFO_TRIM);
}

static int remove_page(struct sgx_encl *encl, unsigned long address,
		       bool trim)
{
	struct sgx_encl_page *encl_page;
	struct vm_area_struct *vma;
	struct sgx_va_page *va_page;

	vma = sgx_find_vma(encl, address);
	if (!vma)
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
		list_del(&encl_page->load_list);
		zap_vma_ptes(vma, encl_page->addr, PAGE_SIZE);
		sgx_free_page(encl_page->epc_page, encl);
		encl->secs_child_cnt--;
	}

	mutex_unlock(&encl->lock);

	kfree(encl_page);

	return 0;
}

/**
 * sgx_ioc_page_notify_accept() - Pages defined in range will be moved to
 * the trimmed list, i.e. they can be freely removed from now. These pages
 * should have PT_TRIM page type and should have been eaccepted priorly
 * @arg range address of pages
 */
long sgx_ioc_page_notify_accept(struct file *filep, unsigned int cmd,
				unsigned long arg)
{
	struct sgx_range *rg;
	unsigned long address, end;
	struct sgx_encl *encl;
	int ret, tmp_ret = 0;

	if (!sgx_has_sgx2)
		return -ENOSYS;

	rg = (struct sgx_range *)arg;

	address = rg->start_addr;
	address &= ~(PAGE_SIZE-1);
	end = address + rg->nr_pages * PAGE_SIZE;

	ret = sgx_find_and_get_encl(address, &encl);
	if (ret) {
		pr_debug("sgx: No enclave found at start address 0x%lx\n",
			address);
		return ret;
	}

	for (; address < end; address += PAGE_SIZE) {
		tmp_ret = remove_page(encl, address, true);
		if (tmp_ret) {
			sgx_dbg(encl, "sgx: remove failed, addr=0x%lx ret=%d\n",
				 address, tmp_ret);
			ret = tmp_ret;
			continue;
		}
	}

	kref_put(&encl->refcount, sgx_encl_release);

	return ret;
}



/**
 * sgx_ioc_page_remove() - Pages defined by address will be removed
 * @arg address of page
 */
long sgx_ioc_page_remove(struct file *filep, unsigned int cmd,
			 unsigned long arg)
{
	struct sgx_encl *encl;
	unsigned long address = *((unsigned long *) arg);
	int ret;

	if (!sgx_has_sgx2)
		return -ENOSYS;

	if (sgx_find_and_get_encl(address, &encl)) {
		pr_debug("sgx: No enclave found at start address 0x%lx\n",
			 address);
		return -EINVAL;
	}

	ret = remove_page(encl, address, false);
	if (ret) {
		pr_debug("sgx: Failed to remove page, address=0x%lx ret=%d\n",
			  address, ret);
	}

	kref_put(&encl->refcount, sgx_encl_release);
	return ret;
}

typedef long (*sgx_ioc_t)(struct file *filep, unsigned int cmd,
			  unsigned long arg);

long sgx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	char data[256];
	sgx_ioc_t handler = NULL;
	long ret;

	switch (cmd) {
	case SGX_IOC_ENCLAVE_CREATE:
		handler = sgx_ioc_enclave_create;
		break;
	case SGX_IOC_ENCLAVE_ADD_PAGE:
		handler = sgx_ioc_enclave_add_page;
		break;
	case SGX_IOC_ENCLAVE_INIT:
		handler = sgx_ioc_enclave_init;
		break;
	case SGX_IOC_ENCLAVE_EMODPR:
		handler = sgx_ioc_page_modpr;
		break;
	case SGX_IOC_ENCLAVE_MKTCS:
		handler = sgx_ioc_page_to_tcs;
		break;
	case SGX_IOC_ENCLAVE_TRIM:
		handler = sgx_ioc_trim_page;
		break;
	case SGX_IOC_ENCLAVE_NOTIFY_ACCEPT:
		handler = sgx_ioc_page_notify_accept;
		break;
	case SGX_IOC_ENCLAVE_PAGE_REMOVE:
		handler = sgx_ioc_page_remove;
		break;
	default:
		return -ENOIOCTLCMD;
	}

	if (copy_from_user(data, (void __user *)arg, _IOC_SIZE(cmd)))
		return -EFAULT;

	ret = handler(filep, cmd, (unsigned long)((void *)data));
	if (!ret && (cmd & IOC_OUT)) {
		if (copy_to_user((void __user *)arg, data, _IOC_SIZE(cmd)))
			return -EFAULT;
	}

	return ret;
}
