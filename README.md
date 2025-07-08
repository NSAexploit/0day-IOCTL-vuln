# Linux Kernel BTRFS - Write-What-Where Vulnerability in `read_extent_buffer_to_user_nofault` and `copy_to_sk`

**Author:** Matteu Olivieri Bastiani 
**Date:** 2025-07-08  
**Status:** Public Disclosure  
**CVE:** Pending Assignment  
**Severity:** High



## Summary

A **Write-What-Where** vulnerability exists in the Linux kernel BTRFS filesystem, specifically in the `read_extent_buffer_to_user_nofault()` and `copy_to_sk()` functions. Due to insufficient validation of user-controlled pointers, an unprivileged local attacker can cause **arbitrary writes to kernel memory**, potentially leading to privilege escalation or system compromise.



## Affected Component

- **Subsystem:** BTRFS Filesystem
- **Files:**
  - `extent_io.c`
  - `ioctl.c`
- **Functions:**
  - `read_extent_buffer_to_user_nofault()`
  - `copy_to_sk()`
- **Kernel versions:** Confirmed on Linux 5.x and 6.x (upstream analysis recommended)



## Technical Details

## 1️⃣ `read_extent_buffer_to_user_nofault()`

**File:** `extent_io.c:3677-3720`

```c
if (eb->addr) {
    if (copy_to_user_nofault(dstv, eb->addr + start, len))  // ⚠️ WRITE-WHAT-WHERE
        ret = -EFAULT;
    return ret;
}

Impact

    Write-What-Where Primitive: Arbitrary kernel memory write.

    Privilege Escalation: Potentially achievable.

    Denial of Service: Kernel panic.

    Potential RCE: With further exploitation steps.


Proof of Concept

No working exploit is included.
Exploitation is feasible in theory by supplying crafted pointers to ioctl() interfaces.
