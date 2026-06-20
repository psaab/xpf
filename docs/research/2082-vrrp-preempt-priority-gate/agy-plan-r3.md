# VRRP Preempt Priority Gate Research Plan Review (r3)

This document presents the adversarial review and validation of the proposed changes in the VRRP preempt priority gate research plan (revision r3).

---

## 1. Mechanical Cleanliness and Behavior Preservation of `stepBackup()` Seam

The proposed extraction of the `StateBackup` select block into `stepBackup(masterDownTimer, advertTimer *time.Timer) bool` is **mechanically clean and behavior-preserving**.

* **State Modification:** Any transitions out of `StateBackup` (e.g., to `StateMaster` on timeout or preemption) are executed via `vi.becomeMaster()`, which updates the internal state variable `vi.state`. On the next iteration of the outer `run()` loop, `vi.getState()` will correctly return `StateMaster`, routing the loop to the master state handler.
* **Timer Operations:** The timers `masterDownTimer` and `advertTimer` are passed by pointer, allowing `stepBackup` to stop and reset them synchronously. Since `stepBackup` runs on the same goroutine as the original loop, this introduces no new race conditions on the timers.
* **Loop Control:** Returning `false` on `vi.stopCh` selection ensures `run()` exits immediately, preserving the original shutdown behavior.

---

## 2. Genuinely Avoiding the Receiver Nil-Panic in Unit Tests

Yes, calling `stepBackup()` directly in the unit tests **genuinely and completely avoids the nil-`conn` receiver panic**.

* **Root Cause of Panic:** In the original `run()` loop, the preamble unconditionally spawns background receiver goroutines (`receiver()`, `receiverAfPacket()`, etc.) if initialization occurs in a test context. These receivers call `vi.conn.SetReadDeadline(...)` on a nil socket connection, causing a nil-pointer dereference in a background goroutine that crashes the test binary.
* **The Seam Solution:** Since the unit tests will call `stepBackup()` directly without invoking `run()`, the preamble is never executed. Consequently, no receiver goroutines are spawned, and `vi.conn` is never dereferenced.

---

## 3. Fail-Soft becomeMaster() Chain in Test Contexts

The `becomeMaster()` path is fully fail-soft and will **not panic** during a unit test:

1. **`addVIPs()`:** Uses `netlink.LinkByName(vi.cfg.Interface)`. In a test context where the interface does not exist, it fails soft, logs a warning, and returns early without panicking.
2. **`sendPacket()`:** Returns `nil` immediately if `vi.rawConn == nil`.
3. **`sendGARP()`:** Uses helper functions (`SendGratuitousARPBurst` and `SendARPProbe`) that log warnings on missing interfaces instead of panicking.
4. **`suppressGARP`:** Setting `vi.suppressGARP.Store(true)` in the test completely bypasses the asynchronous `sendGARP` execution path, preventing any background goroutine side-effects or warning log pollution.

---

## 4. Folding of the Refinements into r3

Revision r3 **correctly and fully folds** the two key refinements:

* **Lock Discipline:** §5 item 3 explicitly specifies using `vi.mu.RLock()` / `vi.mu.RUnlock()` instead of `Lock()` / `Unlock()` inside the gate helper to avoid blocking concurrent external readers like `Status()`.
* **Staleness Horizon:** §5 item 3 includes `cfg.AdvertiseInterval` in the snapshot variables under the read lock to correctly compute the `masterDownInterval` staleness horizon.

---

## 5. Potential Flaws or Gaps in the stepBackup Extraction

* **Timer Dereferences (Test Implementation Note):** Because `stepBackup` and `handleBackupRx` dereference the timer pointers (e.g., calling `masterDownTimer.Stop()` or `advertTimer.Reset()`), the unit test **must pass initialized, non-nil dummy timers** (e.g., `time.NewTimer(10 * time.Hour)`) to avoid a panic in the test code.
* **Deterministic Channel Selection:** To ensure the `preemptNowCh` branch is taken deterministically in tests, the test must make sure that `rxCh` is empty, `stopCh` is open/empty, and the dummy `masterDownTimer` has not fired. This is easily achieved by using a long-duration timer (e.g. `10 * time.Hour`).

---

## Verdict

### **PLAN-READY**

The proposed plan (r3) is mechanically sound, addresses the nil-panic blocker, enforces clean lock discipline, and is ready for implementation.
