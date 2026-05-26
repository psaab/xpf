**Adversarial PLAN Review for #1165**

**Verdict: PLAN-KILL**

The drafter's empirical baseline holds up under direct scrutiny, and the issue's CPU-reality framing is factually incorrect for this binary. Shipping churn to appease a misdiagnosis of the compiled artifact is the exact #944 / #966 anti-pattern. Close the issue with the empirical writeup.

Here is the adversarial breakdown per the review contract:

### 1. Empirical Baseline & DCE Verification (CONFIRMED)
I audited the source code directly to verify the gating mechanism that leads to the DCE claims:
- **`afxdp/frame/mod.rs:375-400`**: `BUILD_FWD_DBG_COUNT` is explicitly gated inside `if cfg!(feature = "debug-log") { thread_local! { ... } }`.
- **`afxdp/bpf_map.rs:145-165`**: `HB_LOG_COUNT` is identically gated by `if cfg!(feature = "debug-log")`.
- **`afxdp/tx/dispatch.rs:390-415`**: `SEG_MISS_LOG` (at line 403) is inside the `count_forwarded_tcp_segmentation_miss_if_needed` branch but is *not* `cfg`-gated.
- **`filter/mod.rs:320-335`**: `PENDING_FILTER_COUNTER_RECORD` is conditionally compiled with `#[cfg(not(test))]` but is otherwise unconditional structural batching.

In a standard `cargo build --release` (which lacks the `debug-log` feature), the `cfg!(...)` guard evaluates to `false`. LLVM constant-folds the `if false` branch and completely eliminates the block via Dead Code Elimination (DCE). The `thread_local!` static, its initializer, and the heavy `eprintln!` formatting machinery are never emitted. The baseline claim that 10 out of 12 variables are ghosts in the release binary is correct.

### 2. CPU-Reality Framing (REFUTED)
The issue claims that accessing the `thread_local!` macro compiles down to hidden function calls involving `__tls_get_addr`. 
This is factually wrong for this binary. The issue author is describing the `general-dynamic` TLS model used in PIC shared libraries. This project builds a static executable that uses the **`initial-exec`** TLS model. In `initial-exec`, the linker allocates TLS slots statically relative to the thread pointer (`%fs` on x86_64). Accessing a thread local compiles down to a single instruction (e.g., `mov %fs:offset, %rax`). There are zero `__tls_get_addr` calls involved. The 14.8M pps hot path does not suffer from hidden function calls. 

### 3. `#[cold]` Outline Effectiveness (MARGINAL / NO-OP)
Does moving `SEG_MISS_LOG` to an out-of-line `#[cold]` helper actually improve the L1-i footprint? 
LLVM's basic block placement already sinks branches containing massive formatting machinery (`eprintln!`) to the tail of the function, far past the warm exit. While outlining the code into a separate function will technically reduce the `.text` size of `enqueue_pending_forwards` (15,161 B) by stripping the sunk block entirely, the *taken warm path* cache line footprint will be identical. The instruction cache does not load the cold tail. As the plan notes, if the shrinkage is under 64 B, the move is effectively noise.

### 4. Architectural Pattern (#944 / #966)
This is a textbook recurrence of the #944 / #966 pattern: a reviewer reads the source code, sees a heavy macro (`thread_local!`), incorrectly assumes a worst-case execution model (`general-dynamic` PIC overhead), and files a performance bug without profiling the actual release binary.

### Conclusion
The load-bearing claim of the plan is correct: the issue's premise is a hallucination of overhead that LLVM and the `initial-exec` TLS model have already mitigated. We do not ship "source code clarity" churn (Change 2) or marginal out-of-lining (Change 1) to validate incorrect bug reports. 

**PLAN-KILL.** Proceed with closing the issue using the empirical baseline writeup as the rationale.
