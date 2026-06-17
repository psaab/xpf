# Hostile Plan Review: Issue #1944 — `system login user` encrypted-password

## Verdict: `PLAN-NEEDS-WORK`

The implementation direction (reusing `chpasswd -e`, closing the schema asymmetry for `authentication`, and introducing a typed-leaf validator) is structurally correct. However, the plan contains critical validation defects, security/reconciliation gaps, and test incompatibilities that must be resolved before proceeding to implementation.

---

## Findings

### 1. Validator Character Set Exclusion of `=` (High Risk: Operator Lockout)
* **Quoted Evidence (lines 214-216):**
  > `- Accept "$<id>$..." where <id> ∈ {"1","2a","2b","2y","5","6","y","gy","7"} and the remainder is non-empty and uses the crypt base64 alphabet ([./0-9A-Za-z$]), with at least one $ after the id (salt present).`

* **Analysis:** 
  Standard sha512crypt (`$6$`) and sha256crypt (`$5$`) hashes support a customized rounds parameter (e.g., `$6$rounds=10000$salt$hash`). The proposed character set regex `[./0-9A-Za-z$]` **does not include the `=` (equals sign) character**. As a result, any valid hash carrying custom rounds parameters will be rejected by the compiler validator, locking the operator out from committing their configuration.
* **Resolution:** 
  Update the allowed alphabet in the validator regex to explicitly include the `=` sign (e.g., `[./0-9A-Za-z$=]`).

---

### 2. Reconciliation Security Footgun on Password Removal (High Risk: Active Orphans)
* **Quoted Evidence (lines 273-277):**
  > `- **D1 leave the existing hash (do nothing) (RECOMMENDED for r1)**: matches today's non-removal behaviour for SSH keys/sudoers; least surprising; avoids accidentally locking out an admin mid-session. The operator removed the *config directive*, not necessarily the intent to keep the account usable.`

* **Analysis:** 
  Selecting D1 is a silent security vulnerability. In a declarative system, when an administrator removes the `encrypted-password` directive from a user, they expect password authentication for that user to be deactivated. Under D1, the password hash remains active in `/etc/shadow`, meaning the user can still log in on the serial console or via password-auth SSH using their old password.
* **Resolution:** 
  Reject D1. Adopt D2 (lock the password on removal) but implement it cleanly using the same `chpasswd -e` mechanism. If a user is present in the configuration but their `EncryptedPassword` is empty, write a locked sentinel to `/etc/shadow` (e.g., `echo "username:!" | chpasswd -e`).

---

### 3. Missing Support for Prepended `!` (Medium Risk: Locked Accounts)
* **Quoted Evidence (lines 218-219):**
  > `- Accept "*" and "!"/"!!" (explicitly-locked sentinels — Junos/operators may want a locked account; warn-not-reject is the alternative).`

* **Analysis:** 
  The proposed validator rules accept `!` and `!!` as standalone strings but do not allow a leading `!` or `!!` prepended to a valid crypt hash (e.g., `!$6$salt$hash`). Prepending `!` is the standard Unix way to disable/lock a password while retaining the original hash for future unlocking. Disallowing this prevents operators from committing standard locked/disabled hashes in the configuration.
* **Resolution:** 
  Modify the validator regex to accept an optional leading `!` or `!!` prepended to any recognized crypt format.

---

### 4. Incompatibility with Existing Root-Auth Test Dummy Hash (Low Risk: Build Break)
* **Quoted Evidence (lines 320-323):**
  > `(note: existing test uses "$6$abc123" which has **no salt separator** — the validator must accept it OR the test value must be updated to a well-formed $6$salt$hash; flag this in review as a compatibility decision).`

* **Analysis:** 
  If Path E1 (recommended) is selected to validate root authentication, `TestSystemConfigSetSyntax` in `pkg/config/parser_system_test.go` (which defines `set system root-authentication encrypted-password "$6$abc"`) will fail compile/commit validation because `"$6$abc"` lacks a salt separator. Relaxing the production validator to accept invalid hashes (which would lock out users in production if written to shadow) just to keep a dummy test value green is a bad compromise.
* **Resolution:** 
  Update the test fixture in `parser_system_test.go` to use a structurally valid crypt hash (e.g., `"$6$salt$hash"`) rather than weakening the validator code.

---

## Verdict Summary

The plan is close to ready but requires these 4 adjustments. No code has been modified. Re-review is recommended once the plan is updated to address the character set regex, the password removal reconciliation path, and the test fixture updates.
