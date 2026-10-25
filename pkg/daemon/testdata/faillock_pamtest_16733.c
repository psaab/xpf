/* faillock_pamtest_16733.c — #16733 PAM harness, two roles.
 *
 * Driver (default): pamtest16733 <pam-dir> <service> <user> <password>
 * Loads <pam-dir>/<service> via pam_start_confdir (Linux-PAM >= 1.4)
 * and prints SUCCESS or AUTH_ERR; exits 2 on harness errors so the
 * Go test can tell "PAM said no" from "harness broken". The PAM
 * ABI declarations below are the stable Linux-PAM ABI, declared
 * inline so the test builds without libpam-dev headers; only the
 * runtime -lpam is needed.
 *
 * Stub unix (-DSTUB_UNIX, built -shared as pam_unix.so): succeeds
 * iff the supplied password equals "correct<user>pw" (so root's is
 * "correctrootpw"). pam_faillock, pam_succeed_if, pam_deny and
 * pam_permit remain the host's real modules — only credential
 * verification is stubbed, because the host /etc/shadow is not the
 * system under test.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAM_SUCCESS 0
#define PAM_AUTH_ERR 7
#define PAM_BUF_ERR 5
#define PAM_CONV_ERR 19
#define PAM_PROMPT_ECHO_OFF 1
#define PAM_USER 2
#define PAM_AUTHTOK 6
struct pam_message { int msg_style; const char *msg; };
struct pam_response { char *resp; int resp_retcode; };
struct pam_conv {
    int (*conv)(int, const struct pam_message **, struct pam_response **, void *);
    void *appdata_ptr;
};
typedef struct pam_handle pam_handle_t;
extern int pam_start_confdir(const char *, const char *, const struct pam_conv *, const char *, pam_handle_t **);
extern int pam_authenticate(pam_handle_t *, int);
extern int pam_end(pam_handle_t *, int);
extern int pam_get_user(pam_handle_t *, const char **, const char *);
extern int pam_get_authtok(pam_handle_t *, int, const char **, const char *);

#ifndef STUB_UNIX

static int conv_fn(int num_msg, const struct pam_message **msg,
                   struct pam_response **resp, void *appdata_ptr) {
    const char *pw = (const char *)appdata_ptr;
    if (num_msg != 1 || msg[0]->msg_style != PAM_PROMPT_ECHO_OFF)
        return PAM_CONV_ERR;
    struct pam_response *r = calloc(1, sizeof(*r));
    if (!r) return PAM_BUF_ERR;
    r->resp = strdup(pw);
    *resp = r;
    return PAM_SUCCESS;
}

int main(int argc, char **argv) {
    if (argc != 5) { fprintf(stderr, "usage: %s dir service user pass\n", argv[0]); return 2; }
    struct pam_conv conv = { conv_fn, (void *)argv[4] };
    pam_handle_t *pamh = NULL;
    int rc = pam_start_confdir(argv[2], argv[3], &conv, argv[1], &pamh);
    if (rc != PAM_SUCCESS) { fprintf(stderr, "pam_start: %d\n", rc); return 2; }
    rc = pam_authenticate(pamh, 0);
    if (rc == PAM_SUCCESS) printf("SUCCESS\n");
    else if (rc == PAM_AUTH_ERR) printf("AUTH_ERR\n");
    else { fprintf(stderr, "pam_authenticate: %d\n", rc); pam_end(pamh, rc); return 2; }
    pam_end(pamh, PAM_SUCCESS);
    return 0;
}

#else /* STUB_UNIX */

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL, *tok = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) return PAM_AUTH_ERR;
    if (pam_get_authtok(pamh, PAM_AUTHTOK, &tok, NULL) != PAM_SUCCESS || !tok) return PAM_AUTH_ERR;
    /* pam_faillock only tallies users present in passwd. The test runs
     * as an unprivileged user whose own account IS present but the
     * synthetic root/alice accounts are not, so map the stack under
     * test onto real passwd entries: the driver is invoked with the
     * real passwd names (mappedUidUser args to the Go harness, which
     * substitutes root->host user, alice->nobody before calling, and
     * expects passwords correct<invoked-name>pw). This stub therefore
     * only sees real passwd users; faillock tallies them per PAM_USER.
     * Password rule: "correct<user>pw" for whatever PAM_USER is. */
    char want[64];
    snprintf(want, sizeof(want), "correct%spw", user);
    return strcmp(tok, want) == 0 ? PAM_SUCCESS : PAM_AUTH_ERR;
}
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_AUTH_ERR; }

#endif
