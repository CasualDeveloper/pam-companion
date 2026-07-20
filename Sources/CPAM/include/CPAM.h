#ifndef PAM_COMPANION_CPAM_H
#define PAM_COMPANION_CPAM_H

#include <stdint.h>
#include <security/pam_constants.h>

static inline int32_t pam_companion_pam_success(void) {
    return PAM_SUCCESS;
}

static inline int32_t pam_companion_pam_auth_err(void) {
    return PAM_AUTH_ERR;
}

static inline int32_t pam_companion_pam_ignore(void) {
    return PAM_IGNORE;
}

static inline int32_t pam_companion_pam_silent(void) {
    return PAM_SILENT;
}

#endif
