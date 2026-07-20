#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#include <security/pam_modules.h>

typedef int (*pam_module_function)(pam_handle_t *, int, int, const char **);

#define REQUIRE_PAM_SIGNATURE(name)                                      \
    _Static_assert(                                                      \
        __builtin_types_compatible_p(                                    \
            pam_module_function,                                         \
            __typeof__(&name)                                            \
        ),                                                               \
        #name " signature must match the system PAM module ABI"         \
    )

REQUIRE_PAM_SIGNATURE(pam_sm_authenticate);
REQUIRE_PAM_SIGNATURE(pam_sm_setcred);
REQUIRE_PAM_SIGNATURE(pam_sm_acct_mgmt);
REQUIRE_PAM_SIGNATURE(pam_sm_chauthtok);

static pam_module_function resolve(void *module, const char *name) {
    void *symbol = dlsym(module, name);
    if (symbol == NULL) {
        fprintf(stderr, "missing symbol %s: %s\n", name, dlerror());
        exit(1);
    }

    pam_module_function function = NULL;
    _Static_assert(
        sizeof(function) == sizeof(symbol),
        "function and data pointers must have the same representation"
    );
    memcpy(&function, &symbol, sizeof(function));
    return function;
}

static void require_ignore(
    pam_module_function function,
    const char *name,
    int argument_count
) {
    int result = function(NULL, 0, argument_count, NULL);
    if (result != PAM_IGNORE) {
        fprintf(stderr, "%s returned %d instead of PAM_IGNORE\n", name, result);
        exit(1);
    }
}

int main(int argument_count, const char **arguments) {
    if (argument_count != 2) {
        fprintf(stderr, "usage: pam_companion_smoke <pam_companion.so>\n");
        return 2;
    }

    void *module = dlopen(arguments[1], RTLD_NOW | RTLD_LOCAL);
    if (module == NULL) {
        fprintf(stderr, "could not load module: %s\n", dlerror());
        return 1;
    }

    pam_module_function authenticate = resolve(module, "pam_sm_authenticate");
    pam_module_function set_credentials = resolve(module, "pam_sm_setcred");
    pam_module_function account_management = resolve(module, "pam_sm_acct_mgmt");
    pam_module_function change_token = resolve(module, "pam_sm_chauthtok");

    require_ignore(authenticate, "pam_sm_authenticate", -1);
    require_ignore(set_credentials, "pam_sm_setcred", 0);
    require_ignore(account_management, "pam_sm_acct_mgmt", 0);
    require_ignore(change_token, "pam_sm_chauthtok", 0);

    if (dlclose(module) != 0) {
        fprintf(stderr, "could not unload module: %s\n", dlerror());
        return 1;
    }

    puts("PASS: release module loads and its C ABI returns PAM_IGNORE safely");
    return 0;
}
