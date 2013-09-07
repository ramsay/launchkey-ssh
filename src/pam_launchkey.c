#include <stdio.h>
#include <syslog.h>

#define PAM_SM_ACCT

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	char **response;
	int rc;
	rc = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, response, "LaunchKey Username: ");
	
    if (*response == NULL) {
        rc = PAM_CONV_ERR;
    }

    if (rc != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_WARNING, "No response to query: %s", "LaunchKey Username");
    }
    pam_syslog(pamh, LOG_NOTICE, "%s %s", "LaunchKey Username", *response);
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}