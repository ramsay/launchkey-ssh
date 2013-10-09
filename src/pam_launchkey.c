#include <stdio.h>
#include <syslog.h>

#define PAM_SM_ACCT

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

#include "launchkey.h"

bool is_whitespace(char c)
{
    return c == ' ' || c == '\n' || c == '\t';
}

bool readf(const char * filepath, char** content, bool trim)
{
    FILE* fp = fopen(filepath, "r");
    size_t file_length, result;
    if (!fp) {
        return false;
    }

    fseek(fp, 0, SEEK_END);
    file_length = ftell(fp);
    rewind(fp);
    
    if (file_length < 1) {
        fclose(fp);
        return false;
    }

    *content = (char *) malloc(file_length);
    if (!*content) {
        fclose(fp);
        return false;
    }
    result = fread(*content, 1, file_length, fp);
    fclose(fp);
    if (result != file_length) {
        return false;
    }
    (*content)[result] = '\0';
    if (trim) {
        int i;
        for (i = result-1; is_whitespace((*content)[i]); i--) {
            (*content)[i] = '\0';
        }
    }
    return true;
}

void get_user_hash(const char* username, char** user_hash)
{
    char* filepath = (char*)malloc(255);
    strcpy(filepath, "/etc/launchkey/");
    strcat(filepath, username);
    bool success = readf(filepath, user_hash, true);
    if (!success) {
        user_hash = NULL;
    }
}

bool set_user_hash(const char* username, char* user_hash)
{
    char* filepath = (char*) malloc (255);
    strcpy(filepath, "etc/launchkey/");
    strcat(filepath, username);
    FILE* fp = fopen(filepath, "w");
    if (fp == NULL) {
        fclose(fp);
        return false;
    }
    int size = fputs(user_hash, fp);
    fclose(fp);
    
    if (size < 1 && size != strlen(user_hash)) {
        return false;
    }

    return true;
}

/*****************************************************************************
 * lk_login - A synchronous full LaunchKey authentication method. It will 
 *     attempt to poll the authenticaiton request 6 times waiting 5 seconds
 *     before each.
 * 
 * @param char*  app_key          The LaunchKey application ID as a string.
 * @param char*  secret_key       The LaunchKey application secrete key as a
 *     string.
 * @param char*  private_key_file The full filepath to the LaunchKey app 
 *     private key.
 * @param char*  username         The username supplied by the authenticatee.
 *
 ****************************************************************************/
bool lk_login(
    pam_handle_t *pamh, 
    const char* app_key, 
    const char* secret_key, 
    const char* private_key_file,
    char* username
) {
    /**
     * Construct the LaunchKey API state object.
     */
    api_data api;
    api.ping_time = NULL;
    api.app_key = (char *) malloc (strlen(app_key)+1);
    strcpy(api.app_key, app_key);
    api.secret_key = (char *) malloc (strlen(secret_key)+1);
    strcpy(api.secret_key, secret_key);
    if (!readf(private_key_file, &api.private_key, false)) {
        pam_syslog(
            pamh, LOG_ERR, 
            "Error reading private key file: %s", private_key_file
        );
        return false;
    }
    //pam_syslog(pamh, LOG_NOTICE, "Loaded private_key: %s", api.private_key);
    
    /**
     * Initial authentication process
     */
    auth_request request = lk_authorize(&api, username, false);
    if (!request.auth_request) {
        pam_syslog(pamh, LOG_ERR, "Unable to authorize launchkey user.");
    }
    /**
     * Initialize auth_response to a null state.
     */
    auth_response response;
    response.auth = NULL;

    /**
     * Create a poll iteration counter.
     */
    int count = 0;
    while (response.auth == NULL) {
        /**
         * After 6 tries to get a proper authentication response, give up.
         */
        if (count > 6) {
            break;
            pam_syslog(pamh, LOG_WARNING, "Reached max attempts for launchkey poll.");
        }
        /**
         * Wait 5 seconds to allow for push notificaiton latency and
         * actuall user interaction.
         */
        sleep(5);
        
        count++;
        /**
         * Check for user response to our request, response may be unaffected.
         */
        response = lk_poll_request(&api, request);
    }

    /**
     * Capture the authorized state from the user response, if any.
     */
    bool result = lk_is_authorized(&api, request, response.auth);
    
    if (result) {
        /**
         * Store or Verify the user_hash
         */
        char* user_hash;
        const char* lusername;
        int retval = pam_get_user(pamh, &lusername, NULL);
        if (retval != PAM_SUCCESS) {
            pam_syslog(pamh, LOG_ERR, "%s", "Unable to get local username.");
            return false;
        }
        get_user_hash(lusername, &user_hash);
        if (user_hash == NULL) {
            pam_syslog(pamh, LOG_NOTICE, "No user hash for %s, creating.", lusername);
            set_user_hash(lusername, response.user_hash);
        } else if (strcmp(user_hash, response.user_hash) != 0) {
            pam_syslog(pamh, LOG_ERR, "User hash did not match: %s %s", user_hash, response.user_hash);
            return false;
        }
    }
    return result;
}

/*****************************************************************************
 * PAM authentication interface function.
 * This pulls in the configuration arguments, prompts for the launchkey
 * username and then passes them off to the synchronous lk_login.
 *
 * @param pam_handle_t *pamh  The PAM object used for all PAM API calls.
 * @param int          flags  The PAM flags, ignored currently.
 * @param int           argc  The count of arguments in the next parameter. We
 *     expect it to equal 3, else the module is improperly configured.
 * @param const char *  argv  The arguments set in the PAM configuration. We 
 *     expect to see the LaunchKey App Id, the LaunchKey App secret key, and
 *     the full file path to the LaunchKey App private key.
 * 
 * @return int                A PAM response code.
 ****************************************************************************/
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if (
        argc < 3 || // Not enough config arguments
        !strlen(argv[0]) || // App ID empty
        !strlen(argv[1]) || // App Secret Key empty
        !strlen(argv[2]) // App Private Key File path empty
    ) {
        return PAM_CRED_INSUFFICIENT; // Improperly configured.
    }

	char *response;
	int rc;
    response = (char *) malloc (120);
	rc = pam_prompt(
        pamh, PAM_PROMPT_ECHO_ON, &response, "LaunchKey Username: ");
	
    if (response == NULL) {
        rc = PAM_CONV_ERR;
    }

    if (rc != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_WARNING, "No response to query: %s", "LaunchKey Username");
        return rc;
    }
    pam_syslog(pamh, LOG_NOTICE, "%s %s", "LaunchKey Username", response);

    if (lk_login(pamh, argv[0], argv[1], argv[2], response)) {
        return PAM_SUCCESS;
    }
    return PAM_AUTH_ERR;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}