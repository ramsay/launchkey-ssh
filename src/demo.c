#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include "launchkey.h"
#define ROOT_DIR "/Users/rramsay/workspace/ramsay/launchkey-ssh"
#define MAX_BUFFER 500

bool is_whitespace(char c) {
	return (c == ' ' || c == '\t' || c == '\r' || c == '\n');
}

bool readf(char* filename, char** content, bool trim)
{
	FILE * file;
	char* filepath = (char*) malloc(sizeof(char)*MAX_BUFFER);
	long size;
 	size_t result;
 	strcpy(filepath, ROOT_DIR);
 	strcat(filepath, filename);
 	file = fopen(filepath, "r");
 	if (!file) {
 		return false;
 	}

 	fseek (file , 0 , SEEK_END);
 	size = ftell (file);
 	rewind (file);

	// allocate memory to contain the whole file:
	*content = (char*) malloc (sizeof(char)*size);
	if (*content == NULL) {
		return false;
	}

	result = fread(*content, 1, size, file);
	if (result != size) {
		return false;
	}
	(*content)[result] = '\0';
	if (trim) {
		int i;
		for (i = size-1; is_whitespace(*content[i]); i--) {
			*content[i] = '\0';
		}
	}
	fclose (file);
	return true;
}



bool login(const char* username)
{
	api_data api;
	api.app_key = "1301024551";
	readf("/secret.key", &api.secret_key, true);
	readf("/private.key", &api.private_key, false);

	curl_global_init(CURL_GLOBAL_ALL);
	auth_request request = lk_authorize(&api, username);
	auth_response response;
	response.auth = NULL;
	while (response.auth == NULL) {
		sleep(5);
		response = lk_poll_request(&api, request);
	}
	bool result = lk_is_authorized(&api, request, response.auth);
	curl_global_cleanup();
	return result;
}

int main(int argc, char* argv[]) {
	bool authenticated = login("rramsay");
	if (authenticated) {
		printf("You have been authenticated.\n");
	} else {
		printf("You have not been authenticated.\n");
	}
	return 0;
}
