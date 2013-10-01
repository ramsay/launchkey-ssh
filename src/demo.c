#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include "launchkey.h"
#define MAX_BUFFER 500

bool is_whitespace(char c) {
	return (c == ' ' || c == '\t' || c == '\r' || c == '\n');
}

bool readf(const char* filename, char** content, bool trim)
{
	FILE * file;
	long size;
 	size_t result;
 	file = fopen(filename, "r");

 	if (!file) {
 		return false;
 	}

 	fseek (file , 0 , SEEK_END);
 	size = ftell (file);
 	rewind (file);

	// allocate memory to contain the whole file:
	*content = (char*) malloc (sizeof(char)*size);
	if (*content == NULL) {
		fclose(file);
		return false;
	}

	result = fread(*content, 1, size, file);
	fclose(file);
	if (result != size) {
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



bool login(
	const char* app_key,
	const char* secret_key,
	const char* private_key_file,
	const char* username
) {
	api_data api;
	api.ping_time = NULL;
	api.app_key = (char *) malloc(strlen(app_key)+1);
	strcpy(api.app_key, app_key);
	api.secret_key = (char *) malloc(strlen(secret_key)+1);
	strcpy(api.secret_key, secret_key);
	readf(private_key_file, &api.private_key, true);
	curl_global_init(CURL_GLOBAL_ALL);
	auth_request request = lk_authorize(&api, username);
	auth_response response;
	response.auth = NULL;
	int count = 0;
	while (!lk_is_authorized(&api, request, response.auth)) {
		if (count > 6) {
			break;
		}
		sleep(5);
		count++;
		response = lk_poll_request(&api, request);
	}
	bool result = lk_is_authorized(&api, request, response.auth);
	curl_global_cleanup();
	return result;
}

int main(int argc, char* argv[]) {
	if (argc < 4) {
		printf("usage: demo app_key app_secret /path/to/private_key");
		return 1;
	}
	char* username = (char *) malloc (100);
	printf("Launchkey Username: ");
	scanf("%s", username);
	bool authenticated = login(argv[1], argv[2], argv[3], username);
	if (authenticated) {
		printf("You have been authenticated.\n");
	} else {
		printf("You have not been authenticated.\n");
	}
	return 0;
}
