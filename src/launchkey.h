#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <curl/curl.h>
#include <cJSON/cJSON.h>

typedef struct {
	/** autorize() response object **/
	char* auth_request;
} auth_request;

typedef struct {
	/** poll_request() response **/
	bool* successful;
	char* status_code;
	char* message;
	char* response;
	char* auth;
	char* user_hash;
} auth_response;

typedef struct {
	char* app_key;
	char* secret_key;
	char* private_key;
	char* public_key;
	long* ping_time;
	long ping_difference;
} api_data;

struct MemoryStruct {
	char *memory;
	size_t size;
};

void lk_pre_auth(api_data*);

auth_request lk_authorize(api_data*, const char*);

auth_response lk_poll_request(api_data*, auth_request);

bool lk_is_authorized(api_data* api, auth_request, char*);