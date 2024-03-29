#define HTTP_ONLY
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <curl/curl.h>
#include <openssl/evp.h>

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
	struct tm* ping_time;
	time_t ping_difference;
} api_data;

struct MemoryStruct {
	char *memory;
	size_t size;
};

EVP_PKEY* parse_private_key(const char*);

EVP_PKEY* parse_public_key(const char*);

int b64encode(char*, int, char**);

int b64decode(char*, int, char**);

int encrypt_RSA(char*, const char*, char**);

void decrypt_RSA(char*, const char*, char**);

int sign_data(char*, char*, int, char**);

bool verify_sign(char*, char*, char*);

auth_request lk_authorize(api_data*, const char*, bool);

auth_response lk_poll_request(api_data*, auth_request);

bool lk_is_authorized(api_data* api, auth_request, char*);
