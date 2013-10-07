#define _XOPEN_SOURCE
#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "launchkey.h"
#include "cJSON.h"

#define API_HOST "https://api.launchkey.com/v1"
#define MAX_POST 10000
#define MAX_BUFFER 500
#define TIMESTAMP_FORMAT "%Y-%m-%d %H:%M:%S"

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;

	mem->memory = realloc(mem->memory, mem->size + realsize + 1);
	if(mem->memory == NULL) {
    /* out of memory! */ 
		//fprintf(stderr, "not enough memory (realloc returned NULL)\n");
		return 0;
	}

	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

char* http_get(char* base_url, cJSON* data)
{
	CURL *curl_handle;
	char* url = (char *) malloc (1024);
	strcpy(url, base_url);
	CURLcode res;
 
	struct MemoryStruct chunk;

 	chunk.memory = malloc(1);
 	chunk.size = 0;

 	/* init the curl session */ 
	curl_handle = curl_easy_init();

	if (data) {
		char* param = (char *) malloc (512);
		cJSON* ptr = data->child;
		while (ptr) {
			if (ptr->prev == NULL) {
				sprintf(
					param, 
					"?%s=%s", 
					ptr->string, 
					curl_easy_escape(curl_handle, ptr->valuestring, 0)
				);
			} else {
				sprintf(
					param,
					"&%s=%s",
					ptr->string,
					curl_easy_escape(curl_handle, ptr->valuestring, 0)
				);
			}
			strcat(url, param);
			ptr = ptr->next;
		}
		free(param);
	}
 	/* specify URL to get */ 
	curl_easy_setopt(curl_handle, CURLOPT_URL, url);

 	/* send all data to this function  */ 
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

 	/* we pass our 'chunk' struct to the callback function */ 
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);

 	/* get it! */ 
	res = curl_easy_perform(curl_handle);

 	/* check for errors */ 
	if (res != CURLE_OK) {
		//fprintf(stderr, "curl_easy_perform() failed: %s\n",
		//	curl_easy_strerror(res));
	} else {
    	//printf("%lu bytes retrieved\n", (long)chunk.size);
	}
 
	/* cleanup curl stuff */ 
	curl_easy_cleanup(curl_handle);

	return chunk.memory;
}


char* http_post(char* url, cJSON* data, bool verify)
{
	CURL *curl_handle;
	CURLcode res;
 
	struct MemoryStruct chunk;

 	chunk.memory = malloc(1);
 	chunk.size = 0;

 	/* init the curl session */ 
	curl_handle = curl_easy_init();

 	/* specify URL to get */ 
	curl_easy_setopt(curl_handle, CURLOPT_URL, url);

 	/* send all data to this function  */ 
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

 	/* we pass our 'chunk' struct to the callback function */ 
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);

	struct curl_httppost* form = NULL;
	struct curl_httppost* last = NULL;
	cJSON* ptr = data->child;
	int err;

	while (ptr->next != NULL) {
		err = curl_formadd(
			&form, &last,
			CURLFORM_COPYNAME, ptr->string,
            CURLFORM_COPYCONTENTS, ptr->valuestring,
            CURLFORM_END
        );
        if (err != 0) {
        	//fprintf(stderr, "form add error: %d\n", err);
        }
		ptr = ptr->next;
	}

	curl_easy_setopt(curl_handle, CURLOPT_HTTPPOST, form);
 	/* get it! */ 
	res = curl_easy_perform(curl_handle);

 	/* check for errors */ 
	if (res != CURLE_OK) {
		//fprintf(stderr, "curl_easy_perform() failed: %s\n",
		//	curl_easy_strerror(res));
	} else {
    	//printf("%lu bytes retrieved\n", (long)chunk.size);
	}
 
	/* cleanup curl stuff */ 
	curl_easy_cleanup(curl_handle);

	return chunk.memory;
}

EVP_PKEY* parse_private_key(const char* string)
{
	BIO *mbio;
	mbio=BIO_new(BIO_s_mem());
	BIO_puts(mbio, string);
	
	return PEM_read_bio_PrivateKey(mbio, NULL, NULL, NULL);
}

void fix_public_key(char** string)
{
    char* buffer = (char *) malloc (strlen(*string));
	char* begin;
	char* end;
	begin = strstr(*string, "\n\n");
	end = strstr(begin+2, "\n\n");
	strcpy(buffer, "");
	if (begin && end) {
		strncat(buffer, *string, (begin+1) - *string);
		strncat(buffer, begin+2, end - (begin+2));
		strncat(buffer, end+1, strlen(end+1)+1);
	}
	strcpy(*string, buffer);
	free(buffer);
}

EVP_PKEY* parse_public_key(const char* string)
{
	BIO *mbio;
	mbio=BIO_new(BIO_s_mem());
	
	BIO_puts(mbio, string);

	return PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
}

int b64encode(char* string, int length, char** encoded)
{
	BIO *bio, *mbio, *b64bio;
	mbio = BIO_new(BIO_s_mem());
	b64bio = BIO_new(BIO_f_base64());
	bio = BIO_push(b64bio, mbio);
	BIO_write(bio, string, length);
	BIO_flush(bio);
	int data_length = (int)BIO_ctrl(mbio, BIO_CTRL_INFO, 0, encoded);
	(*encoded)[data_length] = '\0';
	return data_length;
}

int remove_backslashes(char** string, int max_size)
{
	char* buffer = (char *) malloc (max_size);
	char* p = *string;
	int i = 0;
	while (i < max_size) {
		if (*p =='\0') {
			buffer[i++] = *p;
			break;
		} else if (*p != '\\') {
			buffer[i++] = *p;
		}
		p++;
	}
	strncpy(*string, buffer, i);
	free(buffer);
	return i;
}

int b64decode(char* string, int length, char** decoded)
{
	BIO *bio, *mbio, *b64bio;
	mbio = BIO_new(BIO_s_mem());
	b64bio = BIO_new(BIO_f_base64());
	bio = BIO_push(b64bio, mbio);
	int iops = BIO_write(mbio, string, strlen(string));
	*decoded = (char *) malloc (strlen(string)*2);
	int dlength = BIO_read(b64bio, *decoded, strlen(string)*2);
	return dlength;
}

int encrypt_RSA(char* public_key_string, const char* message, char** encrypted)
{
	EVP_PKEY* public_key = parse_public_key(public_key_string);

	char* raw_crypt = (char *) malloc(EVP_PKEY_size(public_key));

	int len = RSA_public_encrypt(strlen(message), message, raw_crypt, public_key->pkey.rsa, RSA_PKCS1_OAEP_PADDING);
	
	return b64encode(raw_crypt, len, encrypted);
}

void decrypt_RSA(char* private_key_string, const char* package, char** decrypted)
{
	EVP_PKEY* private_key = parse_private_key(private_key_string);

	int length, dlength;
	char* mpackage;
	char* data;
	length = strlen(package);
	mpackage = (char *) malloc(length+1);
	strncpy(mpackage, package, length+1);
	dlength = b64decode(mpackage, length, &data);
	*decrypted = (char*) malloc(sizeof(char)*dlength);
	RSA_private_decrypt(dlength, data, *decrypted, private_key->pkey.rsa, RSA_PKCS1_OAEP_PADDING);
}

int sign_data(
	char* private_key_string, char* data, int data_length, char** signature
) {
	EVP_PKEY* private_key = parse_private_key(private_key_string);
	EVP_MD_CTX* ctx = EVP_MD_CTX_create();

    const EVP_MD* md = EVP_sha256();

    if (!EVP_SignInit(ctx, md)) {
        return 0;
    }
    
    char* decoded;
    int dlength = b64decode(data, data_length, &decoded);
    
    if (!EVP_SignUpdate(ctx, decoded, dlength)) {
        return 0;
    }

    unsigned int sig_len;

	char* raw_sig = malloc(EVP_PKEY_size(private_key));
    if (!EVP_SignFinal(ctx, (unsigned char *)raw_sig, &sig_len, private_key)) {
        return 0;
    }
    sig_len = b64encode(raw_sig, sig_len, signature);
    return sig_len;
}

bool verify_sign(char* public_key_string, char* signature, char* data)
{
	EVP_PKEY* public_key = parse_public_key(public_key_string);

    EVP_MD_CTX* ctx = EVP_MD_CTX_create();

    const EVP_MD* md = EVP_sha256();

    if (!EVP_VerifyInit(ctx, md)) {
        return false;
    }
    
    int data_len = strlen(data);
    
    if (!EVP_VerifyUpdate(ctx, data, data_len)) {
        return false;
    }

    unsigned int sig_len;
    char* raw_sig;
    sig_len = b64decode(signature, strlen(signature), &raw_sig);

	int ret = EVP_VerifyFinal(ctx, raw_sig, sig_len, public_key);
	if (ret <= 0) {
        return false;
	}
    return true;
}

void lk_ping(api_data* api)
{
    if (api->public_key == NULL || api->ping_time == NULL) {
    	char url[MAX_BUFFER];
    	strcpy(url, API_HOST);
    	strcat(url, "/ping/");
    	char* raw_data = http_get(url, NULL);
    	cJSON* data = cJSON_Parse(raw_data);
    	api->public_key = (char*) malloc (sizeof(char)*MAX_BUFFER);
    	strcpy(api->public_key, cJSON_GetObjectItem(data, "key")->valuestring);
    	fix_public_key(&(api->public_key));
    	api->ping_time = (struct tm*) malloc(sizeof(struct tm));
    	strptime(
    		cJSON_GetObjectItem(data, "launchkey_time")->valuestring, 
    		TIMESTAMP_FORMAT, 
    		api->ping_time
    	);
    	api->ping_difference = time(NULL);
    } else {
    	time_t now = time(NULL);
    	double diff = difftime(now, api->ping_difference);
    	time_t t = mktime(api->ping_time);
    	t += diff;
    	*api->ping_time = *localtime(&t);
    }
}

void lk_pre_auth(api_data* api, char** encrypted_app_secret, char** signature)
{
    lk_ping(api);
    char* to_encrypt = (char *) malloc (500);
    char timestamp[50];

    strftime(timestamp, 50, TIMESTAMP_FORMAT, api->ping_time);
    sprintf(to_encrypt, "{'secret': '%s', 'stamped': '%s'}", api->secret_key, timestamp);
    int encrypted_length = encrypt_RSA(api->public_key, to_encrypt, encrypted_app_secret);
    sign_data(api->private_key, *encrypted_app_secret, encrypted_length, signature);
}

auth_request lk_authorize(api_data* api, const char* username, bool session) {
	auth_request request;
	char* secret_key;
	char* signature;
	lk_pre_auth(api, &secret_key, &signature);
	cJSON* post_data = cJSON_CreateObject();
	cJSON_AddStringToObject(post_data, "app_key", api->app_key);
	cJSON_AddStringToObject(post_data, "secret_key", secret_key);
	cJSON_AddStringToObject(post_data, "signature", signature);
	cJSON_AddStringToObject(post_data, "username", username);
	if (session) {
		cJSON_AddTrueToObject(post_data, "session");
	} else {
		cJSON_AddFalseToObject(post_data, "session");
	}

	char* authorize_url = (char *) malloc (512);
	strcpy(authorize_url, API_HOST);
	strcat(authorize_url, "/auths/");
	char* raw_data = http_post(authorize_url, post_data,  true);
	cJSON* data = cJSON_Parse(raw_data);
	request.auth_request = cJSON_GetObjectItem(data, "auth_request")->valuestring;
	return request;
}

auth_response lk_poll_request(api_data* api, auth_request request) {
	auth_response response;
	char* secret_key;
	char* signature;
	lk_pre_auth(api, &secret_key, &signature);
	cJSON* params = cJSON_CreateObject();
	cJSON_AddStringToObject(params, "app_key", api->app_key);
	cJSON_AddStringToObject(params, "secret_key", secret_key);
	cJSON_AddStringToObject(params, "signature", signature);
	cJSON_AddStringToObject(params, "auth_request", request.auth_request);

	char* poll_url = (char *) malloc (512);
	strcpy(poll_url, API_HOST);
	strcat(poll_url, "/poll/");

	char* raw_data = http_get(poll_url, params);
	cJSON* data = cJSON_Parse(raw_data);
	cJSON* auth = cJSON_GetObjectItem(data, "auth");
	cJSON* user_hash = cJSON_GetObjectItem(data, "user_hash");
	if (auth) {
		response.auth = auth->valuestring;
	} else {
		response.auth = NULL;
	}
	if (user_hash) {
		response.user_hash = user_hash->valuestring;
	} else {
		response.user_hash = NULL;
	}
	free(poll_url);
	return response;
}

bool lk_is_authorized(api_data* api, auth_request request, char* auth) {
	if (!request.auth_request || !auth) {
		return false;
	}
	int length = remove_backslashes(&auth, 500);
	char * raw_data;
	decrypt_RSA(api->private_key, auth, &raw_data);
	cJSON* data = cJSON_Parse(raw_data);
	cJSON* response = cJSON_GetObjectItem(data, "response");
	cJSON* auth_request2 = cJSON_GetObjectItem(data, "auth_request");

	if (
		response &&
		(strcmp(response->valuestring, "true") == 0 ||
			strcmp(response->valuestring, "True") == 0) &&
		auth_request2 &&
		strcmp(request.auth_request, auth_request2->valuestring) == 0
	) {
		return true;
	}
	return false;
}
