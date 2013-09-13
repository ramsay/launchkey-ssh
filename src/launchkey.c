#include <stdio.h>
#include "launchkey.h"
#include "cJSON.h"
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#define API_HOST "https://api.launchkey.com/v1"
#define MAX_BUFFER 500
#define TIMESTAMP_FORMAT "%Y-%m-%0d %H:%M:%S"

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;

	mem->memory = realloc(mem->memory, mem->size + realsize + 1);
	if(mem->memory == NULL) {
    /* out of memory! */ 
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

char* http_get(char* url)
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

 	/* get it! */ 
	res = curl_easy_perform(curl_handle);

 	/* check for errors */ 
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n",
			curl_easy_strerror(res));
	} else {
	    /*
	     * Now, our chunk.memory points to a memory block that is chunk.size
	     * bytes big and contains the remote file.
	     *
	     * Do something nice with it!
	     *
	     * You should be aware of the fact that at this point we might have an
	     * allocated data block, and nothing has yet deallocated that data. So when
	     * you're done with it, you should free() it as a nice application.
	     */ 

    	printf("%lu bytes retrieved\n", (long)chunk.size);
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

	curl_easy_setopt(curl_handle, CURLOPT_POST, true);

	void* post_data = (void*) malloc (sizeof(char)*MAX_BUFFER);
	char* formfield = (char*) malloc (sizeof(char)*100);
	cJSON* ptr = data;

	while (ptr->next != NULL) {
		sprintf(formfield, "%s=%s\n", ptr->string, ptr->valuestring);
		strcat((char*)post_data, formfield);
	}

	curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, post_data);
 	/* get it! */ 
	res = curl_easy_perform(curl_handle);

 	/* check for errors */ 
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n",
			curl_easy_strerror(res));
	} else {
	    /*
	     * Now, our chunk.memory points to a memory block that is chunk.size
	     * bytes big and contains the remote file.
	     *
	     * Do something nice with it!
	     *
	     * You should be aware of the fact that at this point we might have an
	     * allocated data block, and nothing has yet deallocated that data. So when
	     * you're done with it, you should free() it as a nice application.
	     */ 

    	printf("%lu bytes retrieved\n", (long)chunk.size);
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
	//int data_length = BIO_gets(mbio, data, 1024);
	int data_length = (int)BIO_ctrl(mbio, BIO_CTRL_INFO, 0, encoded);
	(*encoded)[data_length] = '\0';
	return data_length;
}

int b64decode(char* string, int length, char** decoded)
{
	BIO *bio, *mbio, *b64bio;
	mbio = BIO_new(BIO_s_mem());
	b64bio = BIO_new(BIO_f_base64());
	bio = BIO_push(b64bio, mbio);
	BIO_write(mbio, string, length);
	BIO_flush(bio);
	*decoded = (char *) malloc (sizeof(char)*strlen(string)*2);
	int dlength = BIO_read(bio, *decoded, strlen(string)*2);
	return dlength;
}

bool rsa_sign(EVP_PKEY* private_key, const char* data, char** signature)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_create();

    const EVP_MD* md = EVP_sha256();

    if (!EVP_SignInit(ctx, md)) {
        return false;
    }
    
    int data_len = strlen(data);
    
    if (!EVP_SignUpdate(ctx, data, data_len)) {
        return false;
    }

    unsigned int sig_len;

	char* raw_sig = malloc(EVP_PKEY_size(private_key));
    if (!EVP_SignFinal(ctx, (unsigned char *)raw_sig, &sig_len, private_key)) {
        return false;
    }

    sig_len = b64encode(raw_sig, sig_len, signature);
    return sig_len;
}

void encrypt_RSA(char* public_key_string, const char* message, char** encrypted)
{
	EVP_PKEY* public_key = parse_public_key(public_key_string);

	char* raw_crypt = (char *) malloc(EVP_PKEY_size(public_key));

	int len = RSA_public_encrypt(strlen(message), message, raw_crypt, public_key->pkey.rsa, RSA_PKCS1_OAEP_PADDING);
	
	b64encode(raw_crypt, len, encrypted);
}

void decrypt_RSA(char* private_key_string, const char* package, char** decrypted)
{
	EVP_PKEY* private_key = parse_private_key(private_key_string);

	int length, dlength;
	char* data;
	length = strlen(package);
	dlength = b64decode(package, length, &data);
	*decrypted = (char*) malloc(sizeof(char)*dlength);
	RSA_private_decrypt(dlength, data, *decrypted, private_key->pkey.rsa, RSA_PKCS1_OAEP_PADDING);
}

void sign_data(char* private_key_string, char* data, char** signature)
{
	EVP_PKEY* private_key = parse_private_key(private_key_string);
	rsa_sign(private_key, data, signature);
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
    	char* url = (char*) malloc (sizeof(char)*MAX_BUFFER);
    	strcpy(url, API_HOST);
    	strcat(url, "/ping/");
    	char* raw_data = http_get(url);
    	cJSON* data = cJSON_Parse(raw_data);
    	api->public_key = (char*) malloc (sizeof(char)*MAX_BUFFER);
    	strcpy(api->public_key, cJSON_GetObjectItem(data, "key")->valuestring);
    	api->ping_time = (struct tm*) malloc(sizeof(struct tm));
    	strptime(
    		cJSON_GetObjectItem(data, "launchkey_time")->valuestring, 
    		TIMESTAMP_FORMAT, 
    		api->ping_time
    		);
    	api->ping_difference = time(NULL);
    } else {
    	api->ping_time = time(NULL) - api->ping_difference + api->ping_time;
    }
}

void lk_pre_auth(api_data* api, char** encrypted_app_secret, char** signature)
{
    lk_ping(api);
    char* to_encrypt = (char*) malloc (sizeof(char)*MAX_BUFFER);
    char* timestamp = (char*) malloc (sizeof(char)*50);
    unsigned char* other;

    strftime(timestamp, 50, TIMESTAMP_FORMAT, api->ping_time);
    sprintf(to_encrypt, "{'secret': '%s', 'stamped': '%s'}", api->secret_key, timestamp);
    encrypt_RSA(api->public_key, to_encrypt, encrypted_app_secret);
    sign_data(api->private_key, *encrypted_app_secret, signature);
}

auth_request lk_authorize(api_data* api, const char* username) {
	auth_request request;
	char* secret_key;
	char* signature;
	char* session = "True";
	lk_pre_auth(api, &secret_key, &signature);
	cJSON* post_data = (cJSON*) malloc (sizeof(cJSON));
	cJSON_AddStringToObject(post_data, "app_key", api->app_key);
	cJSON_AddStringToObject(post_data, "secret_key", secret_key);
	cJSON_AddStringToObject(post_data, "signature", signature);
	cJSON_AddStringToObject(post_data, "username", username);
	cJSON_AddStringToObject(post_data, "session", session);

	char* raw_data = http_post(strcat(API_HOST, "/auths/"), post_data,  true);
	cJSON* data = cJSON_Parse(raw_data);
	request.auth_request = cJSON_GetObjectItem(data, "auth_request")->valuestring;
	return request;
}

auth_response lk_poll_request(api_data* api, auth_request request) {
	auth_response response;
	response.auth = "something";
	return response;
}

bool lk_is_authorized(api_data* api, auth_request request, char* auth) {
	return false;
}