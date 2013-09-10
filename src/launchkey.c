#include <stdio.h>
#include "launchkey.h"
#include "cJSON.h"
#include <openssl/pem.h>
#include <openssl/crypto.h>
#define API_HOST "https://api.launchkey.com/v1"
#define MAX_BUFFER 500
#define TIMESTAMP_FORMAT "%Y-%0m-%0d %0H:%0M:%0S"

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

void encrypt_RSA(char* encrypted, char* key, char* message)
{
	FILE* fp = fopen("/tmp/public_key", "w+");
	bool endl = false;
	for(;*key != '\0'; key++) {
		if (!endl || *key != '\n') {
			fputc(*key, fp);
		}
		endl = (*key == '\n');
	}
	rewind(fp);

	RSA* rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);

	encrypted = (char *) malloc (RSA_size(rsa));

	//int flen, unsigned char *from,
    //unsigned char *to, RSA *rsa, int padding
    int length = strlen(message);
	RSA_public_encrypt(length, message, encrypted, rsa, 4);
	
	RSA_free(rsa);
}

void sign_data(char* private_key, char* data)
{
	/**
    from Crypto.PublicKey import RSA
    from Crypto.Signature import PKCS1_v1_5
    from Crypto.Hash import SHA256
    from base64 import b64encode, b64decode
    rsakey = RSA.importKey(priv_key)
    signer = PKCS1_v1_5.new(rsakey)
    digest = SHA256.new()
    digest.update(b64decode(data))
    sign = signer.sign(digest)
    **/


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

void lk_pre_auth(api_data* api, char* encrypted_app_secret, char* signature)
{
    lk_ping(api);
    char* to_encrypt = (char*) malloc (sizeof(char)*MAX_BUFFER);
    char* timestamp = (char*) malloc (sizeof(char)*50);
    signature = (char*) malloc (sizeof(char)*MAX_BUFFER);

    strftime(timestamp, 50, TIMESTAMP_FORMAT, api->ping_time);
    sprintf(to_encrypt, "{'secret': '%s', 'stamped': '%s'}", api->secret_key, timestamp);
    encrypt_RSA(encrypted_app_secret, api->public_key, to_encrypt);
    sign_data(api->private_key, encrypted_app_secret);
}

auth_request lk_authorize(api_data* api, const char* username) {
	/**
	'''
        Used to send an authorization request for a specific username
        :param username: String. The LaunchKey username of the one authorizing
        :param session: Boolean. If keeping a session mark True; transactional mark False
        :return: String. The auth_request value for future reference.
        '''
        params = self._prepare_auth()
        params['username'] = username
        params['session'] = session
        response = requests.post(self.API_HOST + "auths", params=params, verify=self.verify)
        if 'status_code' in response.json() and response.json()['status_code'] >= 300:
            #Error response.json()['message_code']
            '''30421 - POST; Incorrect data for API call
            30422 - POST; Credentials incorrect for app and app secret
            30423 - POST; Error verifying app
            30424 - POST; No paired devices'''
            return "Error"
        return response.json()['auth_request']
        **/
	auth_request request;
	char* secret_key;
	char* signature;
	char* session = "True";
	lk_pre_auth(api, secret_key, signature);
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