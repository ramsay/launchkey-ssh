#include "launchkey.h"
#include "cJSON.h"
#define API_HOST "https://api.launchkey.com/v1"
 
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

void parse(char* string, node* data) {
	data = 
}

void* get(node* data, char* key, ...) {
	return 0;
}

void lk_ping(api_data* api) {
	/**
        import datetime
        if self.api_pub_key is None or self.ping_time is None:
            response = requests.get(self.API_HOST + "ping", verify=self.verify).json()
            self.api_pub_key = response['key']
            self.ping_time = datetime.datetime.strptime(response['launchkey_time'], "%Y-%m-%d %H:%M:%S")
            self.ping_difference = datetime.datetime.now()
        else:
            self.ping_time = datetime.datetime.now() - self.ping_difference + self.ping_time
            **/
    if (api->public_key == NULL || api->ping_time == NULL) {
    	char* url = API_HOST;
    	char* raw_data = http_get(strcat(url, "/ping/"));
    	node* data;

    	parse(raw_data, data);

    	api->ping_time = get(data, "launchkey_time");
    	api.ping_difference = 
    }
}

void lk_pre_auth(api_data* api) {
	/**
	def _prepare_auth(self):
        ''' Encrypts app_secret with RSA key and signs '''
        #Ping to get key and time
        self.ping()
        to_encrypt = {"secret": self.app_secret, "stamped": str(self.ping_time)}
        encrypted_app_secret = encrypt_RSA(self.api_pub_key, str(to_encrypt))
        signature = sign_data(self.private_key, encrypted_app_secret)
        return {'app_key': self.app_key, 'secret_key': encrypted_app_secret,
                'signature': signature}
                **/

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