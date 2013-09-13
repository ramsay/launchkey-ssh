pam_launchkey.so: src/pam_launchkey.c
	gcc -fPIC -c src/pam_launchkey.c
	gcc -shared -o pam_launchkey.so pam_launchkey.o -lpam

demo: src/demo.c src/launchkey.c src/launchkey.h
	gcc -o demo -ggdb src/cJSON.c src/launchkey.c src/demo.c -lcurl -lcrypto

keys: src/launchkey.c src/launchkey.h src/keys.c
	gcc -o keys -ggdb src/cJSON.c src/launchkey.c src/keys.c -lcrypto -lcurl