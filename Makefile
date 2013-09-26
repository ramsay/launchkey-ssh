pam_launchkey.so: cJSON.o launchkey.o src/pam_launchkey.c
	gcc -fPIC -c src/pam_launchkey.c
	gcc -shared -o pam_launchkey.so pam_launchkey.o launchkey.o cJSON.o -lm -lcurl -lcrypto -lpam

launchkey.o: src/launchkey.c src/launchkey.h
	gcc -fPIC -c src/launchkey.c

cJSON.o: src/cJSON.c
	gcc -fPIC -c src/cJSON.c

demo: cJSON.o launchkey.o src/demo.c
	gcc -o demo -ggdb -g -Wall cJSON.o launchkey.o src/demo.c -lm -lcurl -lcrypto

keys: src/launchkey.c src/launchkey.h src/keys.c
	gcc -o keys -ggdb src/cJSON.c src/launchkey.c src/keys.c -lcrypto -lcurl
