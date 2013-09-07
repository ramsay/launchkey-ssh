pam_launchkey.so: src/pam_launchkey.c
	gcc -fPIC -c src/pam_launchkey.c
	gcc -shared -o pam_launchkey.so pam_launchkey.o -lpam