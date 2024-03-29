all: pam_launchkey.so

pam_launchkey.so: cJSON.o launchkey.o src/pam_launchkey.c
	gcc -fPIC -c src/pam_launchkey.c
	gcc -shared -o pam_launchkey.so pam_launchkey.o launchkey.o cJSON.o -lm -lcurl -lcrypto -lpam

demo: cJSON.o launchkey.o src/demo.c
	gcc -o demo -ggdb -g -Wall cJSON.o launchkey.o src/demo.c -lm -lcurl -lcrypto

launchkey.o: src/launchkey.c src/launchkey.h
	gcc -fPIC -c src/launchkey.c

cJSON.o: src/cJSON.c
	gcc -fPIC -c src/cJSON.c

.PHONY: install clean all

install: pam_launchkey.so
	install -D pam_launchkey.so $(DESTDIR)/lib/security/pam_launchkey.so
	install -d $(DESTDIR)/etc/launchkey

clean:
	rm -f *.o *.so demo


