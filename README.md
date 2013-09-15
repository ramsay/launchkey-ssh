launchkey-ssh
=============

SSH PAM

This is a PAM module for adding LaunchKey second factor authentication to
any Unix PAM capable service like SSH. 

This library contains a submodule (cJSON), after cloning you will need to also run:

    $ git submodule init
    $ git submodule update


To install, first create a LaunchKey app at https://dashboard.launchkey.com/my/newapp, and obtain the following:

	* App Key
	* Secret Key
	* Public Key
	* Private Key (Store this in a text file, such as private.key)

Next, install the dependencies:

    $ sudo apt-get install make libpam0g-dev libopenssl libcurl4-openssl-dev

Now build the LaunchKey shared PAM module, and add it to the security directory:

    $ make
    $ sudo mv pam_launchkey.so /lib/security/

Place your private.key file in a sensible location like /etc/launchkey/private.key. Then create a launchkey pam config file.

    $ sudo touch /etc/pam.d/launchkey

And add the following to it updating the last three arguments with your specific credentials.

    # /etc/pam.d/launchkey         App Key    Secret Key                        Path to Private Key
    auth required pam_launchkey.so 1543215647 cladfjekru39590dfjk3589034aerety  /etc/launchkey/private.key

Now you can add launchkey support to your /etc/pam.d/sshd, just after @include common-auth add the follwing lines:

    # LaunchKey 2-factor authentication
    @include launchkey

You may need to enable challenge-response to your sshd config, add or set:

    # /etc/ssh/sshd_config
    ChallengeResponseAuthentication yes

Now restart the ssh service on your host machine, and test. It should now prompt for your LaunchKey username after submitting your password.

    $ sudo service ssh restart
    $ ssh localhost
    Password: *********
    LaunchKey username: rramsay
    
    
