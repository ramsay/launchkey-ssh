"""
Robert Ramsay <robert.alan.ramsay@gmail.com>
MIT License 2013
LaunchKey PAM module for use with SSH.

pam_python http://ace-host.stuart.id.au/russell/files/pam_python/

Install pam_python
add the following line to /etc/pam.d/sshd
account required pam_python.so /path/to/pam_launchkey.pam_python

"""
import sys, os
root_dir = os.sep.join(__file__.split(os.sep)[:-1])
sys.path.append(root_dir + '/.env/lib/python2.7/site-packages/')
import launchkey
from time import sleep 
DEFAULT_USER    = "nobody"


def pam_sm_acct_mgmt(pamh, flags, argv):
    username = argv[1]
    if login(username):
        return pamh.PAM_SUCCESS
    return pamh.PAM_AUTH_ERR


def login(username):
    app_key = 1301024551
    secret_key = open(root_dir + "/secret.key", "r").read().strip()
    private_key = open(root_dir + "/private.key", "r").read()
    print >> sys.stderr, (app_key, secret_key, private_key) 
    api = launchkey.API(app_key, secret_key, private_key)

    auth_request = api.authorize(username)
    print >> sys.stderr, "auth_request: ", auth_request
    auth_response = {}
    retries = 0
    while auth_response.get('auth') is None:
        sleep(5)
        auth_response = api.poll_request(auth_request)
        print >> sys.stderr, (retries, auth_response)

    return api.is_authorized(auth_request, auth_response['auth'])

