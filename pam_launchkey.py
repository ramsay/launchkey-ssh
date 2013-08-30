"""
Robert Ramsay <robert.alan.ramsay@gmail.com>
MIT License 2013
LaunchKey PAM module for use with SSH.

pam_python http://ace-host.stuart.id.au/russell/files/pam_python/

Install pam_python
add the following line to /etc/pam.d/sshd
account required pam_python.so /path/to/pam_launchkey.pam_python

"""
import launchkey
from time import sleep 
DEFAULT_USER    = "nobody"


def pam_sm_acct_mgmt(pamh, flags, argv):
    response = pamh.conversation(pamh.Message(0, "LaunchKey Username:"))
    username = response.resp
    if login(username):
        return pamh.PAM_SUCCESS
    return pamh.PAM_AUTH_ERROR


def login(username):
    app_key = 1301024551
    secret_key = open("secret_key", "r").read()
    private_key = open("private.key", "r").read() 
    api = launchkey.API(app_key, secret_key, private_key)

    auth_request = api.authorize(username)
    
    auth_response = {}

    while auth_response.get('auth') is None:
        sleep(5)
        auth_response = api.poll_request(auth_request)

    return api.is_authorized(auth_response['auth'])