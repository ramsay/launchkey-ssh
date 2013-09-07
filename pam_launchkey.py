"""
Robert Ramsay <robert.alan.ramsay@gmail.com>
MIT License 2013
LaunchKey PAM module for use with SSH.

pam_python http://ace-host.stuart.id.au/russell/files/pam_python/

Install pam_python
add the following line to /etc/pam.d/sshd
auth required pam_python.so /path/to/pam_launchkey.py

sshd_config:
ChallengeResponseAuthentication yes

"""
import sys
sys.path.append('/home/robert/workspace/ramsay/launchkey-ssh/.env/lib/python2.7/site-packages/')
import launchkey
from time import sleep 


def pam_sm_authenticate(pamh, flags, argv):
    response = pamh.conversation(message)
    message = pamh.Message(pamh.PAM_PROMPT_ECHO_ON, "LaunchKey username: ")
    try:
        response = pamh.conversation(message)
    except pamh.exception, exc:
        print exc
    else:
        username = response.resp
        pamh.Message(pamh.PAM_TEXT_INFO, "")
        if login(username):
            return pamh.PAM_SUCCESS
    return pamh.PAM_AUTH_ERR


def login(username):
    app_key = 1301024551
    secret_key = open("secret.key", "r").read().strip()
    private_key = open("private.key", "r").read()
    api = launchkey.API(app_key, secret_key, private_key)

    auth_request = api.authorize(username)
    auth_response = {}
    retries = 0
    while auth_response.get('auth') is None:
        sleep(5)
        auth_response = api.poll_request(auth_request)
        print >> sys.stderr, (retries, auth_response)

    return api.is_authorized(auth_request, auth_response['auth'])

if __name__ == '__main__':
    api = None
    print login('rramsay')

