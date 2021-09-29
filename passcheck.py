import hashlib
from collections import defaultdict
import requests
import getpass


"""
Return the number of hits for a given password
"""

# pwnedpasswords API URL
PWNEDURL = "https://api.pwnedpasswords.com/range/{}"


def get_passwd_digest_pwnd(passwd):
    """
    Check if a given password is in the compromised/reported list and
    return the number of hits, if it's compromised/reported.

    :param passwd: The password that we want to check
    :type passwd: str

    :return: The number of times a password is compromised/reported
    :rtype: int
    """

    sha1 = hashlib.sha1()
    sha1.update(passwd.encode())
    hex_digest = sha1.hexdigest().upper()

    hex_digest_f5 = hex_digest[:5]
    hex_digest_remaining = hex_digest[5:]

    r = requests.get(PWNEDURL.format(hex_digest_f5))

    leaked_passwd_freq = defaultdict(int)

    for passwd_freq in r.content.splitlines():
        pass_parts = passwd_freq.split(b":")
        passwd = pass_parts[0].decode()
        freq = pass_parts[1]
        leaked_passwd_freq[passwd] = int(freq)

    if hex_digest_remaining in leaked_passwd_freq:
        return leaked_passwd_freq[hex_digest_remaining]

    return 0


if __name__ == "__main__":

    password = getpass.getpass("Enter password:")

    number_hits = get_passwd_digest_pwnd(password)

    if number_hits > 0:
        print(
            "WARNING: Your password is compromised with {} hits in the compromised passwords database".format(
                number_hits
            )
        )
    else:
        print("Your password was not found in the compromised passwords database")
