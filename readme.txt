Requirements:

-Requires argon2 library from https://pypi.org/project/argon2/
    - install with:
    pip3 install argon2
    OR
    pip3 install --user argon2

-Must be run with python3
    python3 authenticate.py [username] [password]
    python3 enroll.py [username] [password]

-Requires words.txt and passwords.txt files
    - words.txt contains common password words
    - passwords.txt contains usernames and hashed passwords
    - if one of these files does not exist, and empty one will be created

-user/pass combos are stored in the format [username]:[hashed password]:[salt]
    - hashed passwords are stretched to 32 bytes
    - salts are 32 random bytes
