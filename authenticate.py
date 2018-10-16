#---------------------------------------
# Author: Joel van Egmond
# ID: 10102094
#
# Purpose: Checks if the user/password combo entered exists in the database.
#   If so, prints "Accepted", else prints "Rejected"
#
# Usage: python3 authenticate.py [username] [password]
#
# Note: requires argon2 library from https://pypi.org/project/argon2/
#       must be run with python3
#       user/pass combos are stored in the format [username]:[hashed password]:[salt]
#---------------------------------------

import sys
import re
import os
import argon2   #from https://pypi.org/project/argon2/

def main(argv):
    if(len(argv) != 3):
        print("Invalid args!\nauthenticate.py [username] [password]")
        exit()

    username = argv[1]
    password = argv[2]

    # read the password file into a hashtable
    passTable = {}
    passFile = open(PWORD_FILENAME, 'r', encoding=PWORD_ENCODING).read()

    while(passFile != ""):
        splitPass = passFile.split(SEPARATOR_CHAR, 1)
        currentUsername = splitPass[0]
        currentHashedPass = splitPass[1][:HASH_SIZE_IN_BYTES]
        currentSalt = splitPass[1][HASH_SIZE_IN_BYTES+1:(HASH_SIZE_IN_BYTES*2)+1]
        passFile = splitPass[1][(HASH_SIZE_IN_BYTES*2)+2:]
        passTable[currentUsername] = (currentHashedPass,currentSalt)

    if(username in passTable):
        if(passwordCorrect(username, password, passTable[username][0], passTable[username][1])):
            print("Accepted")
        else:
            # Rejected - password does not match
            print("Rejected")
    else:
        # Rejected - username not in file
        print("Rejected")


#---------------------------------------
# Purpose: Tests if the password is correct by comparing the h(pass,salt) with the stored hash
# Inputs:
#   username - name of the user as string
#   password - user's password as string
#   storedHashPass - hash of password that is stored in the password file as string
#   storedSalt - salt corresponding to this user/password hash in the password file
# Output:
#   passwordCorrect - whether or not h(pass,salt) matches with the stored hash
#---------------------------------------
def passwordCorrect(username, password, storedHashPass, storedSalt):
    hashPass = hashPassword(password, storedSalt.encode(encoding=PWORD_ENCODING))

    return hashPass.decode(encoding=PWORD_ENCODING) == storedHashPass


#---------------------------------------
# Purpose: Uses argon2 to produce a hash from a given password and salt 
# Inputs:
#   password - password as a string
#   salt - a random salt as bytes
# Output:
#   argon2 hash - the password and salt hashed in argon2 slow mode (argon2_i), with a size of 32 bytes
#---------------------------------------
def hashPassword(password, salt):
    return argon2.argon2_hash(password=password, salt=salt, buflen=HASH_SIZE_IN_BYTES, argon_type=argon2.Argon2Type.Argon2_i)
    
    
# Constants
WORDS_FILENAME = "words.txt"        # file containing list of password "words"
PWORD_FILENAME = "passwords.txt"    # file containing usernames and passwords
HASH_SIZE_IN_BYTES = 32             # size of hash in bytes
PWORD_ENCODING = "latin-1"          # encoding of the password file
SEPARATOR_CHAR = ':'                # separator character in the password file

if __name__ == "__main__":
    main(sys.argv)