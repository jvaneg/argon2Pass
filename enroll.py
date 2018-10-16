#---------------------------------------
# Author: Joel van Egmond
# ID: 10102094
#
# Purpose: Adds the user to the password file if they have a valid (not already used) username,
#          and a valid password.
#          A password is invalid if it follows the format [word], [number], [wordnumber], or [numberword]
#          Where [word] comes from the words.txt file
#
# Usage: python3 entroll.py [username] [password]
#
# Note: requires argon2 library from https://pypi.org/project/argon2/
#       must be run with python3
#       doesn't allow usernames with ':' character in them (need a delimiter)
#       user/pass combos are stored in the format [username]:[hashed password]:[salt]
#---------------------------------------

import sys
import re
import os
import argon2   #from https://pypi.org/project/argon2/

def main(argv):
    if(len(argv) != 3):
        print("Invalid args!\nenroll.py [username] [password]")
        exit()

    username = argv[1]
    password = argv[2]

    if(usernameValid(username) and passwordValid(password)):
        addUser(username,password)
        print("Accepted")
    

#---------------------------------------
# Purpose: Checks if a username is valid.
#          A username is valid if it isn't already used, and it doesn't contain
#          a ':' character (used as a separator in the password file)
# Input:
#   username - the username entered by the user as a string
# Output:
#   whether or not the username is valid. true if so, false if not
#---------------------------------------
def usernameValid(username):
    valid = True

    if(SEPARATOR_CHAR in username):
        # Rejected - separator ':' in username
        print("Rejected")
        valid = False
    else:
        usernameList = set({})

        passFile = open(PWORD_FILENAME, 'r', encoding=PWORD_ENCODING).read()

        while(passFile != ""):
            splitPass = passFile.split(SEPARATOR_CHAR, 1)
            currentUsername = splitPass[0]
            passFile = splitPass[1][(HASH_SIZE_IN_BYTES*2)+2:]
            usernameList.add(currentUsername)

        if(username in usernameList):
            # Rejected - username already in use
            print("Rejected")
            valid = False

    return valid


#---------------------------------------
# Purpose: Checks if the password entered by the user is a valid.
#          A password is invalid if it follows the format [word], [number], [wordnumber], or [numberword]
#          Where [word] comes from the words.txt file
# Input:
#   password - the password entered by the user, as a string
# Output:
#   whether or not the password is valid. true if so, false if not
#---------------------------------------
def passwordValid(password):
    valid = True

    wordList = set(open(WORDS_FILENAME).read().split())

    if(password.isdigit()):
        # Rejected - password is [num]
        print("Rejected")
        valid = False
    elif(password in wordList):
        # Rejected - password is [word]
        print("Rejected")
        valid = False
    else:
        splitPassword = list(filter(None, re.split('(\d+)', password)))
        if(len(splitPassword) == 2):
            if((splitPassword[0] in wordList) and (splitPassword[1].isdigit())):
                # Rejected - password is [wordnum]
                print("Rejected")
                valid = False
            elif((splitPassword[0].isdigit()) and (splitPassword[1] in wordList)):
                # Rejected - password is [numword]
                print("Rejected")
                valid = False

    return valid


#adds a valid user to the file
#---------------------------------------
# Purpose: Adds a valid user/password combo to the password file.
#          Password is hashed together with a random salt using argon2,
#          and only the username, hash, and salt are stored in the password file.
#          and salt are stored in the password file.
#          
# Inputs:
#   username - the username chosen by the user, as a string
#   password - the password chosen by the user, as a string
# Output:
#   whether or not the password is valid. true if so, false if not
#---------------------------------------
def addUser(username, password):
    salt = os.urandom(HASH_SIZE_IN_BYTES)
    hashPass = hashPassword(password, salt)

    with open(PWORD_FILENAME, 'a', encoding=PWORD_ENCODING) as pwordFile:
        pwordFile.write(username + SEPARATOR_CHAR + hashPass.decode(encoding=PWORD_ENCODING) + SEPARATOR_CHAR + salt.decode(encoding=PWORD_ENCODING) + '\n') # could be any text, appended @ the end of file


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