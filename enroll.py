import sys
import re
import os

def main(argv):
    if(len(argv) != 3):
        print("Invalid args!\nenroll.py [username] [password]")
        exit()

    username = argv[1]
    password = argv[2]

    if(usernameValid(username) and passwordValid(password)):
        addUser(username,password)
        print("Accepted")
    
    

#checks if a username is valid
def usernameValid(username):
    valid = True

    if(':' in username):
        print("Rejected - ':' in username")
        valid = False
    else:
        usernameList = set({})

        passFile = open(PWORD_FILENAME, 'r').read()

        while(passFile != ""):
            splitPass = passFile.split(':', 1)
            currentUsername = splitPass[0]
            passFile = splitPass[1][(HASH_SIZE_IN_BYTES*2)+2:]
            usernameList.add(currentUsername)

        #print(usernameList)
        if(username in usernameList):
            print("Rejected - username already in use")
            valid = False

    return valid



# checks if username is valid
# no longer used, SUCKS
def usernameValid_old(username):
    valid = True

    if(':' in username):
        print("Rejected - ':' in username")
        valid = False
    else:
        usernameList = set(line.split(':')[0] for line in open(PWORD_FILENAME))
        print(usernameList)
        if(username in usernameList):
            print("Rejected - username already in use")
            valid = False

    return valid



#checks if password is valid
def passwordValid(password):
    valid = True

    wordList = set(open(WORDS_FILENAME).read().split())

    if(password.isdigit()):
        print("Rejected - password is [num]")
        valid = False
    elif(password in wordList):
        print("Rejected - password is [word]")
        valid = False
    else:
        splitPassword = list(filter(None, re.split('(\d+)', password)))
        # print(splitPassword)
        if(len(splitPassword) == 2):
            if((splitPassword[0] in wordList) and (splitPassword[1].isdigit())):
                print("Rejected - password is [wordnum]")
                valid = False
            elif((splitPassword[0].isdigit()) and (splitPassword[1] in wordList)):
                print("Rejected - password is [numword]")
                valid = False

    return valid



#adds a valid user to the file
def addUser(username, password):

    salt = os.urandom(HASH_SIZE_IN_BYTES)
    #hashPass = hashPass(password, salt)
    #hashPass = os.urandom(HASH_SIZE_IN_BYTES)
    hashPass = "01234567890123456789012345678901"

    with open(PWORD_FILENAME, 'a') as pwordFile:
        pwordFile.write(username + ':' + hashPass + ":" + salt + '\n') # could be any text, appended @ the end of file



#def hashPass(password, salt):
#    return argon2.argon2_hash(password=password, salt=salt, buflen=HASH_SIZE_IN_BYTES, argon_type=argon2.Argon2Type.Argon2_i)
    
    
    
# constants and python main thing

WORDS_FILENAME = "words.txt"    #file containing list of password "words"
PWORD_FILENAME = "passwords.txt"    #file containing usernames and passwords
HASH_SIZE_IN_BYTES = 32

if __name__ == "__main__":
    main(sys.argv)