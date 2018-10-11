import sys
import re
import os

def main(argv):
    if(len(argv) != 3):
        print("Invalid args!\nauthenticate.py [username] [password]")
        exit()

    username = argv[1]
    password = argv[2]

    # read the password file into a hashtable
    passTable = {}
    passFile = open(PWORD_FILENAME, 'r').read()

    while(passFile != ""):
        splitPass = passFile.split(':', 1)
        currentUsername = splitPass[0]
        currentHashedPass = splitPass[1][:HASH_SIZE_IN_BYTES]
        currentSalt = splitPass[1][HASH_SIZE_IN_BYTES+1:(HASH_SIZE_IN_BYTES*2)+1]
        passFile = splitPass[1][(HASH_SIZE_IN_BYTES*2)+2:]

        passTable[currentUsername] = (currentHashedPass,currentSalt)

        #print("name: " + currentUsername)
        #print("Pass: " + currentHashedPass)
        #print("Salt: " + currentSalt)
        #print("Remaining split pass: " + passFile)

    #print(passTable)

    if(username in passTable):
        if(passwordCorrect(username, password, passTable[username][0], passTable[username][1])):
            print("Accepted")
        else:
            print("Rejected - password does not match")
    else:
        print("Rejected - username not in file")



#tests if the password is correct
def passwordCorrect(username, password, storedHashPass, storedSalt):
    #hashPass = hashPass(password, storedSalt)
    #return hashPass == storedHashPass
    return password == storedHashPass



#def hashPass(password, salt):
#    return argon2.argon2_hash(password=password, salt=salt, buflen=HASH_SIZE_IN_BYTES, argon_type=argon2.Argon2Type.Argon2_i)
    
    

# constants and python main thing
WORDS_FILENAME = "words.txt"    #file containing list of password "words"
PWORD_FILENAME = "passwords.txt"    #file containing usernames and passwords
HASH_SIZE_IN_BYTES = 32

if __name__ == "__main__":
    main(sys.argv)