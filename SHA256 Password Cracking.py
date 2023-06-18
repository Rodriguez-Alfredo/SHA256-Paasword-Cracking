from pwn import *

import sys

#parameter in the command line
if len(sys.argv) != 2:
    
    #print invalid if it does not eauql 2
    print('invalid arguments!')

    #show how to use the script
    print('>> {} <sha256sum>'.format(sys.argv[0]))
    
    #information not provided, script will end
    exit()

#assigned parameter to the variable
wanted_hash = sys.argv[1]

#assign text file 
password_file = '/usr/share/lists/wordlists/rockyou.txt'

#show attempts made
attempts = 0

#shows what is being cracked
with log.progress('Attempting to back: {}!\n'.format(wanted_hash)) as p:

    #open password file and specify encoding
    with open(password_file, 'r', encode = 'latin-1') as password_list:
        
        #looping through each word in rockyou.txt
        for password in password_list:
            
            #remove new lines from each word and encode
            password = password.strip('\n').encode('latin-1')

            #hash password
            password_hash = sha256sumhex(password)

            #show attempts, password 
            p.status('[{}] {} = {}'.format(attempts, password.decode('latin-1'), password_hash))

            
            if password_hash == wanted_hash:
                
                #output found password, attempts, and hash
                p.success('Password has found after {} attempts! {} hashes to {}!'.format(attempts, password.decode('latin-1'), password_hash))
                
                #found password, exit script
                exit()

            #increase attempt
            attempts += 1
        
        #attempt failed 
        p.failure('Password hash not found')
        