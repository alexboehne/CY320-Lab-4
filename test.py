from operator import index

import bcrypt

def get_hashed_password(plain_text_password): # hashes password
    return bcrypt.hashpw(plain_text_password.encode('utf-8'), bcrypt.gensalt())

def check_password(plain_text_password, hashed_password): # checks password against stored
    return bcrypt.checkpw(plain_text_password, hashed_password)


a = " "
with open("secrets.txt", 'r') as f:
    a = (f.readline()[2:-1]).encode('utf-8')
    print(a)

why = input(" ")

print(check_password(why.encode('utf-8'), a))