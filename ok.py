from cryptography.fernet import Fernet

def generate_key():
    key=Fernet.generate_key()
    with open("secret.key","wb") as key_file:
        key_file.write(key)
        print("Key is generated")

def load_key():
    return open("secret.key").read()

def encrypt_message(message):
    key = load_key()
    encode_msg = message.encode()
    f = Fernet(key)
    encrypt_msg = f.encrypt(encode_msg)
    return encrypt_msg
    # print(encrypt_msg)

#

def decrypt_message(enc_msg):
    key = load_key()
    f = Fernet(key)
    dec_msg = f.decrypt(enc_msg)
    return dec_msg.decode()

# print(encrypt_message("I'm Derick"))

enc = encrypt_message("Hi There this is Derick")
print(enc)
dec = decrypt_message(enc)
print(dec)
