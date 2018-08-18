from base64 import b64encode, b64decode
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random
from struct import *
from common import *
import hashlib


def generate_rsa_keys():
    random_generator = Random.new().read
    private_key = RSA.generate(4096, random_generator)
    public_key = private_key.publickey()
    return private_key, public_key

def load_privatekey(private_key_path):
    private_key = None
    with open(private_key_path) as pkey_file:
        private_key = RSA.importKey(pkey_file.read())
    return private_key

def get_public_key(private_key):
    return private_key.publickey()

def encrypt(public_key, plaintext):
    cipher = public_key.encrypt(plaintext, 32)[0]
    return cipher

def decrypt(private_key, cipher):
    plaintext = private_key.decrypt(cipher)
    return plaintext

def sign_data(private_key, data):
    '''
    param: private_key_loc Path to your private key
    param: package Data to be signed
    return: base64 encoded signature
    '''
    signer = PKCS1_v1_5.new(private_key)
    digest = SHA256.new()
    # It's being assumed the data is base64 encoded, so it's decoded before updating the digest
    digest.update(b64decode(data))
    sign = signer.sign(digest)

    signature = b64encode(sign)
    return signature

def verify_signature(public_key, data, signature):
    verifier = PKCS1_v1_5.new(public_key)
    digest = SHA256.new()

    # It's being assumed the data is base64 encoded, so it's decoded before updating the digest
    digest.update(b64decode(data))

    verified = verifier.verify(digest, b64decode(signature))
    return verified

def hash(data):
    # SHA1  for now...
    hash_object = hashlib.sha1(data)
    hex_dig = hash_object.hexdigest()
    return hex_dig

def pack_magic(message):
    message = pack('>i'+str(len(message))+'s', MAGIC, message)
    return message

def unpack_magic(message):
    magic = unpack('>i', message[:4])[0]
    message = unpack(str(len(message)-4)+'s', message[4:])[0]
    return magic, message

def pack_message(cipher_message, signature):
    message = pack('>i'+str(len(cipher_message))+'s', len(cipher_message), cipher_message)
    sig = pack('>i'+str(len(signature))+'s', len(signature), signature)
    return message+sig

def unpack_message(message):
    cipher_message = ""
    signature = ""

    cipher_message_length = unpack('>i', message[:4])[0]

    cipher_message = unpack(str(cipher_message_length)+'s', message[4:4+cipher_message_length])[0]
    signature_length = unpack('>i', message[4+cipher_message_length:4+cipher_message_length+4])[0]
    signature = unpack(str(signature_length)+'s', message[4+cipher_message_length+4:4+cipher_message_length+4+signature_length])[0]

    return cipher_message, signature

if __name__=="__main__":
    message = pack_message("AAAAA", "BBBBBBBBBBBBBBBBBBBB")
    print(message)
    a,b = unpack_message(message)
    print(a)
    print(b)
    # data = b64encode("This is the data")
    # private_key, public_key = generate_rsa_keys()
    #
    # signature = sign_data(private_key, data)
    #
    # is_verified = verify_signature(public_key, data, signature)
