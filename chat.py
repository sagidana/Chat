from base64 import b64decode, b64encode
from common import *
from core import *

import configparser
import argparse
import os


class Chat:
    def __init__(self, args):
        self.parse_config(args.global_config)

    def parse_config(self, config_path):

        config = configparser.ConfigParser()
        config.read(config_path)

        # self.private_key = load_privatekey(config["General"]["private_key_file"])
        self.public_keys_location = config["General"]["public_keys_location"]
        self.private_keys_location = config["General"]["private_keys_location"]

    def send_message(self, private_key_id, recipient_id, message):
        message = b64encode(message)
        private_key = self.__get_private_key(private_key_id)

        if not private_key:
            return None

        signature = sign_data(private_key, message)

        recipient_key = self.__get_recipient_key(recipient_id)
        message = pack_magic(message)
        cipher_message = encrypt(recipient_key, message)

        message = pack_message(cipher_message, signature)
        message = b64encode(message)
        return message

    def recv_message(self, message):
        message = b64decode(message)
        cipher_message, signature = unpack_message(message)

        private_key_id = None
        for private_key in self.__get_private_keys():
            message = decrypt(private_key, cipher_message)
            magic, message = unpack_magic(message)
            if magic == MAGIC:
                private_key_id = hash(private_key.exportKey())
                break

        if not private_key_id:
            return

        recipient_id = self.__get_recipient_from_message(message, signature)

        message = b64decode(message)
        return private_key_id, recipient_id, message

    def __get_recipient_from_message(self, message, signature):
        recipient_id = None
        for filename in os.listdir(self.public_keys_location):
            current_recipient_id = filename[:filename.find(".pkey")]
            full_path = os.path.join(self.public_keys_location, filename)

            recipient_key = None
            with open(full_path) as recipient_key_file:
                recipient_key = recipient_key_file.read()

            if not recipient_key:
                continue

            recipient_key = RSA.importKey(recipient_key)

            if verify_signature(recipient_key, message, signature):
                recipient_id = current_recipient_id
                break

        return recipient_id

    def __get_private_key(self, private_key_id):
        private_key = None
        for filename in os.listdir(self.private_keys_location):
            current_private_key_id = filename[:filename.find('.key')]

            if private_key_id == current_private_key_id:
                full_path = os.path.join(self.private_keys_location, filename)
                with open(full_path) as private_key_file:
                    private_key = private_key_file.read()
                    private_key = RSA.importKey(private_key)
                    break

        return private_key

    def __get_private_keys(self):
        private_keys = []
        for filename in os.listdir(self.private_keys_location):
            full_path = os.path.join(self.private_keys_location, filename)
            with open(full_path) as private_key_file:
                private_key = private_key_file.read()
                private_key = RSA.importKey(private_key)
                private_keys.append(private_key)

        return private_keys

    def __get_recipient_key(self, recipient_id):
        recipient_key = None
        for filename in os.listdir(self.public_keys_location):
            current_recipient_id = filename[:filename.find('.pkey')]

            if recipient_id == current_recipient_id:
                full_path = os.path.join(self.public_keys_location, filename)
                with open(full_path) as recipient_key_file:
                    recipient_key = recipient_key_file.read()
                    recipient_key = RSA.importKey(recipient_key)
                    break
        return recipient_key

    def list_private_keys(self):
        private_keys = []
        for filename in os.listdir(self.private_keys_location):
            private_keys.append(filename[:filename.find('.key')])

        if len(private_keys) == 0:
            print("Currently there is not any configured private keys.")
            return
        else:
            print("Currently configured private keys:")
            for key in private_keys:
                print("\t- {}".format(key))

    def list_recipients(self):
        recipients = []
        for filename in os.listdir(self.public_keys_location):
            if filename == "me.pkey":
                continue
            recipients.append(filename[:filename.find('.pkey')])

        if len(recipients) == 0:
            print("Currently there is not any configured recipients.")
            return
        else:
            print("Currently configured recipients:")
            for recipient in recipients:
                print("\t- {}".format(recipient))

    def insert_public_key(self, public_key_path):
        public_key = None

        with open(public_key_path) as pkey_file:
            public_key = RSA.importKey(pkey_file.read())

        if not public_key:
            return

        recipient_id = hash(public_key.exportKey())

        recipient_file_location = os.path.join(self.public_keys_location, "{}.pkey".format(recipient_id))
        with open(recipient_file_location, 'w') as recipient_file:
            recipient_file.write(public_key.exportKey())

    def insert_private_key(self, private_key_path):
        public_key = None

        with open(private_key_path) as pkey_file:
            private_key = RSA.importKey(pkey_file.read())

        if not private_key:
            return

        id = hash(private_key.exportKey())

        file_location = os.path.join(self.private_keys_location, "{}.key".format(id))
        with open(file_location, 'w') as f:
            f.write(private_key.exportKey())

    def generate_rsa_keys(self):
        return generate_rsa_keys()

def init():
    main_parser = argparse.ArgumentParser(description='Chat implementation.', usage="chat -r <recipient_pubkey> -m <message>.")
    main_parser.add_argument('--global-config', '-g', default="chat.conf", help='The config to use for global configuration.')
    main_parser.add_argument('--insert-public-key', '-ipbk', help='Insert public key using the public key file.')
    main_parser.add_argument('--insert-private-key', '-iprk', help='Insert private key using the private key file.')
    main_parser.add_argument('--list-recipients', '-lr', action='store_true', help='List the recipients in the system.')
    main_parser.add_argument('--list-private-keys', '-lpk', action='store_true', help='List the private keys in the system.')
    main_parser.add_argument('--send', '-s', action='store_true', help='Send message.')

    main_parser.add_argument('--private-key', '-pk', nargs="+", help='The private key id used to send this message.')
    main_parser.add_argument('--recipient', '-r', nargs="+", help='The public key id of the recipient to send this message to.')
    main_parser.add_argument('--message', '-m', nargs="+", help='The message to send.')
    main_parser.add_argument('--recv', '-rcv', action='store_true', help='Receive message.')
    main_parser.add_argument('--generate-rsa-keys', '-gk', action='store_true', help='Generate new rsa keys.')

    return main_parser.parse_args()

if __name__ == "__main__":
    args = init()
    chat = Chat(args)

    if args.list_recipients:
        chat.list_recipients()
        exit()
    elif args.list_private_keys:
        chat.list_private_keys()
        exit()
    elif args.generate_rsa_keys:
        private_key, public_key = chat.generate_rsa_keys()
        print("private_key:\n{}".format(private_key.exportKey()))
        print("public_key:\n{}".format(public_key.exportKey()))
        exit()
    elif args.insert_private_key:
        chat.insert_private_key(args.insert_private_key)
        exit()
    elif args.insert_public_key:
        chat.insert_public_key(args.insert_public_key)
        exit()
    elif args.send:
        if not args.private_key:
            print("No private-key provided.")
            exit()
        if not args.recipient:
            print("No recipient provided.")
            exit()
        elif not args.message:
            print("No message provided.")
            exit()
        for p in args.private_key:
            for r in args.recipient:
                for m in args.message:
                    encrypted_message = chat.send_message(p, r, m)
                    print("encrypted_message: {}".format(encrypted_message))
        exit()
    elif args.recv:
        if not args.message:
            print("No message provided.")
            exit()
        for i in range(len(args.message)):
            private_key, recipient, decrypted_message = chat.recv_message(args.message[i])
            print("private_key: {}".format(private_key))
            print("recipient: {}".format(recipient))
            print("decrypted_message: {}".format(decrypted_message))
            exit()
