# Yael Avioz, 207237421, Bar Shein, 316045285

import base64
import hashlib
import math


# Define a Node in a Merkle Tree
class Node:
    def __init__(self, data):
        self.left = None
        self.right = None
        self.parent = None
        self.data = data


# Define a Leaf in a Merkle Tree
class Leaf:
        def __init__(self, data):
        self.parent = None
        self.hash = hash_func(data)


# Returns the hax value of the hash SHA256 function
def hash_func (val):
    return sha256(val.encode()).hexdigest()


# input 1 - Add a leaf to the Merkle tree

# input 2 - Calculates the root value
def root_value(self):


# input 3 - Create Proof of Inclusion

# input 4 - Proof of Inclusion

# input 5 - Creat a key (using RSA algorithm)
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                            encryption_algorithm=serialization.NoEncryption()).decode()

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    return private_pem, public_pem

# input 6 - Create Signature
def create_signature()


# input 7 - Verify Signature
