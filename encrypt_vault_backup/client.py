"""
This is client-side script. It's main purpose is to allow users to create private, public and encryption keys through a master password,
handling the encryption and decryption mechanism, and the signature and request structuring mechanism in order to send an appriopriately structured
request to the server.

Functions include:
1. nonce_generator: for creatin one use numbers to avoid replaying requests
2. create_authentication_request: creates a structured authentication ready json request that can be sent to the server side for authentication
3. generate_keys: using email and master password to create a master key, which derives private and public key pairs, and exncryption key
4. encrypt_vault: uses a nonce and byte string vault, and encrypt the vault with the encryption key
5. decrypt_vault: takes in the merged encrypted vault with the nonce and encrypted vault, and decrypts the vault with the encryption key

Main request functions that sends request to the server side from the client side:
1. register: register the user's email
2. verify: verify the user's email
3. storing: creates the storing/ updating vault payload and generates the right request to send to the server for storing the encrypted vault
4. retrieve: creates the retrieval payload and generates the right request to send to the server for retrieving the encrypted vault

generate nonce
create pk and sk and ek
"""

import httpx

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json
import hashlib
import base64
import time


SERVER_URL = "http://127.0.0.1:8000"


###=================###
### Functions below ###
###=================###

###--- nonce generator
def nonce_generator():
    return time.time_ns()



###---This function takes the user's email, payload_data, private key and returns a structured request ready to be sent to the server for authentication
def create_authentication_request(email, payload_data, private_key):

    #Turn payload data into a json with consistent format, encodes payload data into bytes and turn it into base64
    payload_json = json.dumps(
        payload_data,
        sort_keys=True,
        separators=(",", ":")
    ).encode()

    payload = base64.b64encode(payload_json).decode()


    #Create nonce
    nonce = nonce_generator()


    #Structure the message for signing, including essential info like email, payload and nonce
    message = json.dumps(
        {
            "email": email,
            "payload": payload,
            "nonce": nonce
        },
        sort_keys=True,
        separators=(",", ":")
    ).encode()


    #Sign using private key and turn signature into base64
    signature_bytes = private_key.sign(message)

    signature = base64.b64encode(signature_bytes).decode()


    #finally structure the response with the message and the signature, which is then sent to the server for verifying and updating vault
    structured_request = {
            "email": email,
            "payload": payload,
            "nonce": nonce,
            "signature": signature
        }

    return structured_request



###--- This function is for using email and master password to create a master key, which derives private and public key pairs, and exncryption key
def generate_keys(email, master_password):

    #hash the email with SHA-256 and take the first 16 bytes to use as a deterministic salt.
    #this makes sure same email produces same salt , making a email-password pair uniquely creates a public and private key pair, and encryption key 
    #16 byte chosen because its sufficiently long enough and keeps salts consistent in length
    salt = hashlib.sha256(email.encode()).digest()[:16]

    #Use Argon2id as a password-based key derivation function. This creates the master key/ master seed
    #this function is deliberately computationally and memory expensive as a "memory-hard function", 
    #making it a greater attacker deterent
    master_seed = hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )
    # Derive separate 32 bytes for signing
    signing_seed = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"signing"
    ).derive(master_seed)

    # Derive separate 32 bytes for vault encryption
    encryption_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"encryption"
    ).derive(master_seed)

    #creating private and public key from argon2 signing_seed output
    private_key = Ed25519PrivateKey.from_private_bytes(signing_seed)
    public_key = private_key.public_key()

    #turn the public key into raw bytes, and convert into base64 for more compact and stored more easily
    public_bytes = public_key.public_bytes_raw()
    public_key_base64 = base64.b64encode(public_bytes).decode()

    return private_key, public_key_base64, encryption_key



###--- encryption and decryption mechansims are written with functions below

#the encryption uses a nonce and byte string vault, and encrypt the vault with the encryption key
#The nonce is ensure each encryption is unique 
def encrypt_vault(vault, encryption_key):
    aes = AESGCM(encryption_key)

    nonce = os.urandom(12)

    vault_bytes = json.dumps(vault).encode()

    #encrypt the vault bytes
    ciphertext = aes.encrypt(
        nonce,
        vault_bytes,
        None
    )

    #adding nonce to the encrypted vault so that it can be extracted for decryption
    encrypted_data = nonce + ciphertext

    return base64.b64encode(encrypted_data).decode()

#The decryption takes in the nonce and encrypted vault, and decrypts the vault with the encryption key
def decrypt_vault(encrypted_vault, encryption_key):
    encrypted_data = base64.b64decode(encrypted_vault)

    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    aes = AESGCM(encryption_key)

    vault_bytes = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return json.loads(vault_bytes.decode())



###=======================================================================================================================================###
###   All functions below create request to the server, including registering, verifying email, adding/storing vault, and retriving vault ###
###=======================================================================================================================================###
def register(email, public_key):
    response = httpx.post(
        f"{SERVER_URL}/register",
        json={
            "email": email,
            "public_key": public_key
        }
    )

    print("REGISTER:")
    print(response.status_code)
    print(response.json())
    return response



def verify(email):
    response = httpx.post(
        f"{SERVER_URL}/verify",
        json={
            "email": email
        }
    )

    print("VERIFY:")
    print(response.status_code)
    print(response.json())
    return response



def store(email, encrypted_vault, private_key):
    #payload data signalling it is to store/ add new data, therefore encrypted vault is added
    payload_data = {
        "type": "store",
        "vault": encrypted_vault
    }

    #Create a structured storing request ready to sent to the server
    request_data = create_authentication_request(email=email, payload_data=payload_data, private_key=private_key)

    #The structured storing request is then sent to the server for authenticating and updating vault
    response = httpx.post(
        f"{SERVER_URL}/store",
        json = request_data
    )

    print("STORE:")
    print(response.status_code)
    print(response.json())
    return response



def retrieve(email, private_key):
    #payload data signalling it is to retrieve data only
    payload_data = {
        "type": "retrieve"
    }

    #Create a structured retrieval request ready to sent to the server
    request_data = create_authentication_request(email=email, payload_data=payload_data, private_key=private_key)


    #The structured retrieval request is then sent to the server for authenticating and retrieving encrypted vault vault
    response = httpx.post(
        f"{SERVER_URL}/retrieve",
        json = request_data
    )

    print("RETRIEVE:")
    print(response.status_code)
    print(response.json())

    return response.json()






###--- Demonstration of the application below:
# It simulates a scenario where Bob regisiters, verifies his email. Then he encrypts and store his encrypted vault
# before retrieving then decrypting his vault
if __name__ == "__main__":
    #Bob's private information
    email = "bob@example.com"
    password = "ReallyGreatpassword1@"


    #key generate
    sk, pk, ek = generate_keys(email=email,master_password=password)


    #register and verify
    register(email, pk)
    print("Registration sucessful!\n")


    verify(email)
    print("Bob's Email verified!\n")


    #Bob's Vault
    vault= {
        "google": {
            "username": "bobby",
            "password": "testpassword"
        },
        "Twtich":{
            "username":"SeaDawg",
            "password":"Bakeryman"
        },
        "BA": {
            "username":"player",
            "password":"Teacher1@"
        }
    }

    #encryption
    eVault = encrypt_vault(vault=vault, encryption_key=ek)
    print(f"Bob's Vault:\n{vault}")
    print(f"encrpyted vault:\n{eVault}\n")


    #Storing or updating  
    store(email=email,encrypted_vault=eVault,private_key= sk)
    print("Successfully stored Bob's encrypted vault!\n")


    #retrieval
    result = retrieve(email = email, private_key= sk)
    Retrieved_vault = result["vault"]
    print(f"Retrieved Bob's encrypted vault:\n{Retrieved_vault}\n")

    
    #decryption
    print("Decrypting Bob's retireved vault:")
    the_vault = decrypt_vault(encrypted_vault=Retrieved_vault, encryption_key=ek)
    print(f"The final vault: \n{the_vault}")




