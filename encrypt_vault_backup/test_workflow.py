"""
The test:
1. Generates keys from the user's email and master password
2. Registers the user
3. Verifies the user's email
4. Encrypts a sample vault
5. Stores the encrypted vault
6. Retrieves the encrypted vault
7. Decrypts it
8. Confirms the recovered vault matches the original
"""

import uuid
import sqlite3

from client import (
    generate_keys,
    encrypt_vault,
    decrypt_vault,
    register,
    verify,
    store,
    retrieve
)

def test_workflow():
    #Create an example user for testing, with uniquely generated email each time
    email = f"workflow-{uuid.uuid4()}@testmail.com"
    master_password = "testpassword1@"
    try:


        #Generate keys: private key = sk, public key = pk, encryption key = ek
        sk, pk, ek = generate_keys(email=email, master_password=master_password)


        #Registration test
        response = register(email=email, public_key=pk)

        assert response.status_code == 200


        #Verifying user email
        response = verify(email=email)

        assert response.status_code == 200


        #Create Vault for user
        original_vault = {
            "google":{
                "user":"googleguy",
                "password":"googletestpw2#"
            },
            "Spotify":{
                "user":"MusicBro",
                "password":"Tuyuwithlove1@"
            }
        }

        #Encrypting vault => eVault
        eVault = encrypt_vault(vault=original_vault, encryption_key=ek)

        assert eVault != original_vault

        #Storing or updating user's vault
        response = store(email=email, encrypted_vault=eVault, private_key=sk)

        assert response.status_code == 200



        #Retrieval
        result = retrieve(email=email, private_key=sk)
        Retrieved_vault = result["vault"]
        assert Retrieved_vault == eVault


        #Decryption
        decrypted_vault = decrypt_vault(encrypted_vault=Retrieved_vault, encryption_key=ek)

        assert decrypted_vault == original_vault


        print("Test Workflow fully completed: Passed!")



    finally:
        #Deleting example user from vault database even if assertion raised
        conn = sqlite3.connect("vault.db")

        conn.execute(
            "DELETE FROM users WHERE email = ?",
            (email,)
        )
        conn.commit()
        conn.close()


