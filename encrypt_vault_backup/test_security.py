"""
This script is for secuirty testing, including invalid signature, altered payload after signing, replay same signed request/nonce
The test is done with Pytest where a pytest fixture bob is created to create a baseline for testing each secuirty issue and deleted afterwards to
avoid filling up the vault database user table.
If the application successfully passed all the test, no assertion is raised and a confirmation message of passing the test should follow.

The functions include:
1. bob(): The pytest fixture for creating a baseline for all
2. test_invalid_signature: testing invalid signature by using alice's private key to sign bob's retrieval request
3. test_altered_request: testing altered signature by switching the payload with an invalid one
4. test_replayed_request: testing replayed request by sending another exact response after bob sent his

To implement test type 'pytest -s -v test_security.py' in the terminal after starting the server
"""


import pytest
import uuid
import httpx
import json
import base64
import time
import sqlite3

#import right functions to create invalid examples for testing
from client import generate_keys
SERVER_URL = "http://127.0.0.1:8000"

#Bob pytest fixture is created here to create a baseline for all test
#Bob's email is randomly generated, along with all his private key, public key and encryption key. He is then registered and has his email validated to
#create an appropriate example for testing
@pytest.fixture
def bob():
    #randomly generating bob's email and his corresponding keys
    email = f"bob-{uuid.uuid4()}@example.com"

    private_key, public_key, encryption_key = generate_keys(
        email,
        "bob-test-password"
    )

    #Bob's registration, and ensures it is always bob's first time registering
    response = httpx.post(
        f"{SERVER_URL}/register",
        json={
            "email": email,
            "public_key": public_key
        }
    )
    assert response.status_code == 200

    #Bob's email verification, and ensures it is always his first email verification
    response = httpx.post(
        f"{SERVER_URL}/verify",
        json={"email": email}
    )
    assert response.status_code == 200

    #Outputs for following tests
    yield {
        "email": email,
        "private_key": private_key,
        "public_key": public_key,
        "encryption_key": encryption_key
    }

    # cleanup after test
    conn = sqlite3.connect("vault.db")
    conn.execute(
        "DELETE FROM users WHERE email = ?",
        (email,)
    )
    conn.commit()
    conn.close()

###--- This function is for testing the invalid signature, 
#The function simulates a scenario where Bob tries to retrieve his vault but Alice's private key is used to sign his request message, creating invalid signature
#The process of creating the payload and message is exactly the same as retrieve funciton in client script but Alice's private key is used to sign the message
#We expect the server to return: '401 {"detail":"invalid signature"}' 

def test_invalid_signature(bob):

    #Generate Alice's private key
    alice_private_key, _, _ = generate_keys(
        "alice@example.com",
        "alice-test-password"
    )

    #Build a valid retrieve payload for Bob
    payload_data = {
        "type": "retrieve"
    }

    payload = base64.b64encode(
        json.dumps(
            payload_data,
            sort_keys=True,
            separators=(",", ":")
        ).encode()
    ).decode()

    nonce = time.time_ns()

    #Build a request claiming to be Bob
    message = json.dumps(
        {
            "email": bob["email"],
            "payload": payload,
            "nonce": nonce
        },
        sort_keys=True,
        separators=(",", ":")
    ).encode()

    #But sign Bob's request using ALICE'S private key
    signature_bytes = alice_private_key.sign(message)

    signature = base64.b64encode(
        signature_bytes
    ).decode()

    #Send the invalid request
    response = httpx.post(
        f"{SERVER_URL}/retrieve",
        json={
            "email": bob["email"],
            "payload": payload,
            "nonce": nonce,
            "signature": signature
        }
    )

    #Server should reject Alice pretending to be Bob
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid signature"



###--- This function is for testing altered payload. 
#The function simulates a scenario where Bob tries to retrieve his vault but a hacker intercepts his request and switched out his payload
#We expect the server to return: '401 {"detail":"invalid signature"}' 
def test_altered_request(bob):

    #Original valid retrieve payload
    original_payload_data = {
        "type": "retrieve"
    }

    original_payload = base64.b64encode(
        json.dumps(
            original_payload_data,
            sort_keys=True,
            separators=(",", ":")
        ).encode()
    ).decode()

    nonce = time.time_ns()

    #Bob signs the ORIGINAL request
    original_message = json.dumps(
        {
            "email": bob["email"],
            "payload": original_payload,
            "nonce": nonce
        },
        sort_keys=True,
        separators=(",", ":")
    ).encode()

    signature_bytes = bob["private_key"].sign(
        original_message
    )

    signature = base64.b64encode(
        signature_bytes
    ).decode()

    #Attacker changes the payload AFTER Bob signed it
    altered_payload_data = {
        "type": "store",
        "vault": "malicious-vault"
    }

    altered_payload = base64.b64encode(
        json.dumps(
            altered_payload_data,
            sort_keys=True,
            separators=(",", ":")
        ).encode()
    ).decode()

    #Send altered payload with Bob's OLD signature
    response = httpx.post(
        f"{SERVER_URL}/store",
        json={
            "email": bob["email"],
            "payload": altered_payload,
            "nonce": nonce,
            "signature": signature
        }
    )

    #Signature should no longer match the modified request and request cannot be verified
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid signature"



###--- This function is for testing replay attack, ie copy and pasting request.
#The function simulates a scenario where Bob tries to update his vault but an attacker copy and pasted the exact request impersonating as Bob.
#We expect the server to return: '409 {"detail":"Nonce already used"}' 
def test_replayed_request(bob):

    #Create a valid store payload
    payload_data = {
        "type": "store",
        "vault": "test-encrypted-vault"
    }

    payload = base64.b64encode(
        json.dumps(
            payload_data,
            sort_keys=True,
            separators=(",", ":")
        ).encode()
    ).decode()

    #One nonce for this request
    nonce = time.time_ns()

    #Create the message Bob will sign
    message = json.dumps(
        {
            "email": bob["email"],
            "payload": payload,
            "nonce": nonce
        },
        sort_keys=True,
        separators=(",", ":")
    ).encode()

    #Bob signs the request correctly
    signature_bytes = bob["private_key"].sign(message)

    signature = base64.b64encode(
        signature_bytes
    ).decode()

    request_data = {
        "email": bob["email"],
        "payload": payload,
        "nonce": nonce,
        "signature": signature
    }

    #First request should succeed, so status code = 200
    first_response = httpx.post(
        f"{SERVER_URL}/store",
        json=request_data
    )

    assert first_response.status_code == 200

    #Send the same request again
    second_response = httpx.post(
        f"{SERVER_URL}/store",
        json=request_data
    )

    #Server should reject the replayed nonce
    assert second_response.status_code == 409
    assert second_response.json()["detail"] == "Nonce already used"
