"""
This script is focused on persistannce test, which means testing if the vault database persist and can be used again when the server shuts down and
restarts anew. The script consists of some helper functions that help launch a test server and database and shuts it down later, as well as creating
an efficient way of creating signed requests. The code following would be the execution of the test itself. 

Helper functions:
1. get_free_port: finds a free port for the server
2. start_server: creates a new variable in a copy of the current environement for the server, and launch it with uvicorn 
3. wait_for_server: Ensures the server starts before running remaining code. 
4. stop_server: terminates the server, and if it takes more than 5 seconds, it will kill the process
5. make_authenticated_request: it automatically outputs a signed request from private key, email, nonce and payload, to avoid repetition

The test:
1. Finds a port and creates a temporary location for test database
2. Starts the first test server with this port and database
3. Creates an example user with their email, password, keys, and encrypted vault
4. Executes registration, verification and storing for the example user in this test server
5. Terminates the first test Server

6. Starts a new second test server with the same port and the same test database
7. Executes retrieval as the example user with the new server and same database to test if the database persist
8. Check if the retrieved vault and decrypted vault is the same as the encrypted and original vault of the example user respectively
9. Stops the second test server and concludes test

The test uses pytest and requires running pytest -s -v persistance.py to execute test
"""


import os
import sys
import time
import json
import base64
import socket
import subprocess
from pathlib import Path

import httpx

from client import (
    generate_keys,
    encrypt_vault,
    decrypt_vault
)

###--- helper functions
PROJECT_DIR = Path(__file__).resolve().parent

#This function finds a free port for the server
def get_free_port():

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


#This funciton creates a variable for the server in a copy of current environment, then runs the server with uvicorn
def start_server(port, db_path):
    env = os.environ.copy()

    # Tell this server process to use the temporary test database
    env["VAULT_DB_NAME"] = str(db_path)

    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "server:app",
            "--port",
            str(port)
        ],
        cwd=PROJECT_DIR,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return process

#This function keeps requesting access to the server until it allows it. If it took too long (ie it took more than 50 loops here), raises runtime error
def wait_for_server(server_url):
    for _ in range(50):
        try:
            response = httpx.get(
                f"{server_url}/",
                timeout=0.5
            )

            if response.status_code == 200:
                return

        except httpx.RequestError:
            pass

        time.sleep(0.1)

    raise RuntimeError("Test server failed to start")


#This funciton terminates the server, and if it took too long, kills the process entirely
def stop_server(process):
    process.terminate()

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


#This function automatically creates a signed request in the right format with email, payload, nonce and private key. This avoids repetition
def make_authenticated_request(
    email,
    payload_data,
    nonce,
    private_key
):
    payload = base64.b64encode(
        json.dumps(
            payload_data,
            sort_keys=True,
            separators=(",", ":")
        ).encode()
    ).decode()

    message = json.dumps(
        {
            "email": email,
            "payload": payload,
            "nonce": nonce
        },
        sort_keys=True,
        separators=(",", ":")
    ).encode()

    signature = base64.b64encode(
        private_key.sign(message)
    ).decode()

    return {
        "email": email,
        "payload": payload,
        "nonce": nonce,
        "signature": signature
    }


###--- executing the persistance test below

def test_vault_survives_server_restart(tmp_path):

    #pytest gives us a temporary folder and hence a path for the test database
    test_db = tmp_path / "test_vault.db"

    #Find server port and generate url
    port = get_free_port()
    server_url = f"http://127.0.0.1:{port}"


    #Creates an example user, creating their email password, keys and encrypted vault
    email = "persistence-test@example.com"
    master_password = "test-password"

    sk, pk, ek = generate_keys(email, master_password)

    original_vault = {
        "google": {
            "username": "test-user",
            "password": "test-password"
        }
    }

    encrypted_vault = encrypt_vault(original_vault,ek)

    # -------------------------------
    # FIRST SERVER PROCESS
    # -------------------------------

    server = start_server(
        port,
        test_db
    )

    try:
        wait_for_server(server_url)

        #Register, verify and store with this new test server url

        #Register
        response = httpx.post(
            f"{server_url}/register",
            json={
                "email": email,
                "public_key": pk
            }
        )

        assert response.status_code == 200

        #Verify
        response = httpx.post(
            f"{server_url}/verify",
            json={
                "email": email
            }
        )

        assert response.status_code == 200

        #Store vault
        store_request = make_authenticated_request(
            email=email,
            payload_data={
                "type": "store",
                "vault": encrypted_vault
            },
            nonce=1,
            private_key=sk
        )

        response = httpx.post(
            f"{server_url}/store",
            json=store_request
        )

        assert response.status_code == 200

    finally:
        # Actually terminate the server
        stop_server(server)


    # Database must still exist after server stops
    assert test_db.exists()


    # -------------------------------
    # SECOND SERVER PROCESS
    # -------------------------------

    #Use the same port to start a new server
    server = start_server(
        port,
        test_db
    )

    try:
        wait_for_server(server_url)

        #Try retrieving vault as the same example user
        retrieve_request = make_authenticated_request(
            email=email,
            payload_data={
                "type": "retrieve"
            },
            nonce=2,
            private_key=sk
        )

        response = httpx.post(
            f"{server_url}/retrieve",
            json=retrieve_request
        )

        assert response.status_code == 200

        retrieved_encrypted_vault = response.json()["vault"]

        #Confirm same retrieved vault survived restart, ie matches the initial encrypted vault
        assert retrieved_encrypted_vault == encrypted_vault

        #Confirm the retireved vault can still be decrypted
        recovered_vault = decrypt_vault(
            retrieved_encrypted_vault,
            ek
        )

        assert recovered_vault == original_vault

        print("Persistence test passed")

    finally:
        stop_server(server)