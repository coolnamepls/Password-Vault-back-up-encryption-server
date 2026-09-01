"""
This script is for the server side functionalities, including the registration, verification, vault addition, retrival mechanism
for user to register to use the vault, verify their email and adding their encrypted vault. 
The idea is the client script will send the new user's email and public key to the server, 
and if the user is new (no this email in db), a new row record for the user is added to the db,
allowing the user to add their encrypted vault. 
The user's email is verified if the user is registered and the send their email for verification.
Their encrypted vault is added if the user is registered and email verified.
Their vault is retrieved with their email if they had already been registered, verified, and had an existing vault.

Idea for each core function 
get_db: Connect to database
create_tables: User table is created if not exist.
register: Add new user if their email didn't exist
verify: Verify user if their email is sent and they had already been registered
store: adding or replacing ecrypted vault to user db if user is registered and email verified
retrieve: Retrieving user's vault with their email, given that the had already registered, verified their email, and previously added a vault.
"""



from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3

import json
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import os

app = FastAPI()

DB_NAME = os.getenv("VAULT_DB_NAME", "vault.db")


###--- Connect database and create user table, ensuring user table exists
def get_db():
#Connects to database and allow access to data via column name
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
#creates table if not exist in db
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            verified INTEGER NOT NULL DEFAULT 0,
            vault TEXT,
            last_nonce INTEGER NOT NULL DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()


create_tables()




###--- Request structures (These classes ensure input jsons are consistent in structure)
class RegisterRequest(BaseModel):
    email: str
    public_key: str

class VerifyRequest(BaseModel):
    email: str

class AuthenticatedRequest(BaseModel):
    email: str
    payload: str
    nonce: int
    signature: str

class RetrieveRequest(BaseModel):
    email: str

###--- To check if the server runs
@app.get("/")
def home():
    return {"status": "server is running"}


##-- This function is for authenticating the user and then outputs the payload if successful authentication
#Authentication is done through verifying the signature with public key and ensuring the nonce is not used, which avoids replaying request
def authenticate_request(request, user, conn):

    if user is None:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    if user["verified"] == 0:
        conn.close()
        raise HTTPException(
            status_code=403,
            detail="Email not verified"
        )

    #Recreate the message which was signed from the client side
    message = json.dumps(
        {
            "email": request.email,
            "payload": request.payload,
            "nonce": request.nonce
        },
        sort_keys=True,
        separators=(",", ":")
    ).encode()

    #Get public key from the database and decode it back to bytes to obtain the public key object
    public_key_bytes = base64.b64decode(user["public_key"])

    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

    #Convert signature from Base64 back into bytes and verify the signature
    signature_bytes = base64.b64decode(request.signature)

    try:
        public_key.verify(signature_bytes,message)

    except InvalidSignature:
        conn.close()
        raise HTTPException(
            status_code=401,
            detail="Invalid signature"
        )

    #Check if nonce is used before, make sure every update is unique, avoid replaying
    if request.nonce <= user["last_nonce"]:
        conn.close()
        raise HTTPException(
            status_code=409,
            detail="Nonce already used"
        )

    #Decode payload and convert back to json: includes type of payload, and should include encrpyted vault if type is "store"
    payload_json = base64.b64decode(request.payload).decode()

    payload = json.loads(payload_json)    

    return payload

###========================================================================================================================================###
### The following are the main mechanisms from the server side, including registering, verifying email, storing vault, and retrieving vault###
###========================================================================================================================================###

###--- The main registration mechanism, ensuring input json structure and create new record in user table if it user is new 
@app.post("/register")
def register(request: RegisterRequest):
#Creates new record if user didn't exist in user table, and print out the reocrd added or existed 
    conn = get_db()

    try:
        conn.execute(
            """
            INSERT INTO users (email, public_key)
            VALUES (?, ?)
            """,
            (request.email, request.public_key)
        )

        conn.commit()

    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="Email already registered"
        )

    finally:
        conn.close()

    return {
        "message": "User registered",
        "email": request.email
    }


###--- Verification mechanism, sending a json with email as input to verify user if user is registered
@app.post("/verify")
def verify(request: VerifyRequest):
    conn = get_db()

    cursor = conn.execute(
        """
        UPDATE users
        SET verified = 1
        WHERE email = ?
        """,
        (request.email,)
    )

    conn.commit()

    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    conn.close()

    return {
        "message": "Email verified",
        "email": request.email
    }


###--- Vault adding/storing mechansim, checks if the user is registered and verified, then unpacks the payload to verify signature through autehntication
# and update the vault (encrypted)
@app.post("/store")
def store(request: AuthenticatedRequest):

    conn = get_db()

    #Find the user, and ensure they are registered and verified
    user = conn.execute(
        """
        SELECT * FROM users
        WHERE email = ?
        """,
        (request.email,)
    ).fetchone()

    #Obtain payload after authentication
    payload = authenticate_request(request = request, user = user, conn = conn)

    # ake sure this really is a store request and extract encrpyted vault
    if payload.get("type") != "store":
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="Invalid payload type"
        )

    encrypted_vault = payload["vault"]

    #Store encrypted vault and remember nonce
    conn.execute(
        """
        UPDATE users
        SET vault = ?, last_nonce = ?
        WHERE email = ?
        """,
        (
            encrypted_vault,
            request.nonce,
            request.email
        )
    )

    conn.commit()
    conn.close()

    return {
        "message": "Vault stored",
        "email": request.email
    }


###--- Retrival mechanism, request retrival through email and user authentication, 
#check if user has a vault already. If so, retrieve vault
@app.post("/retrieve")
def retrieve(request: AuthenticatedRequest):

    conn = get_db()
    #Search the user's email, and check if they have been registered and email verified
    user = conn.execute(
        """
        SELECT * FROM users
        WHERE email = ?
        """,
        (request.email,)
    ).fetchone()

    #Obtain payload after authentication
    payload = authenticate_request(request=request, user=user, conn=conn)

    #This makes sures the payload type is actually retrieve
    if payload.get("type") != "retrieve":
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="Invalid payload type"
        )

    #**Verification came first to ensure payload is verified before acting on the user's data
    #This makes sure the vault is not empty and has something to retrieve
    if user["vault"] is None:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="No vault stored"
        )


    conn.execute(
        """
        UPDATE users
        SET last_nonce = ?
        WHERE email = ?
        """,
        (
            request.nonce,
            request.email
        )
    )

    conn.commit()

    vault = user["vault"]

    conn.close()

    return {
        "email": request.email,
        "vault": vault
    }





