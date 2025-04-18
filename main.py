# import requests
# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# from Crypto.Util.Padding import pad
# import os
# import base64
# from Block_chain import send_to_blockchain
# from dotenv import load_dotenv

# # Load .env
# load_dotenv("/Users/sirisipallinarendra/Desktop/Block_chain/env")

# # AES block size
# BLOCK_SIZE = AES.block_size

# def generate_key_from_aadhar(aadhar: str) -> bytes:
#     from hashlib import sha256
#     return sha256(aadhar.encode()).digest()

# def aes_encrypt(data: bytes, key: bytes) -> bytes:
#     iv = get_random_bytes(16)
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     encrypted_data = cipher.encrypt(pad(data, BLOCK_SIZE))
#     return iv + encrypted_data

# def encrypt_file(file_path: str, key: bytes, out_path: str = "encrypted_upload.bin") -> str:
#     with open(file_path, 'rb') as f:
#         file_data = f.read()
#     encrypted = aes_encrypt(file_data, key)
#     with open(out_path, 'wb') as f:
#         f.write(encrypted)
#     return out_path

# def upload_to_ipfs(file_path: str) -> str:
#     url = "http://127.0.0.1:5001/api/v0/add"
#     with open(file_path, 'rb') as f:
#         response = requests.post(url, files={"file": f})
#     if response.status_code == 200:
#         return response.json()['Hash']
#     else:
#         raise Exception("IPFS upload failed: " + response.text)

# def encrypt_cid(cid: str, key: bytes) -> str:
#     encrypted = aes_encrypt(cid.encode(), key)
#     return base64.b64encode(encrypted).decode('utf-8')

# def process_document(file_path: str, aadhar: str):
#     key = generate_key_from_aadhar(aadhar)

#     print("🔐 Encrypting document...")
#     encrypted_path = encrypt_file(file_path, key)

#     print("📤 Uploading to IPFS...")
#     cid = upload_to_ipfs(encrypted_path)

#     print("🔒 Encrypting CID...")
#     encrypted_cid = encrypt_cid(cid, key)

#     metadata = f"filename={os.path.basename(file_path)}"

#     print("⛓️ Sending encrypted CID + metadata to blockchain...")
#     tx_hash = send_to_blockchain(encrypted_cid, metadata)

#     return {
#         "original_file": file_path,
#         "encrypted_file": encrypted_path,
#         "cid": cid,
#         "encrypted_cid": encrypted_cid,
#         "tx_hash": tx_hash
#     }

# if __name__ == "__main__":
#     file = r"/Users/sirisipallinarendra/Desktop/Block_chain/EVault Doccumentation.docx"
#     aadhar = "123456789012"
#     result = process_document(file, aadhar)

#     print("\n✅ PROCESS COMPLETE:")
#     print("🔗 CID:", result['cid'])
#     print("🔐 Encrypted CID (base64):", result['encrypted_cid'])
#     print("📁 Encrypted File:", result['encrypted_file'])
#     print("⛓️ Blockchain Tx Hash:", result['tx_hash'])

import streamlit as st
import sqlite3, os, csv, base64, requests
from datetime import datetime, timezone
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Block_chain import send_event          # same folder
from dotenv import load_dotenv

load_dotenv()                                # for IPFS auth if any

# ----------  CONFIG  ------------------------------------------------
DB_PATH       = "/Users/sirisipallinarendra/Desktop/Block_chain/evault.db"
CSV_PATH      = "/Users/sirisipallinarendra/Desktop/Block_chain/transactions.csv"
IPFS_ADD_URL  = "http://127.0.0.1:5001/api/v0/add"
IPFS_CAT_URL  = "http://127.0.0.1:5001/api/v0/cat"   # <-- no querystring, we'll pass params
BLOCK_SIZE    = AES.block_size
DOC_TYPES     = ("Aadhaar", "Passport", "Pan Card")

# ----------  DB INIT  ----------------------------------------------

def init_db():
    """Initialise SQLite DB.  In the new requirement we allow multiple files of
    the same doc_type per user, so we removed the UNIQUE constraint."""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute(
            """CREATE TABLE IF NOT EXISTS users(
                   aadhaar   TEXT PRIMARY KEY,
                   name      TEXT,
                   pwd_hash  TEXT
               )"""
        )
        # no UNIQUE(aadhaar, doc_type) — multiple versions allowed
        c.execute(
            """CREATE TABLE IF NOT EXISTS documents(
                   id          INTEGER PRIMARY KEY AUTOINCREMENT,
                   aadhaar     TEXT,
                   doc_type    TEXT,
                   file_name   TEXT,
                   cid_enc     TEXT,
                   key_hex     TEXT,
                   tx_hash_up  TEXT,
                   tx_hash_dl  TEXT,
                   downloaded  INTEGER DEFAULT 0,
                   up_time     TEXT,
                   dl_time     TEXT,
                   FOREIGN KEY(aadhaar) REFERENCES users(aadhaar)
               )"""
        )
        conn.commit()

init_db()

# ----------  CRYPTO UTILS  -----------------------------------------

def key_from_aadhaar(aadhaar: str) -> bytes:
    return sha256(aadhaar.encode()).digest()


def aes_encrypt(data: bytes, key: bytes) -> bytes:
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(data, BLOCK_SIZE))


def aes_decrypt(data: bytes, key: bytes) -> bytes:
    iv, ct = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), BLOCK_SIZE)


def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()


def ub64(s: str) -> bytes:
    return base64.b64decode(s)

# ----------  IPFS  --------------------------------------------------

def ipfs_add(fp: str) -> str:
    with open(fp, "rb") as f:
        r = requests.post(IPFS_ADD_URL, files={"file": f})
    r.raise_for_status()
    return r.json()["Hash"]


def ipfs_get(cid: str) -> bytes:
    # All Kubo endpoints require POST – using GET returns 405.
    r = requests.post(IPFS_CAT_URL, params={"arg": cid}, stream=True)
    r.raise_for_status()
    return r.content

# ----------  DB HELPERS  -------------------------------------------

def add_user(aadhaar, name, pwd_hash):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("INSERT INTO users VALUES (?,?,?)", (aadhaar, name, pwd_hash))
        conn.commit()


def check_user(aadhaar, pwd_hash):
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "SELECT * FROM users WHERE aadhaar=? AND pwd_hash=?", (aadhaar, pwd_hash)
        )
        return cur.fetchone()


def save_doc(rec: tuple):
    """rec = (aadhaar, doc_type, file_name, cid_enc, key_hex, tx_hash_up, up_time)"""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """INSERT INTO documents
               (aadhaar, doc_type, file_name, cid_enc, key_hex, tx_hash_up, up_time)
               VALUES (?,?,?,?,?,?,?)""",
            rec,
        )
        conn.commit()


def get_docs(aadhaar, doc_type):
    """Return all docs for user & type, newest first."""
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            """SELECT * FROM documents WHERE aadhaar=? AND doc_type=? ORDER BY id DESC""",
            (aadhaar, doc_type),
        )
        return cur.fetchall()


def mark_download(doc_id, tx_hash):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """UPDATE documents SET downloaded=1, tx_hash_dl=?, dl_time=? WHERE id=?""",
            (tx_hash, datetime.now(timezone.utc).isoformat(), doc_id),
        )
        conn.commit()

# ----------  CSV LOG  ----------------------------------------------

def log_csv(row: dict):
    exists = os.path.isfile(CSV_PATH)
    with open(CSV_PATH, "a", newline="") as f:
        w = csv.DictWriter(f, row.keys())
        if not exists:
            w.writeheader()
        w.writerow(row)

# ----------  STREAMLIT UI  -----------------------------------------

st.set_page_config("eVault", "📁")

# Session state
auth_key = "auth"
if auth_key not in st.session_state:
    st.session_state[auth_key] = None

# --------------  AUTH FORMS  -----------------
if st.session_state[auth_key] is None:
    tab1, tab2 = st.tabs(["🆕 Sign Up", "🔑 Log In"])

    with tab1:
        st.subheader("Create an account")
        aadhar = st.text_input("Aadhaar", max_chars=12)
        name = st.text_input("Name")
        pw1 = st.text_input("Password", type="password")
        pw2 = st.text_input("Confirm Password", type="password")
        if st.button("Sign Up", disabled=not all([aadhar, name, pw1, pw2])):
            if pw1 != pw2:
                st.error("Passwords do not match")
            else:
                try:
                    add_user(aadhar, name, sha256(pw1.encode()).hexdigest())
                    st.success("Account created – please log in")
                except sqlite3.IntegrityError:
                    st.error("Aadhaar already registered")

    with tab2:
        st.subheader("Log in")
        aadhar_l = st.text_input("Aadhaar", max_chars=12, key="log_a")
        pw_l = st.text_input("Password", type="password", key="log_p")
        if st.button("Login", disabled=not aadhar_l or not pw_l):
            if check_user(aadhar_l, sha256(pw_l.encode()).hexdigest()):
                st.session_state[auth_key] = aadhar_l
                st.rerun()
            else:
                st.error("Invalid credentials")

# --------------  MAIN APP (after login)  --------------
else:
    aadhaar = st.session_state[auth_key]
    st.sidebar.success(f"Logged in as **{aadhaar}**")
    menu = st.sidebar.radio("Menu", ["Upload Document", "Retrieve Document", "Logout"])

    # -------------  LOGOUT  -----------------
    if menu == "Logout":
        st.session_state[auth_key] = None
        st.rerun()

    # -------------  UPLOAD  -----------------
    elif menu == "Upload Document":
        st.header("Upload a new document")
        doctype = st.selectbox("Document type", DOC_TYPES)
        uploaded = st.file_uploader("Choose file")
        if uploaded and st.button("Encrypt & Upload"):
            key = key_from_aadhaar(aadhaar)
            # --- save temp file
            tmp_path = f"tmp_{uploaded.name}"
            with open(tmp_path, "wb") as f:
                f.write(uploaded.getbuffer())

            # --- encrypt file
            enc_path = "encrypted_" + uploaded.name
            with open(tmp_path, "rb") as f:
                data = f.read()
            with open(enc_path, "wb") as f:
                f.write(aes_encrypt(data, key))

            # --- IPFS add
            cid = ipfs_add(enc_path)

            # --- encrypt CID & record on-chain
            cid_enc = b64(aes_encrypt(cid.encode(), key))
            meta = f"{uploaded.name}|{doctype}"
            tx_hash = send_event("UPLOAD", cid_enc, meta)

            # --- DB / CSV
            now_iso = datetime.now(timezone.utc).isoformat()
            save_doc((aadhaar, doctype, uploaded.name, cid_enc, key.hex(), tx_hash, now_iso))
            log_csv({"aadhaar": aadhaar, "doc_type": doctype, "tx_hash": tx_hash, "time": now_iso})

            # --- cleanup
            os.remove(tmp_path)
            os.remove(enc_path)

            st.success("Uploaded & recorded on‑chain")
            st.code(f"CID: {cid}\nTx:  {tx_hash}", language="bash")

    # -------------  RETRIEVE  -----------------
    elif menu == "Retrieve Document":
        st.header("Retrieve stored document(s)")
        doctype = st.selectbox("Select document type", DOC_TYPES)
        if st.button("Fetch"):
            rows = get_docs(aadhaar, doctype)
            if not rows:
                st.error("No documents of this type in your vault")
            else:
                st.info(f"Found {len(rows)} file(s). Decrypting…")
                key = key_from_aadhaar(aadhaar)  # same key for all

                for row in rows:
                    _id, _, _, fname, cid_enc, key_hex, tx_up, tx_dl, dl_flag, _, _ = row
                    # keys are per‑file, but we still decrypt with stored key_hex to be safe
                    key_file = bytes.fromhex(key_hex)
                    cid = aes_decrypt(ub64(cid_enc), key_file).decode()

                    enc_file_bytes = ipfs_get(cid)
                    plain = aes_decrypt(enc_file_bytes, key_file)

                    # unique key for download button to avoid duplicates
                    dl_key = f"dl-{_id}"
                    st.download_button(
                        label=f"⬇️ Download {fname}",
                        data=plain,
                        file_name=fname,
                        key=dl_key,
                    )

                    if not dl_flag:
                        tx_dl = send_event("DOWNLOAD", cid_enc, f"{fname}|{doctype}")
                        mark_download(_id, tx_dl)
                        log_csv(
                            {
                                "aadhaar": aadhaar,
                                "doc_type": doctype,
                                "tx_hash": tx_dl,
                                "time": datetime.now(timezone.utc).isoformat(),
                            }
                        )
                        st.write(f"✅ Download recorded on‑chain — transaction ID:")
                        st.code(tx_dl, language="bash")
                    else:
                        # Already downloaded earlier, still show tx id
                        st.write("Previously downloaded. On‑chain transaction:")
                        st.code(tx_dl, language="bash")
