# from web3 import Web3
# import os
# from dotenv import load_dotenv

# # Load environment variables
# load_dotenv("/Users/sirisipallinarendra/Desktop/Block_chain/env")

# SEPOLIA_RPC_URL = os.getenv("SEPOLIA_RPC_URL")
# PRIVATE_KEY = os.getenv("PRIVATE_KEY")

# # Web3 setup
# w3 = Web3(Web3.HTTPProvider(SEPOLIA_RPC_URL))
# account = w3.eth.account.from_key(PRIVATE_KEY)
# sender_address = account.address

# def check_connection():
#     if w3.is_connected():
#         print("✅ Web3 is connected to Sepolia.")
#     else:
#         print("❌ Web3 is NOT connected.")

# def send_to_blockchain(encrypted_cid: str, metadata: str) -> str:
#     if not w3.is_connected():
#         raise ConnectionError("Web3 is not connected to Sepolia")

#     message = f"CID:{encrypted_cid};META:{metadata}"
#     hex_data = w3.to_hex(text=message)

#     nonce = w3.eth.get_transaction_count(sender_address)
#     tx = {
#         "nonce": nonce,
#         "to": sender_address,
#         "value": 0,
#         "gas": 300000,
#         "gasPrice": w3.to_wei("20", "gwei"),
#         "data": hex_data,
#         "chainId": 11155111,  # Sepolia Chain ID
#     }

#     signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
#     tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

#     return tx_hash.hex()

# if __name__ == "__main__":
#     check_connection()

"""
Blockchain helper – Sepolia via Infura
======================================
Functions
---------
check_connection()              -> prints status
send_event(event, enc_cid, md)  -> returns tx‑hash (hex str)

Event types used by the Streamlit app:
   UPLOAD  – on successful upload
   DOWNLOAD – after a user downloads a file
"""
from web3 import Web3
from datetime import datetime as dt
import os
from dotenv import load_dotenv

# ------------------------------------------------------------------ #
#  Load credentials (.env or env)                                    #
# ------------------------------------------------------------------ #
BASE_DIR      = os.path.dirname(__file__)            # folder of this file
ENV_PATHS     = [os.path.join(BASE_DIR, ".env"),
                 os.path.join(BASE_DIR, "env")]      # try both names

for p in ENV_PATHS:
    if os.path.isfile(p):
        load_dotenv(p)
        break
else:
    raise FileNotFoundError(
        "Credentials file not found – expected .env or env in project folder")

SEPOLIA_RPC_URL = os.getenv("SEPOLIA_RPC_URL")
PRIVATE_KEY      = os.getenv("PRIVATE_KEY")
CHAIN_ID         = 11155111  # Sepolia

if not SEPOLIA_RPC_URL or not PRIVATE_KEY:
    raise EnvironmentError(
        "Missing SEPOLIA_RPC_URL or PRIVATE_KEY in the credentials file")

# ------------------------------------------------------------------ #
#  Web3 setup
# ------------------------------------------------------------------ #
w3 = Web3(Web3.HTTPProvider(SEPOLIA_RPC_URL))
account        = w3.eth.account.from_key(PRIVATE_KEY)
SENDER_ADDRESS = account.address

# … rest of the file stays exactly the same …


# ------------------------------------------------------------------ #
def check_connection() -> None:
    print("✅ Connected" if w3.is_connected()
          else "❌  NOT connected")


# ------------------------------------------------------------------ #
def _build_signed_tx(data_hex: str) -> str:
    nonce = w3.eth.get_transaction_count(SENDER_ADDRESS)
    tx = {
        "nonce":     nonce,
        "to":        SENDER_ADDRESS,   # self‑send, just for data
        "value":     0,
        "gas":       300_000,
        "gasPrice":  w3.to_wei("20", "gwei"),
        "data":      data_hex,
        "chainId":   CHAIN_ID,
    }
    signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    return signed.raw_transaction  # bytes


# ------------------------------------------------------------------ #
def send_event(event_type: str,
               encrypted_cid: str,
               metadata:   str) -> str:
    """
    Push an opaque event string to the chain.
    `metadata` is any extra text (filename, DocType, etc.)
    Returns the tx‑hash as hex.
    """
    if not w3.is_connected():
        raise ConnectionError("Web3 not connected")

    payload = f"{event_type}:{encrypted_cid};META:{metadata};TS:{dt.utcnow().isoformat()}"
    raw_tx  = _build_signed_tx(w3.to_hex(text=payload))
    tx_hash = w3.eth.send_raw_transaction(raw_tx)
    return tx_hash.hex()


# Handy test
if __name__ == "__main__":
    check_connection()
