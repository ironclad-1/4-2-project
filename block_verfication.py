import requests

API_KEY = ''
TX_HASH = '220dac7a090c75c6b13575a886295b89de954d4a52a6713e249f84621203a458'

url = f'https://api-sepolia.etherscan.io/api?module=proxy&action=eth_getTransactionByHash&txhash={TX_HASH}&apikey={API_KEY}'

response = requests.get(url)

# Debug: Print status code and raw text
print("Status Code:", response.status_code)
print("Raw Response Text:", response.text)  # May show HTML error or blank

try:
    data = response.json()
    print("Transaction Details:")
    print(data)
except requests.exceptions.JSONDecodeError as e:
    print("JSON Decode Error:", str(e))
