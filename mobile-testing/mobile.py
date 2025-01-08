#Importing required libraries for mobile simulation
import requests
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import json
import os
import time

BASE_URL = 'http://127.0.0.1:5000'
#BASE_URL ='https://vault-7.onrender.com'
TOKEN_MESSAGE = ''
TOKEN_FILE = ''

def simulate_health_check():
    url = f"{BASE_URL}/api/v1//check_health"
    print("\n [-] Sending GET request to /check_health endpoint")
    response = requests.get(url)
    print(f"\n {response.text}")
    buffer = input(" [-] Press enter to continue....")

def simulate_get_token_for_message(condition):
    global TOKEN_MESSAGE
    # First send a get request and get the client_ip from the server
    url = f"{BASE_URL}/api/v1/check_health"
    print("\n [-] First sending GET request to /check_health endpoint")
    response = requests.get(url)
    print(f"\n {response.text}")
    #Extract the client ip from the response
    print("\n [-] Extracting client_ip from the response")
    response_data = response.json()
    client_ip = response_data.get("client_ip")
    time.sleep(2)
    print(f"\n [-] Setting the client ip as : {client_ip} ")
    time.sleep(1)
    print(f"\n\n [-] Now creating GUID using {client_ip} using client_ip as secret key with AES encryption")
    key = hashlib.sha256(client_ip.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    padded_ip = pad(client_ip.encode(), AES.block_size)
    encrypted_ip = cipher.encrypt(padded_ip)
    device_guid = base64.b64encode(encrypted_ip).decode('utf-8')
    time.sleep(2)
    print(f"\n [-] GUID generated as :  {device_guid}")
    time.sleep(1)
    print(f"\n [-] Now sending POST request with GUID to endpoint /get_token_for_message")
    url =  f"{BASE_URL}/api/v1/get_token_for_message"
    headers = {'Content-Type': 'application/json'}
    json_data = json.dumps({"device_guid": device_guid})
    response = requests.post(url, headers=headers, data=json_data)
    response.raise_for_status()
    time.sleep(2)
    print(f"\n\n [-] POST request returned with response: ")
    print(f"\n {response.json()}\n")
    response_data = response.json()
    token = response_data.get("token")
    TOKEN_MESSAGE = token
    time.sleep(2)
    print(f"\n [-] Setting global TOKEN_MESSAGE with token {token} \n\n")
    if condition == 0:
        buffer = input(" [-] Press enter to continue....")


def simulate_get_token_for_file(condition):
    global TOKEN_FILE
    # First send a get request and get the client_ip from the server
    url = f"{BASE_URL}/api/v1/check_health"
    print("\n [-] First sending GET request to /check_health endpoint")
    response = requests.get(url)
    print(f"\n {response.text}")
    #Extract the client ip from the response
    print("\n [-] Extracting client_ip from the response")
    response_data = response.json()
    client_ip = response_data.get("client_ip")
    time.sleep(2)
    print(f"\n [-] Setting the client ip as : {client_ip} ")
    time.sleep(1)
    print(f"\n\n [-] Now creating GUID using {client_ip} using client_ip as secret key with AES encryption")
    key = hashlib.sha256(client_ip.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    padded_ip = pad(client_ip.encode(), AES.block_size)
    encrypted_ip = cipher.encrypt(padded_ip)
    device_guid = base64.b64encode(encrypted_ip).decode('utf-8')
    time.sleep(2)
    print(f"\n [-] GUID generated as :  {device_guid}")
    time.sleep(1)
    print(f"\n [-] Now sending POST request with GUID to endpoint /get_token_for_file")
    url =  f"{BASE_URL}/api/v1/get_token_for_files"
    headers = {'Content-Type': 'application/json'}
    json_data = json.dumps({"device_guid": device_guid})
    response = requests.post(url, headers=headers, data=json_data)
    response.raise_for_status()
    time.sleep(2)
    print(f"\n\n [-] POST request returned with response: ")
    print(f"\n {response.json()}\n")
    response_data = response.json()
    token = response_data.get("token")
    TOKEN_FILE = token
    time.sleep(2)
    print(f"\n [-] Setting global TOKEN_FILE with token : {TOKEN_FILE} \n\n")
    if condition == 0:
        buffer = input(" [-] Press enter to continue....")

def simulate_get_token_fake_guid():
    url = f"{BASE_URL}/api/v1/check_health"
    print("\n [!] Not sending /check_health endpoint\n")
    client_ip = input (" [-] Enter IP to make GUID with : ")
    time.sleep(2)
    print(f"\n [-] Setting the client ip as : {client_ip} ")
    time.sleep(1)
    print(f"\n\n [-] Now creating GUID using {client_ip} using client_ip as secret key with AES encryption")
    key = hashlib.sha256(client_ip.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    padded_ip = pad(client_ip.encode(), AES.block_size)
    encrypted_ip = cipher.encrypt(padded_ip)
    device_guid = base64.b64encode(encrypted_ip).decode('utf-8')
    time.sleep(2)
    print(f"\n [-] GUID generated as :  {device_guid}")
    time.sleep(1)
    print(f"\n [-] Now sending POST request with GUID to endpoint /get_token_for_message")
    url =  f"{BASE_URL}/api/v1/get_token_for_message"
    headers = {'Content-Type': 'application/json'}
    json_data = json.dumps({"device_guid": device_guid})
    response = requests.post(url, headers=headers, data=json_data)
    response.raise_for_status()
    time.sleep(2)
    print(f"\n\n [-] POST request returned with response: ")
    print(f"\n {response.json()}\n")
    buffer = input(" [-] Press enter to continue....")

def simulate_sending_message_detect():
    url = f"{BASE_URL}/api/v1/message_detection"    
    print("\n\n [-] First running get_token_for_message function to get token")
    simulate_get_token_for_message(1)
    time.sleep(2)
    print(" [-] Token initialization completed")
    time.sleep(2)
    print("\n\n")
    message = input(" [-] Enter your message: ")
    headers = {'Content-Type': 'application/json'}
    message_data = {"message": message, "token": TOKEN_MESSAGE}
    response = requests.post(url, headers=headers, data=json.dumps(message_data))
    time.sleep(1)
    print(f"\n\n [-] Sending POST request to /message_detection with token : {TOKEN_MESSAGE}")
    time.sleep(2)
    print(f"\n\n [-] Response: {response.json()}\n")
    buffer = input(" [-] Press enter to continue....")


# Sending signature along with the filename for detection
def simulate_send_signature_detect():
    url = f"{BASE_URL}/api/v1/malware_detection"
    print("\n\n[-] First running get_token_for_files function to get token")
    simulate_get_token_for_file(1)
    time.sleep(2)
    print("[-] Token initialization completed")
    time.sleep(2)
    print("\n\n")

    # Predefined list of file names and their MD5 signatures
    signatures = [
        ("malware.exe", "e4d909c290d0fb1ca068ffaddf22cbd0"),
        ("ransomware.dll", "a87ff679a2f3e71d9181a67b7542122c"),
        ("trojan.sys", "c4ca4238a0b923820dcc509a6f75849b"),
        ("keylogger.exe", "c81e728d9d4c2f636f067f89cc14862c")
    ]
    
    # Print the signatures being sent
    print("\n[-] Sending the following signatures:")
    for name, sig in signatures:
        print(f"File Name: {name}, Signature: {sig}")
    
    # Prepare the data for the POST request
    headers = {'Content-Type': 'application/json'}
    data = {
        "signatures": signatures,
        "token": TOKEN_FILE
    }
    
    # Sending the POST request
    print(f"\n\n[-] Sending POST request to {url} with token: {TOKEN_FILE}")
    response = requests.post(url, headers=headers, data=json.dumps(data))
    time.sleep(1)
    
    print(f"\n[-] Response: {response.text}")

    buffer = input(" [-] Press enter to continue....")


# Format of the request it is sending:
# {
#     "signatures": [
#         ("malware.exe", "e4d909c290d0fb1ca068ffaddf22cbd0"),
#         ("ransomware.dll", "a87ff679a2f3e71d9181a67b7542122c")
#     ],
#     "token": "your_token_here"
# }


def main():
    choice = 0
    while(choice != 7):
        os.system("clear")
        print("\n ~~Main Menu~~\n")
        print(" 1. Simulate heatlh check \n ")
        print(" 2. Simulate getting token for message with GUID \n")
        print(" 3. Simulate getting token for file with GUID \n")
        print(" 4. Simulate attempting to get token with fake GUID \n")
        print(' 5. Simulate sending a message to detect \n')
        print(" 6. Simulate sending signature to detect \n")
        print(" 7. Exit \n")
        choice = input(" Enter your choice : ")
        match choice:
            case "1":
                simulate_health_check()
            case "2":
                simulate_get_token_for_message(0)
            case "3":
                simulate_get_token_for_file(0)
            case "4":
                simulate_get_token_fake_guid()
            case "5":
                simulate_sending_message_detect()
            case "6":
                simulate_send_signature_detect()
            case "7":
                exit(0)
            case _:
                print(" Invalid Choice!")

if __name__ == '__main__':
    main()
