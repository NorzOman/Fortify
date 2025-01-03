# Vault-7 API

## Overview
Vault-7 API is a backend service designed to manage authentication tokens for detection messages and malware detection. It provides endpoints for securely handling tokens used in the detection pipeline, ensuring seamless communication between various detection systems and tools.


## Installation

Follow the steps below to get the Vault-7 API running on your local machine.

### 1. Clone the Repository
Clone the Vault-7 API repository to your local machine.

```
git clone https://github.com/NorzOman/Vault-7.git
```


### 2. Set Up Your Python Environment
Create and activate a Python virtual environment to isolate your dependencies.

```
python -m venv venv
source venv\Scripts\activate
```


### 3. Install Dependencies
Install the necessary dependencies from the `requirements.txt` file.

```
pip install -r requirements.txt
```


### 4. Run the Backend API (`app.py`)
Once dependencies are installed, you can start the backend API by running `app.py`. This will spin up the backend service.

```
python app.py
```


The server will start running, and you can interact with the API on the specified port (e.g., `http://localhost:5000`).


## Interface

### Vault - 7 [User Front End]
#### Root Front End for the Backend
![Root Front End](https://github.com/user-attachments/assets/115ed609-37f3-4a8a-946c-7e123875b740)

#### Register Point for API Key Access
Users can register here to obtain API key access.
![Register Point](https://github.com/user-attachments/assets/020215db-5da4-4a65-a76a-2984f5efcbd3)

#### User Dashboard
The main dashboard for users.
![User Dashboard](https://github.com/user-attachments/assets/2930b151-583f-46ac-8820-7f410b9af699)

#### Pending API Key Request
Requests for API keys awaiting backend approval.
![Pending API Key Request](https://github.com/user-attachments/assets/084a9742-7095-490a-b916-f469dec25bb8)

> Once the API key request is submitted, it will be processed by the backend.

---

### Vault - 7 [Developer Front End]
#### Developer Login
Use the credentials below to log in as a developer:
- **Username**: `./admin`  
- **Password**: `Engineer$@987`

![Developer Login](https://github.com/user-attachments/assets/3521d087-5465-43b1-8380-6ff08a43469b)

#### Admin Dashboard
The central hub for administrative actions.
![Admin Dashboard](https://github.com/user-attachments/assets/86278df9-0582-4808-932c-fb3f00ae6e5c)

#### System Logs Dashboard
Monitor system logs here.
![System Logs Dashboard](https://github.com/user-attachments/assets/34a6cae7-4983-4d0f-bf65-a3a89b0250a1)

#### Firewall Settings Dashboard
Manage firewall settings.  
Note: `127.0.0.1` is set in the IP allow list to bypass logging for local IP actions.
![Firewall Settings Dashboard](https://github.com/user-attachments/assets/8d443cb3-b8ab-4090-9ae5-d0a1bc7d9c01)

#### Access Key Management Dashboard
Administer API keys and access settings here.
![Access Key Management Dashboard](https://github.com/user-attachments/assets/489a3db4-ddfc-4bbd-bdf6-de6f31147af8)

---

### User Frontend Receiving the API Key
Users receive their API key after approval.
![User API Key Delivery](https://github.com/user-attachments/assets/4f5a4683-6373-4489-859e-453a862b7052)
