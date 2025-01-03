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
![1](https://github.com/user-attachments/assets/0ef532ca-66fa-433c-b117-f7f94cffa181)


### 2. Set Up Your Python Environment
Create and activate a Python virtual environment to isolate your dependencies.

```
python -m venv venv
source venv\Scripts\activate
```
![2](https://github.com/user-attachments/assets/c596a9d1-41fc-4683-9f5e-f437cdcb9b89)


### 3. Install Dependencies
Install the necessary dependencies from the `requirements.txt` file.

```
pip install -r requirements.txt
```
![3](https://github.com/user-attachments/assets/07b5f5eb-b553-4ccd-bb3c-8e6bc547265a)


### 4. Run the Backend API (`app.py`)
Once dependencies are installed, you can start the backend API by running `app.py`. This will spin up the backend service.

```
python app.py
```
![4](https://github.com/user-attachments/assets/0687fb4b-25cc-43f8-a163-331a50a0364d)


The server will start running, and you can interact with the API on the specified port (e.g., `http://localhost:5000`).


## Further Information
You can visit the `/docs` endpoint on the live server to get detailed information about the backend.
