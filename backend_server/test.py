import requests
import time

url = "http://localhost:8000"

print(" -- Start of test")
print(" -- Remember to put the worker sleep for 10s")

jobID = ""

def createJob() -> bool:
    global jobID
    print(" -- Creating a new job")
    response = requests.post(url + "/scanMessage", json={
        "message": "Verify your account at http://mytestlink.com"
    })
    if response.status_code != 200:
        print(" -- Job creation test failed")
        print(f" -- Got status code: {response.status_code}")
        print(f" -- Got content: {response.content}")
        exit(1)

    response = response.json()
    jobID = response.get('jobID')
    print(response)
    print(f" -- Got job ID as: {jobID}")
    return True

def checkStatus() -> bool:
    print(" -- Checking job status")
    response = requests.post(url + "/scanStatus", json={"jobID": jobID})
    if response.status_code != 200:
        print(" -- Job status check test failed")
        print(f" -- Got status code: {response.status_code}")
        print(f" -- Got content: {response.content}")
        exit(1)
    response = response.json()
    status = response.get('status')
    print(response)
    return status != 0  # Returns True if status is not 0

def getReport() -> bool:
    print(" -- Getting job report")
    response = requests.post(url + "/getScanDetails", json={"jobID": jobID})
    if response.status_code != 200:
        print(" -- Job report retrieval test failed")
        print(f" -- Got status code: {response.status_code}")
        print(f" -- Got content: {response.content}")
        exit(1)
    response = response.json()
    print(response)
    return True


# Run the tests
createJob()
while not checkStatus():  # Wait until status changes
    time.sleep(1)
getReport()