from flask import Flask, request, jsonify
import os
import sqlite3
import random

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOADS_FOLDER = os.path.join(BASE_DIR,'inputs')
MALWARE_FOLDER = os.path.join(UPLOADS_FOLDER,'malware')
PHISHING_FOLDER = os.path.join(UPLOADS_FOLDER,'message')

os.makedirs(UPLOADS_FOLDER, exist_ok=True)
os.makedirs(MALWARE_FOLDER, exist_ok=True)
os.makedirs(PHISHING_FOLDER, exist_ok=True)

def id_gen():
    return random.randint(100000,999999)

def print_all_data(cursor):
    res = cursor.execute("SELECT * FROM data")
    return res

def delete_data(cursor):
    cursor.execute("DELETE FROM data")

def insert_data(cursor,id,token,type,input_path,status,output_path,confidence,detection):
    cursor.execute("INSERT INTO data VALUES (?, ?, ?, ?, ?, ?, ?, ?)",(id, token, type, input_path, status, output_path, confidence, detection))

def db_init():
    try:
        conn = sqlite3.connect("Job_database.db")
        cursor = conn.cursor()

        #Creating table

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS data(
                JOB_ID INTEGER NOT NULL,
                JWT_TOKEN TEXT NOT NULL,
                TYPE TEXT CHECK(TYPE IN ("Malware","Phishing")) NOT NULL,
                INPUT_FILE_PATH TEXT,
                STATUS TEXT CHECK(STATUS IN ("Pending","Done")) NOT NULL,
                OUTPUT_FILE_PATH TEXT,
                CONFIDENCE INTEGER NULL,
                DETECTION TEXT NULL
            ) """)
        return conn, cursor
    except sqlite3.Error as error:
        print(f"Error Occured {error}")


def close_db(cursor,conn):
    try:
        conn.commit()
        cursor.close()
    except sqlite3.Error as error:
        print(f"Error Occured {error}")
    finally:
        if conn:
            conn.close()
            print("Connection is closed")

### POST ROUTES 

@app.route('/scanApk',methods=['POST'])
def addApp():
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        jwt_token = auth_header.split(" ")[1]
    else:
        return {"error": "No JWT Token send"}, 401

    if 'file' not in request.files:
        return jsonify({'Error':'No file part'}), 400
    file = request.files['file']
    if file == '':
        return jsonify({'Error':'No file uploaded'}), 400
    
    #Adds the file into the Uploads folder
    filepath = os.path.join(MALWARE_FOLDER, file.filename)
    file.save(filepath)
    
    #Database Init
    conn,cursor = db_init()
    
    id = id_gen()
    #Update the database
    insert_data(cursor,id,jwt_token,'Malware',filepath,'Pending','/output/report.pdf',60,None)
    
    #Printing the database
    for i in print_all_data(cursor):
        print(i)
    
    #Closing Database
    close_db(cursor,conn)
    return jsonify({'jobID':id}), 201    


@app.route('/scanMessage',methods=['POST'])
def addMessage():
    #Getting JWT Token
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        jwt_token = auth_header.split(" ")[1]
    else:
        return {"error": "No JWT Token send"}, 401

    #Generating Job
    id = id_gen()

    #Text file created and wrote
    msg = request.form.get('message')
    filepath = os.path.join(PHISHING_FOLDER,f"message_{id}.txt")    
    with open(filepath, "w") as f:
        f.write(msg)

    #Database Init
    conn,cursor = db_init()
    
    #Update the database
    insert_data(cursor,id,jwt_token,'Phishing',filepath,'Pending','/output/report.pdf',60,None)
    
    #Printing the database
    for i in print_all_data(cursor):
        print(i)
    
    #Closing Database
    close_db(cursor,conn)
    return jsonify({'jobID':id}), 201 

@app.route('/scanStatus')
def getJob():
    conn,cursor = db_init()
    id = request.args['jobID']
    
    #Getting JWT Token
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        user_jwt_token = auth_header.split(" ")[1]
    else:
        return {"error": "No JWT Token send"}, 401
    
    cursor.execute("SELECT * FROM data WHERE JOB_ID = ?",(id,))
    row = cursor.fetchone()
    print(row)
    if row :
        data = {
            "JOB_ID": row[0],
            "JWT_TOKEN": row[1],
            "TYPE": row[2],
            "INPUT_FILE_PATH": row[3],
            "STATUS": row[4],
            "OUTPUT_FILE_PATH": row[5],
            "CONFIDENCE": row[6],
            "DETECTION": row[7]
        }
    else:
        return {"error": "Job not found"}, 404

    if user_jwt_token == row[1]:
        return{'details':data}
    else:
        return{'error': 'You cannot access this Job'}
    

if __name__ == '__main__':
    app.run(debug=True)
