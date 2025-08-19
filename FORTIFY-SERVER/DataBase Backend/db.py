import sqlite3
import random 

def id_gen():
    return random.randint(1000,9999)

def print_all_data(cursor):
    res = cursor.execute("SELECT * FROM data")
    return res

def delete_data(cursor):
    cursor.execute("DELETE FROM data")

def insert_data(cursor,id,token,type,input_path,status,output_path,confidence,detection):
    cursor.execute("INSERT INTO data VALUES (?, ?, ?, ?, ?, ?, ?, ?)",(id, token, type, input_path, status, output_path, confidence, detection))

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


def db_init():
    try:
        conn = sqlite3.connect("example.db")
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

        return conn,cursor
    except sqlite3.Error as error:
        print(f"Error Occured {error}")
