from flask import Flask, request, jsonify
import os
import db

app = Flask(__name__)

UPLOADS_FOLDER = 'uploads'
os.makedirs(UPLOADS_FOLDER, exist_ok=True)

@app.route('/scanApk',methods=['POST'])
def addApp():
    if 'file' not in request.files:
        return jsonify({'Error':'No file part'}), 400
    file = request.files['file']
    if file == '':
        return jsonify({'Error':'No file uploaded'}), 400
    
    #Adds the file into the Uploads folder
    filepath = os.path.join(UPLOADS_FOLDER, file.filename)
    file.save(filepath)
    

    conn,cursor = db.db_init()
    #Update the database
    for i in db.print_all_data(cursor):
        print(i)
    db.insert_data(cursor,db.id_gen(),'token','Malware',filepath,'Pending','/output/report.pdf',60,None)
    db.close_db(cursor,conn)
    return jsonify({'message':'App Saved'}), 201    

if __name__ == '__main__':
    app.run(debug=True)
