import sqlite3

def check_malicious_signatures(signatures):
    db_path = 'signaturesdb.sqlite'
    
    # Connect to the SQLite database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    hashes = [signature[1] for signature in signatures]
    placeholders = ', '.join(['?'] * len(hashes))  # Generates a string like '?, ?, ?'
    query = f"SELECT hash, name FROM HashDB WHERE hash IN ({placeholders})"

    cursor.execute(query, hashes)
    result = cursor.fetchall()
    conn.close()

    malicious_hashes = []

    for row in result:
        hash_value, name = row
        # Find the corresponding file name from the signatures list
        file_name = next(file_name for file_name, file_hash in signatures if file_hash == hash_value)
        malicious_hashes.append({"file_name": file_name, "hash": hash_value, "name": name})

    return malicious_hashes


# Example usage
signatures = [
    ("note.txt", "f4c3fa43b5bdfaa0205990d25ce51c5a"),
    ("iloveyou.exe", "3e9rweb6689a7d400e140c788erwed6f54e73"),
    ("gta5.apk", "e89we9689a7d400e140c788e71rete5e73"),
    ("minecraftfree.apk", "few89wb6689a7d400e140c788eert89d4e73"),
    ("clashofclans.apk", "aqwedb6689a7d400e140c788e711erte73"),
    ("spotifypremium.pdf", "qwewdb6689a7d400e140c788e711er7d73"),
    ("freeloan.doc", "beb27eb5b542c19db60e3a5cbert749bd31")
]

malicious_signatures = check_malicious_signatures(signatures)

if malicious_signatures:
    for malicious in malicious_signatures:
        print(f"Malicious file found: {malicious['file_name']} - {malicious['hash']} - {malicious['name']}")
else:
    print("No malicious files found.")
