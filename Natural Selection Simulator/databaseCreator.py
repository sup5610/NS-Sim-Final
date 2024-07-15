import sqlite3, hashlib, secrets
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive

# gauth = GoogleAuth()
# gauth.LocalWebserverAuth()

def CreateDatabase(databasePath, databaseCreatorSQL):
    con = sqlite3.connect(databasePath)
    cur = con.cursor()

    fd = open(databaseCreatorSQL, "r") # opens sql file in read mode
    sqlFile = fd.read()
    fd.close()

    sqlCommands = sqlFile.split(";")

    for command in sqlCommands:
        cur.execute(command)

    con.commit()
    con.close()

def CreateDefaultUsers(databasePath):
        con = sqlite3.connect(databasePath)
        cur = con.cursor()

        password = "12345"

        userPreSalt = secrets.token_hex(16)
        userPostSalt = secrets.token_hex(16)
        userSaltedPassword = userPreSalt + password + userPostSalt
        userHashedPassword = hashlib.sha512(userSaltedPassword.encode()).hexdigest()

        adminPreSalt = secrets.token_hex(16)
        adminPostSalt = secrets.token_hex(16)
        adminSaltedPassword = adminPreSalt + password + adminPostSalt
        adminHashedPassword = hashlib.sha512(adminSaltedPassword.encode()).hexdigest()

        userDetails = ["user1", userHashedPassword, userPreSalt, userPostSalt, 0]
        adminDetails = ["admin1", adminHashedPassword, adminPreSalt, adminPostSalt, 1]

        cur.execute("INSERT INTO login (USERNAME, HASHED_PASS, PRE_SALT, POST_SALT, ADMIN) VALUES (?, ?, ?, ?, ?)", userDetails)
        cur.execute("INSERT INTO login (USERNAME, HASHED_PASS, PRE_SALT, POST_SALT, ADMIN) VALUES (?, ?, ?, ?, ?)", adminDetails)

        con.commit()
        con.close()