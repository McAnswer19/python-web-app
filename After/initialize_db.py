import sqlite3
import hashlib

db_connection = sqlite3.connect("traffic_db")
db_cursor = db_connection.cursor()

db_cursor.execute("""CREATE TABLE IF NOT EXISTS usernames_and_passwords(
                      username TEXT UNIQUE NOT NULL,
                      password TEXT NOT NULL);""")

usernames_list = ["test", "test1", "test2", "test3", "test4", "test5", "test6", "test7", "test8", "test9", "test10"]
passwords_list = ["1234567890", "password1", "password2", "password3", "password4", "password5", "password6",
                    "password7",
                    "password8", "password9", "password10"]

# This loop traverse each username/password pair and inserts them. Eventually instead of hard-coded lists these
# Will be stored as an external db
for i in range(len(usernames_list)):
    sha256 = hashlib.sha256()
    sha256.update(passwords_list[i].encode())
    hashed_password = str(sha256.digest())
    db_cursor.execute("""INSERT INTO usernames_and_passwords VALUES(?, ?) """, (usernames_list[i], hashed_password))

db_connection.commit()



# Other tables start here . ---------------------------------------------------------------------------

db_cursor.execute("""CREATE TABLE IF NOT EXISTS iuser_tokens(
                      username TEXT NOT NULL,
                      iuser_token INTEGER NOT NULL );""")

db_connection.commit()


  # Creating table with login/logout times:
db_cursor.execute("""CREATE TABLE IF NOT EXISTS start_and_end_times(
                        username TEXT NOT NULL,
                        iuser_token INTEGER NOT NULL,
                        start_time TEXT NOT NULL,
                        end_time TEXT NOT NULL);""")

db_connection.commit()

  # The vehicle obsercation table.
db_cursor.execute("""CREATE TABLE IF NOT EXISTS vehicle_observations(
                        order_added INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        iuser_token INTEGER NOT NULL,
                        location TEXT NOT NULL,
                        vehicle_type TEXT NOT NULL,
                        occupancy INTEGER NOT NULL,
                        time TEXT NOT NULL,
                        undone INTEGER NOT NULL CHECK (undone IN (0,1)));""")    # DO we want an undo feature here???

db_connection.commit()



