#!/usr/bin/env python

# This is a simple web server for a traffic counting application.
# It's your job to extend it by adding the backend functionality to support
# recording the traffic in a SQL database. You will also need to support
# some predefined users and access/session control. You should only
# need to extend this file. The client side code (html, javascript and css)
# is complete and does not require editing or detailed understanding.

# import the various libraries needed
import http.cookies as Cookie # some cookie handling support
from http.server import BaseHTTPRequestHandler, HTTPServer # the heavy lifting of the web server
import urllib # some url parsing support
import base64 # some encoding support
import sqlite3
import hashlib
import numpy.random
import datetime

def initialize_tables():
  global db_connection
  global db_cursor

  #  Creating an empty table to holder the iuser_tokens
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


def update_start_and_end_times(direction, username, iuser):
  """Helper function for updating the table of login/logout times."""
  global db_connection
  global db_cursor

  current_time = datetime.datetime.now()

  # Direction is whether we are updating the start of a record
  # Or putting the endtime on a record that already has a start time.
  if direction == "start":

    db_cursor.execute("""INSERT INTO start_and_end_times 
                          (username, iuser_token, start_time, end_time) 
                          VALUES (?, ?, ?, ?);""",
                          (username, iuser, current_time.strftime("%Y-%m-%d %H:%M:%S"),  "PLACEHOLDER"))
    db_connection.commit()


  elif direction == "end":
    db_cursor.execute("""SELECT * FROM start_and_end_times WHERE 
                      username = ? AND 
                      iuser_token = ? AND
                      end_time = ?""",
                      (username, iuser, "PLACEHOLDER"))

    # Making sure an incomplete record exists in the first place. if not,
    # something has gone wrong.
    assert len(db_cursor.fetchall()) > 0

    db_cursor.execute("""UPDATE start_and_end_times SET end_time = ? WHERE
                      username = ? AND 
                      iuser_token = ? """,
                      (current_time.strftime("%Y-%m-%d %H:%M:%S"), username, iuser ))
    db_connection.commit()


  else:
    raise Exception("Invalid direction value")


def sql_stripper(raw_string_input):
  """This is a helper function for guarding against basic SQL injections."""
  raw_string_input = raw_string_input.replace(" ", "")
  raw_string_input = raw_string_input.replace("*", "")
  raw_string_input = raw_string_input.replace("\'", "")
  cleansed_string = raw_string_input.replace("\"", "")

  return(cleansed_string)


def check_valid_username_and_password(entered_username, entered_password):
  global db_connection
  global db_cursor

  sha256 = hashlib.sha256()
  sha256.update(entered_password.encode())
  hashed_password = str(sha256.digest())

  db_cursor.execute("""SELECT * FROM usernames_and_passwords WHERE username = ? AND password = ?""",
                    (entered_username, hashed_password))

  results = db_cursor.fetchall()

  # If the length is equal to one, then that means at one record returns true.
  # Therefore the username/password exists in the table and the username/password combo is valid.
  if len(results) ==  1:
    return (True)
  else:
    return (False)


# This function builds a refill action that allows part of the
# currently loaded page to be replaced.
def build_response_refill(where,what):
    text = "<action>\n"
    text += "<type>refill</type>\n"
    text += "<where>"+where+"</where>\n"
    m = base64.b64encode(bytes(what,'ascii'))
    text += "<what>"+str(m,'ascii')+"</what>\n"
    text += "</action>\n"
    return text


# This function builds the page redirection action
# It indicates which page the client should fetch.
# If this action is used, only one instance of it should
# contained in the response and there should be no refill action.
def build_response_redirect(where):
    text = "<action>\n"
    text += "<type>redirect</type>\n"
    text += "<where>"+where+"</where>\n"
    text += "</action>\n"
    return text

## Decide if the combination of user and magic is valid
def handle_validate(iuser, imagic):
  global db_cursor

  sanitized_iuser = sql_stripper(iuser)
  sanitized_imagic = sql_stripper(imagic)

  db_cursor.execute("""SELECT * FROM iuser_tokens WHERE username = ? AND iuser_token = ?""",
                    (sanitized_iuser, sanitized_imagic))

  results = db_cursor.fetchall()

  if len(results)  == 1:  # One match for one user.
    return(True)
  else:
    return(False)

## remove the combination of user and magic from the data base, ending the login
def handle_delete_session(iuser, imagic):
  # Just returns null. Should work with everything else.
  return

## A user has supplied a username (parameters['usernameinput'][0])
## and password (parameters['passwordinput'][0]) check if these are
## valid and if so, create a suitable session record in the database
## with a random magic identifier that is returned.
## Return the username, magic identifier and the response action set.
def handle_login_request(iuser, imagic, parameters):
  global db_cursor
  global db_connection

  if ('usernameinput' in parameters and "passwordinput" in parameters):

    # The text from the username/passwords field.
    username_input = sql_stripper(parameters['usernameinput'][0])
    password_input = sql_stripper(parameters['passwordinput'][0])

    # variable to hold any (visible) text sent to the webpage.
    text = "<response>\n"

    # the user is already logged in, so end the existing session.
    if (handle_validate(iuser, imagic) == True):
      handle_delete_session(iuser, imagic)


    ## The user is valid
    if (check_valid_username_and_password(username_input, password_input) == True):

      hash_object = hashlib.sha256(username_input.encode())

      # id_token range is kept small (to work with sqlite types). Should work for now, but does not scale.
      id_token = hash_object.hexdigest()
      id_token = int(id_token, 16)
      id_token = (id_token % 2**25) + numpy.random.randint(0, 2**25)

      db_cursor.execute("""INSERT INTO iuser_tokens (username, iuser_token) VALUES (?, ?);""",
                        (username_input, id_token))

      db_connection.commit()


      update_start_and_end_times(direction= "start", username = username_input, iuser = id_token)

      text += build_response_redirect('/page.html')
      user  = username_input
      magic = id_token

    ## The user is not valid
    else:
      text += build_response_refill('message', 'Invalid password')
      user = '!'
      magic = ''
    text += "</response>\n"

  # There was no login information found, report that to the user.
  else:
    text = "<response>\n"
    text += build_response_refill('message', 'Internal Error: Insufficient login information found.')
    text += "</response>\n"
    user = "!"
    magic = ''
  return [user, magic, text]

## The user has requested a vehicle be added to the count
## parameters['locationinput'][0] the location to be recorded
## parameters['occupancyinput'][0] the occupant count to be recorded
## parameters['typeinput'][0] the type to be recorded
## Return the username, magic identifier (these can be empty  strings) and the response action set.
def handle_add_request(iuser, imagic, parameters):
  global db_cursor
  global db_connection

  location = ""
  current_time = datetime.datetime.now()

  # Location is an optional parameters: the others have to exist because of the way
  # the radio buttons are set up.
  if "locationinput" in parameters: location = " ".join(parameters["locationinput"])

  location = sql_stripper(location)
  iuser = sql_stripper(iuser)
  imagic = sql_stripper(imagic)

  db_cursor.execute("INSERT INTO  vehicle_observations (username, iuser_token, location, vehicle_type, "
                    "occupancy, time, undone) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (iuser, int(imagic), location, parameters["typeinput"][0], int(parameters["occupancyinput"][0]),
                     current_time.strftime("%Y-%m-%d %H:%M:%S"), 0))
  db_connection.commit()

  # Getting the total number of vehicles seen so far.
  db_cursor.execute("""SELECT * FROM vehicle_observations WHERE undone = ?""", (0, ))
  total = len(db_cursor.fetchall())

  text  = "<response>\n"
  if (handle_validate(iuser, imagic) != True):
    text += build_response_redirect('/index.html') #Invalid sessions redirect to login
  else: ## a valid session so process the addition of the entry.
    text += build_response_refill('message', '{0} added.'.format(parameters["typeinput"][0]))
    text += build_response_refill('total', str(total))
  text += "</response>\n"
  user = ''
  magic = ''

  return [user,magic,text]

## The user has requested a vehicle be removed from the count
## This is intended to allow counters to correct errors.
## parameters['locationinput'][0] the location to be recorded
## parameters['occupancyinput'][0] the occupant count to be recorded
## parameters['typeinput'][0] the type to be recorded
## Return the username, magic identifier (these can be empty  strings) and the response action set.
def handle_undo_request(iuser, imagic, parameters):
  global db_cursor
  global db_connection

  # Location is an optional parameters: the others have to exist because of the way
  # the radio buttons are set up.
  location = ""
  if "locationinput" in parameters: location = " ".join(parameters["locationinput"])

  location = sql_stripper(location)
  iuser = sql_stripper(iuser)
  imagic = sql_stripper(imagic)

  # Checking to see if at least one such record exists. A given record has to exist before we can undo it.
  db_cursor.execute("""SELECT * FROM vehicle_observations
                    WHERE 
                    username = ? AND
                    iuser_token = ? AND
                    location = ? AND
                    vehicle_type = ? AND
                    occupancy = ? AND
                    undone = ?""", (iuser, imagic, location, parameters["typeinput"][0],
                                          parameters["occupancyinput"][0], 0))
  if len(db_cursor.fetchall()) > 0:

    # More recent records always have a larger index (order_added) value. Kind of a kludge, but it works.
    db_cursor.execute("""SELECT MAX(order_added) FROM vehicle_observations
                    WHERE 
                    username = ? AND
                    iuser_token = ? AND
                    location = ? AND
                    vehicle_type = ? AND
                    occupancy = ? AND
                    undone = ?""", (iuser, imagic, location, parameters["typeinput"][0],
                                          parameters["occupancyinput"][0], 0))

    update_indice = db_cursor.fetchall()[0][0]

    db_cursor.execute(""" UPDATE vehicle_observations SET undone = 1 WHERE order_added = ?""", (update_indice, ))

    message_text = """Record with parameters username: {0} location: {1} 
                    vehicle type: {2}, occupancy: {3} removed from table.""".format(iuser, location,
                                              parameters["typeinput"][0],parameters["occupancyinput"][0])

    db_cursor.execute("""SELECT *  FROM vehicle_observations WHERE undone = 0""")
    total_text = str(len(db_cursor.fetchall()))


  else:
    # There is no matching record to be undone, so do not change anything.
    message_text = "Nothing undone: No matching record found."


    db_cursor.execute("""SELECT * FROM vehicle_observations WHERE undone = 0""")
    total_text  = str(len(db_cursor.fetchall()))


  text  = "<response>\n"
  if (handle_validate(iuser, imagic) != True): #Invalid sessions redirect to login
    text += build_response_redirect('/index.html')
  else: ## a valid session so process the recording of the entry.
    text += build_response_refill('message', message_text)          # Message text is displayed to user.
    text += build_response_refill('total', total_text)              # Total text is the # of valid records.
  text += "</response>\n"
  user = ''
  magic = ''
  return [user,magic,text]

# This code handles the selection of the back button on the record form (page.html)
# You will only need to modify this code if you make changes elsewhere that break its behaviour
def handle_back_request(iuser,imagic,parameters):
  text  = "<response>\n"
  if (handle_validate(iuser, imagic) != True):
    text += build_response_redirect('/index.html')
  else:
    text += build_response_redirect('/summary.html')
  text += "</response>\n"
  user = ''
  magic = ''
  return [user,magic,text]

## This code handles the selection of the logout button on the summary page (summary.html)
## You will need to ensure the end of the session is recorded in the database
## And that the session magic is revoked.
def handle_logout_request(iuser,imagic,parameters):

  # parameters does nothing in this function. I believe this was Ken's intent.

  iuser = sql_stripper((iuser))
  imagic = sql_stripper((imagic))

  update_start_and_end_times(direction= "end", username = iuser, iuser = imagic)


  text  = "<response>\n"
  text += build_response_redirect('/index.html')
  user  = '!'
  magic = ''
  text += "</response>\n"
  return [user,magic,text]

## This code handles a request for update to the session summary values.
## You will need to extract this information from the database.
def handle_summary_request(iuser,imagic,parameters):
  global db_cursor

  text  = "<response>\n"
  if (handle_validate(iuser, imagic) != True):  # They fail the handle validate, redirect them.
    text += build_response_redirect('/index.html')
  else:

    list_of_vehicle_types =["car", "taxi", "bus", "motorbike", "bicycle", "van", "truck", "other", "total"]
    totals_list = []

    # Traverse the list of vehicles, find the number of matching records for each vehicle type, and
    # then append to an external list
    for vehicle in list_of_vehicle_types:
      if vehicle == "total": # This only executes last, so the total should be correct.
        totals_list.append(sum(totals_list))
      else:
        db_cursor.execute("""SELECT * FROM vehicle_observations WHERE
                          undone = 0 AND
                           vehicle_type = ?""", (vehicle, ))
        totals_list.append(len(db_cursor.fetchall()))

    # Building the text.
    text += build_response_refill('sum_car', str(totals_list[0]))
    text += build_response_refill('sum_taxi', str(totals_list[1]))
    text += build_response_refill('sum_bus', str(totals_list[2]))
    text += build_response_refill('sum_motorbike', str(totals_list[3]))
    text += build_response_refill('sum_bicycle', str(totals_list[4]))
    text += build_response_refill('sum_van', str(totals_list[5]))
    text += build_response_refill('sum_truck', str(totals_list[6]))
    text += build_response_refill('sum_other', str(totals_list[7]))
    text += build_response_refill('sum_total', str(totals_list[8]))
  text += "</response>\n"
  user = ''
  magic = ''
  return [user,magic,text]


# HTTPRequestHandler class
class myHTTPServer_RequestHandler(BaseHTTPRequestHandler):
 
  # GET This function responds to GET requests to the web server.
  def do_GET(self):

    # The set_cookies function adds/updates two cookies returned with a webpage.
    # These identify the user who is logged in. The first parameter identifies the user
    # and the second should be used to verify the login session.
    def set_cookies(x,user, magic):
      ucookie = Cookie.SimpleCookie()
      ucookie['u_cookie'] = user
      x.send_header("Set-Cookie", ucookie.output(header='', sep=''))
      mcookie = Cookie.SimpleCookie()
      mcookie['m_cookie'] = magic
      x.send_header("Set-Cookie", mcookie.output(header='', sep=''))

    # The get_cookies function returns the values of the user and magic cookies if they exist
    # it returns empty strings if they do not.
    def get_cookies(x):
      rcookies = Cookie.SimpleCookie(x.headers.get('Cookie'))
      user=''
      magic=''
      for keyc, valuec in rcookies.items():
        if (keyc == 'u_cookie'):
          user = valuec.value
        if (keyc == 'm_cookie'):
          magic = valuec.value
      return [user,magic]

    # Fetch the cookies that arrived with the GET request
    # The identify the user session.
    um = get_cookies(self)

    # Parse the GET request to identify the file requested and the GET parameters
    parsed_path = urllib.parse.urlparse(self.path)

    # Decided what to do based on the file requested.

    # Return a CSS (Cascading Style Sheet) file. These tell the web client how the page should appear.
    if(self.path.startswith('/css')):
      self.send_response(200)
      self.send_header('Content-type','text/css')
      self.end_headers()
      with open('.'+self.path, 'rb') as file: 
        self.wfile.write(file.read())

    # Return a Javascript file. These tell contain code that the web client can execute.
    if(self.path.startswith('/js')):
      self.send_response(200)
      self.send_header('Content-type','text/js')
      self.end_headers()
      with open('.'+self.path, 'rb') as file: 
        self.wfile.write(file.read())

    # A special case of '/' means return the index.html (homepage) of a website
    elif(parsed_path.path == '/'):
      self.send_response(200)
      self.send_header('Content-type','text/html')
      self.end_headers()
      with open('./index.html', 'rb') as file: 
        self.wfile.write(file.read())
        file.close()

    # Return html pages.
    elif(parsed_path.path.endswith('.html')):
      self.send_response(200)
      self.send_header('Content-type','text/html')
      self.end_headers()
      with open('.'+parsed_path.path, 'rb') as file: 
        self.wfile.write(file.read())
        file.close()

    # The special file 'action' is not a real file, be indicates an action
    # we wish the server to execute.
    elif (parsed_path.path == '/action'):
      self.send_response(200) #respond that this is a valid page request

      # extract the parameters from the GET request. These are passed to the
      # handlers.
      parameters = urllib.parse.parse_qs(parsed_path.query)

      if ('command' in parameters): # check if one of the parameters was 'command'
        # If it is, identify which command and call the appropriate handler function.
        if (parameters['command'][0] == 'login'):
          [user,magic,text] = handle_login_request(um[0],um[1],parameters)
          #The result to a login attempt will be to set the cookies to identify the session.
          set_cookies(self,user,magic)
        elif (parameters['command'][0] == 'add'):
          [user,magic,text] = handle_add_request(um[0],um[1],parameters)
          if(user == '!'): # Check if we've been tasked with discarding the cookies.
            set_cookies(self,'','')
        elif (parameters['command'][0] == 'undo'):
          [user,magic,text] = handle_undo_request(um[0],um[1],parameters)
          if(user == '!'): # Check if we've been tasked with discarding the cookies.
            set_cookies(self,'','')
        elif (parameters['command'][0] == 'back'):
          [user,magic,text] = handle_back_request(um[0],um[1],parameters)
          if(user == '!'): # Check if we've been tasked with discarding the cookies.
            set_cookies(self,'','')
        elif (parameters['command'][0] == 'summary'):
          [user,magic,text] = handle_summary_request(um[0],um[1],parameters)
          if(user == '!'): # Check if we've been tasked with discarding the cookies.
            set_cookies(self,'','')
        elif (parameters['command'][0] == 'logout'):
          [user,magic,text] = handle_logout_request(um[0],um[1],parameters)
          if(user == '!'): # Check if we've been tasked with discarding the cookies.
            set_cookies(self,'','') 
        else:
          # The command was not recognised, report that to the user.
          text  = "<response>\n"
          text += build_response_refill('message','Internal Error: Command not recognised.')
          text += "</response>\n"

      else:
          # There was no command present, report that to the user.
          text  = "<response>\n"
          text += build_response_refill('message','Internal Error: Command not found.')
          text += "</response>\n"
      self.send_header('Content-type', 'application/xml')
      self.end_headers()
      self.wfile.write(bytes(text,'utf-8'))
    else:
      # A file that does n't fit one of the patterns above was requested.
      self.send_response(404)
      self.end_headers()
    return
 
# This is the entry point function to this code.
def run():
  print('starting server...')
  ## You can add any extra start up code here
  # Server settings, etc.
  # Choose port 8081 over port 80, which is normally used for a http server
  server_address = ('127.0.0.1', 8081)
  httpd = HTTPServer(server_address, myHTTPServer_RequestHandler)
  print('running server...')
  httpd.serve_forever() # This function will not return till the server is aborted.


# Connect to the database. db_connection and db_cursor will be global variables for any function that needs
# to access or modify the data database.
db_connection = sqlite3.connect("traffic_db")
db_cursor = db_connection.cursor()

# initialize_tables will initialize all tables in the database. The sole exception is the usernames and
# (hashed) passwords table, which is pre-loaded into the db for security reasons. Sha256 is not secure enough for
# production code, but it is good enough in this case.
initialize_tables()

# Run forever.
run()

