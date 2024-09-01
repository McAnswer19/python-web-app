# Python_Web_App


![alt text](https://github.com/McAnswer19/Python_Web_APP/blob/master/web_app_pages.png)

A web application with a Python backend. Specifically, a web application for recording traffic data by volunteers for entry into a SQL database. Also included was a python script that takes two dates as arguments and creates a CSV file with all traffic between those dates sorted by location and vehicle type for easy reference. 

This was part of a class project where we were provided with the starting HTML, CSS, and JavaScript files and had to provide most of the rest of the code ourselves. The folder entitled "Before" shows what files we were provided with, and the folder "After" contains my personal code for the finished project. 

Overall, this was a great coding project. I appreciated being able to combine Python with HTML and building the various event handlers was a pretty deep challenge. Making the query program was also a great experience as there was a lot of creativity there in how you could handle things, and I think my implementation was pretty elegant overall. 

To use the application, run "server.py" and then check http://127.0.0.1:8081/ using any browser. If the traffic database file is lost or corrupted, a new one can be made by running "initialize_db.py". The program should also be immune to most basic SQL injections, but it is possible that I overlooked something. "initialize_db.py" also contains a hard-coded list of usernames and passwords that are entered into the database when it is created. a vaid username/password combination for logging in is "test2" and "password2". 
