# from imports import *
# import os
# from tkinter import filedialog,messagebox
# import tkinter as tk
# import smtplib
# import random
# from email.mime.text import MIMEText
# from email.mime.multipart import MIMEMultipart
# import json
# import pymysql

# def connect_to_database(host, user, password, database):
#     try:
#         connection = pymysql.connect(
#             host=host,
#             user=user,
#             password=password,
#             database=database
#         )
#         print("Connection successful")
#         return connection
#     except pymysql.MySQLError as e:
#         print(f"Error connecting to the database: {e}")
#         return None

# def execute_query(connection, query, params=None):
#     try:
#         with connection.cursor() as cursor:
#             cursor.execute(query, params)
#             connection.commit()
#             result = cursor.fetchall()
#             return result
#     except pymysql.MySQLError as e:
#         print(f"Error executing query: {e}")
#         return None

# def close_connection(connection):
#     if connection:
#         connection.close()
#         print("Connection closed")


# if len(sys.argv) > 1 and sys.argv[1] == "-cli":
#     print("Starting command line chat")
#     isCLI = True
# else:
#     isCLI = False

        
# # GLOBALS
# commands = ["nick","connect","disconnect","host"]
# conn_array = []  # stores open sockets
# secret_array = dict()  # key: the open sockets in conn_array,
#                         # value: integers for encryption
# username_array = dict()  # key: the open sockets in conn_array,
#                         # value: usernames for the connection
# contact_array = dict()  # key: ip address as a string, value: [port, username]
 
# username = "Self"
 
# location = 0
# port = 0
# top = ""

# is_hinted=False

# main_body_text = 0
# #-GLOBALS-
 
# # So,
#    #  x_encode your message with the key, then pass that to
#    #  refract to get a string out of it.
#    # To decrypt, pass the message back to x_encode, and then back to refract
 
# def binWord(word):
#     """Converts the string into binary."""
#     master = ""
#     for letter in word:
#         temp = bin(ord(letter))[2:]
#         while len(temp) < 7:
#             temp = '0' + temp
#         master = master + temp
#     return master
 
# def xcrypt(message, key):
#     """Encrypts the binary message by the binary key."""
#     count = 0
#     master = ""
#     for letter in message:
#         if count == len(key):
#             count = 0
#         master += str(int(letter) ^ int(key[count]))
#         count += 1
#     return master
 
# def x_encode(string, number):
#     """Encrypts the string by the number."""
#     return xcrypt(binWord(string), bin(number)[2:])
 
# def refract(binary):
#     """Returns the string representation of the binary.
#     Has trouble with spaces.
 
#     """
#     master = ""
#     for x in range(0, int(len(binary) / 7)):
#         master += chr(int(binary[x * 7: (x + 1) * 7], 2) + 0)
#     return master
 
 
# def formatNumber(number):
#     """
    
#     Ensures that number is at least length 4 by
#     adding extra 0s to the front.
 
#     """
#     temp = str(number)
#     while len(temp) < 4:
#         temp = '0' + temp
#     return temp
 
# def netThrow(conn, secret, message):
#     """
#     Sends message through the open socket conn with the encryption key
#     secret. Sends the length of the incoming message, then sends the actual
#     message.
 
#     """
#     try:
#         conn.send(formatNumber(len(x_encode(message, secret))).encode())
#         conn.send(x_encode(message, secret).encode())
#     except socket.error:
#         if len(conn_array) != 0:
#             writeToScreen(
#                 "Connection issue. Sending message failed.", "System")
#             processFlag("-001")
 
# def netCatch(conn, secret):
#     """
    
#     Receive and return the message through open socket conn, decrypting
#     using key secret. If the message length begins with - instead of a number,
#     process as a flag and return 1.
 
#     """
#     try:
#         data = conn.recv(4)
#         if data.decode()[0] == '-': 
#             processFlag(data.decode(), conn)
#             return 1
#         data = conn.recv(int(data.decode()))
#         return refract(xcrypt(data.decode(), bin(secret)[2:]))
#     except socket.error:
#         if len(conn_array) != 0:
#             writeToScreen(
#                 "Connection issue. Receiving message failed.", "System")
#         processFlag("-001")
 
# def isPrime(number):
#     """Checks to see if a number is prime."""
#     x = 1
#     if number == 2 or number == 3:
#         return True
#     while x < math.sqrt(number):
#         x += 1
#         if number % x == 0:
#             return False
#     return True
 
# def processFlag(number, conn=None):
#     """Process the flag corresponding to number, using open socket conn
#     if necessary.
 
#     """
#     global statusConnect
#     global conn_array
#     global secret_array
#     global username_array
#     global contact_array
#     global isCLI
#     t = int(number[1:])
#     if t == 1:  # disconnect
#         # in the event of single connection being left or if we're just a
#         # client
#         if len(conn_array) == 1:
#             writeToScreen("Connection closed.", "System")
#             dump = secret_array.pop(conn_array[0])
#             dump = conn_array.pop()
#             try:
#                 dump.close()
#             except socket.error:
#                 print("Issue with someone being bad about disconnecting")
#             if not isCLI:
#                 statusConnect.set("Connect")
#                 connecter.config(state=NORMAL)
#             return
 
#         if conn != None:
#             writeToScreen("Connect to " + conn.getsockname()
#                           [0] + " closed.", "System")
#             dump = secret_array.pop(conn)
#             conn_array.remove(conn)
#             conn.close()
 
#     if t == 2:  # username change
#         name = netCatch(conn, secret_array[conn])
#         if(isUsernameFree(name)):
#             writeToScreen(
#                 "User " + username_array[conn] + " has changed their username to " + name, "System")
#             username_array[conn] = name
#             contact_array[
#                 conn.getpeername()[0]] = [conn.getpeername()[1], name]
 

#     if t == 4:
#         data = conn.recv(4)
#         data = conn.recv(int(data.decode()))
#         Client(data.decode(),
#                int(contact_array[conn.getpeername()[0]][0])).start()
 
# def processUserCommands(command, param):
#     """Processes commands passed in via the / text input."""
#     global conn_array
#     global secret_array
#     global username

    
        
 
#     if command == "nick":  # change nickname
#         for letter in param[0]:
#             if letter == " " or letter == "\n":
#                 if isCLI:
#                     error_window(0, "Invalid username. No spaces allowed.")
#                 else:
#                     error_window(root, "Invalid username. No spaces allowed.")
#                 return
#         if isUsernameFree(param[0]):
#             writeToScreen("Username is being changed to " + param[0], "System")
#             for conn in conn_array:
#                 conn.send("-002".encode())
#                 netThrow(conn, secret_array[conn], param[0])
#             username = param[0]
#         else:
#             writeToScreen(param[0] +
#                           " is already taken as a username", "System")
#     if command == "disconnect":  # disconnects from current connection
#         for conn in conn_array:
#             conn.send("-001".encode())
#         processFlag("-001")
#     if command == "connect":  # connects to passed in host port
#         if(options_sanitation(param[1], param[0])):
#             Client(param[0], int(param[1])).start()
#     if command == "host":  # starts server on passed in port
#         if(options_sanitation(param[0])):
#             Server(int(param[0])).start()
 
# def isUsernameFree(name):
#     """Checks to see if the username name is free for use."""
#     global username_array
#     global username
#     for conn in username_array:
#         if name == username_array[conn] or name == username:
#             return False
#     return True
 
# def passFriends(conn):
#     """
    
#     Sends conn all of the people currently in conn_array so they can connect
#     to them.
    
#     """
#     global conn_array
#     for connection in conn_array:
#         if conn != connection:
#             conn.send("-004".encode())
#             conn.send(
#                 formatNumber(len(connection.getpeername()[0])).encode())  # pass the ip address
#             conn.send(connection.getpeername()[0].encode())
#             # conn.send(formatNumber(len(connection.getpeername()[1])).encode()) #pass the port number
#             # conn.send(connection.getpeername()[1].encode())
 
# #--------------------------------------------------------------------------
 
# def client_options_window(master):
#     """
    
#     Launches client options window for getting destination hostname
#     and port.
 
#     """
#     top = Toplevel(master)
#     top.title("Connection options")
#     top.protocol("WM_DELETE_WINDOW", lambda: optionDelete(top))
#     top.grab_set()
#     Label(top, text="Server IP:").grid(row=0)
#     location = Entry(top)
#     location.grid(row=0, column=1)
#     location.focus_set()
#     Label(top, text="Port:").grid(row=1)
#     port = Entry(top)
#     port.grid(row=1, column=1)
#     go = Button(top, text="Connect", command=lambda:
#                 client_options_go(location.get(), port.get(), top))
#     go.grid(row=2, column=1)
 
# def client_options_go(dest, port, window):
#     "Processes the options entered by the user in the client options window."""
#     if options_sanitation(port, dest):
#         if not isCLI:
#             window.destroy()
#         Client(dest, int(port)).start()
#     elif isCLI:
#         sys.exit(1)
 
# def options_sanitation(por, loc=""):
#     """
    
#     Checks to make sure the port and destination ip are both valid.
#     Launches error windows if there are any issues.
 
#     """
#     global root
#     if version == 2:
#         por = unicode(por)
#     if isCLI:
#         root = 0
#     if not por.isdigit():
#         error_window(root, "Please input a port number.")
#         return False
#     if int(por) < 0 or 65555 < int(por):
#         error_window(root, "Please input a port number between 0 and 65555")
#         return False
#     if loc != "":
#         if not ip_process(loc.split(".")):
#             error_window(root, "Please input a valid ip address.")
#             return False
#     return True
 
# def ip_process(ipArray):
#     """
    
#     Checks to make sure every section of the ip is a valid number.
    
#     """
#     if len(ipArray) != 4:
#         return False
#     for ip in ipArray:
#         if version == 2:
#             ip = unicode(ip)
#         if not ip.isdigit():
#             return False
#         t = int(ip)
#         if t < 0 or 255 < t:
#             return False
#     return True
 
# #------------------------------------------------------------------------------
 
# def server_options_window(master):
#     """Launches server options window for getting port."""
#     top = Toplevel(master)
#     top.title("Connection options")
#     top.grab_set()
#     top.protocol("WM_DELETE_WINDOW", lambda: optionDelete(top))
#     Label(top, text="Port:").grid(row=0)
#     port = Entry(top)
#     port.grid(row=0, column=1)
#     port.focus_set()
#     go = Button(top, text="Launch", command=lambda:
#                 server_options_go(port.get(), top))
#     go.grid(row=1, column=1)
 
# def server_options_go(port, window):
#     """
#     Processes the options entered by the user in the
#     server options window.
 
 
#     """
#     if options_sanitation(port):
#         if not isCLI:
#             window.destroy()
#         Server(int(port)).start()
#     elif isCLI:
#         sys.exit(1)
 
# #-------------------------------------------------------------------------
 
# def username_options_window(master):
#     """Launches username options window for setting username."""
#     top = Toplevel(master)
#     top.title("Username options")
#     top.grab_set()
#     Label(top, text="Username:").grid(row=0)
#     name = Entry(top)
#     name.focus_set()
#     name.grid(row=0, column=1)
#     go = Button(top, text="Change", command=lambda:
#                 username_options_go(name.get(), top))
#     go.grid(row=1, column=1)
 
 
# def username_options_go(name, window):
#     """Processes the options entered by the user in the
#     server options window.
 
#     """
#     processUserCommands("nick", [name])
    
#     window.destroy()
 
# #-------------------------------------------------------------------------
 
# def error_window(master, texty):
#     """Launches a new window to display the message texty."""
#     global isCLI
#     if isCLI:
#         writeToScreen(texty, "System")
#     else:
#         window = Toplevel(master)
#         window.title("ERROR")
#         window.grab_set()
#         Label(window, text=texty).pack()
#         go = Button(window, text="OK", command=window.destroy)
#         go.pack()
#         go.focus_set()
 
# def optionDelete(window):
#     connecter.config(state=NORMAL)
#     window.destroy()
 
# #-----------------------------------------------------------------------------
# # Contacts window
 
# def contacts_window(master):
#     """Displays the contacts window, allowing the user to select a recent
#     connection to reuse.
 
#     """
#     global contact_array
#     cWindow = Toplevel(master)
#     cWindow.title("Contacts")
#     cWindow.grab_set()
#     scrollbar = Scrollbar(cWindow, orient=VERTICAL)
#     listbox = Listbox(cWindow, yscrollcommand=scrollbar.set)
#     scrollbar.config(command=listbox.yview)
#     scrollbar.pack(side=RIGHT, fill=Y)
#     buttons = Frame(cWindow)
#     cBut = Button(buttons, text="Connect",
#                   command=lambda: contacts_connect(
#                                       listbox.get(ACTIVE).split(" ")))
#     cBut.pack(side=LEFT)
#     dBut = Button(buttons, text="Remove",
#                   command=lambda: contacts_remove(
#                                       listbox.get(ACTIVE).split(" "), listbox))
#     dBut.pack(side=LEFT)
#     aBut = Button(buttons, text="Add",
#                   command=lambda: contacts_add(listbox, cWindow))
#     aBut.pack(side=LEFT)
#     buttons.pack(side=BOTTOM)
 
#     for person in contact_array:
#         listbox.insert(END, contact_array[person][1] + " " +
#                        person + " " + contact_array[person][0])
#     listbox.pack(side=LEFT, fill=BOTH, expand=1)
 
# def contacts_connect(item):
#     """Establish a connection between two contacts."""
#     Client(item[1], int(item[2])).start()
 
# def contacts_remove(item, listbox):
#     """Remove a contact."""
#     if listbox.size() != 0:
#         listbox.delete(ACTIVE)
#         global contact_array
#         h = contact_array.pop(item[1])
 
 
# def contacts_add(listbox, master):
#     """Add a contact."""
#     aWindow = Toplevel(master)
#     aWindow.title("Contact add")
#     Label(aWindow, text="Username:").grid(row=0)
#     name = Entry(aWindow)
#     name.focus_set()
#     name.grid(row=0, column=1)
#     Label(aWindow, text="IP:").grid(row=1)
#     ip = Entry(aWindow)
#     ip.grid(row=1, column=1)
#     Label(aWindow, text="Port:").grid(row=2)
#     port = Entry(aWindow)
#     port.grid(row=2, column=1)
#     go = Button(aWindow, text="Add", command=lambda:
#                 contacts_add_helper(name.get(), ip.get(), port.get(),
#                                     aWindow, listbox))
#     go.grid(row=3, column=1)
 
 
# def contacts_add_helper(username, ip, port, window, listbox):
#     """Contact adding helper function. Recognizes invalid usernames and
#     adds contact to listbox and contact_array.
 
#     """
#     for letter in username:
#         if letter == " " or letter == "\n":
#             error_window(root, "Invalid username. No spaces allowed.")
#             return
#     if options_sanitation(port, ip):
#         listbox.insert(END, username + " " + ip + " " + port)
#         contact_array[ip] = [port, username]
#         window.destroy()
#         return
 
# def load_contacts():
#     """Loads the recent chats out of the persistent file contacts.dat."""
#     global contact_array
#     try:
#         filehandle = open("data\\contacts.dat", "r")
#     except IOError:
#         return
#     line = filehandle.readline()
#     while len(line) != 0:
#         temp = (line.rstrip('\n')).split(" ")  # format: ip, port, name
#         contact_array[temp[0]] = temp[1:]
#         line = filehandle.readline()
#     filehandle.close()
 
# def dump_contacts():
#     """Saves the recent chats to the persistent file contacts.dat."""
#     global contact_array


#     sqlquery = "INSERT INTO usercontacts (UC_contacts) VALUES (%s)"
#     result = execute_query(connect_to_database("localhost","root","root","pychat"), sqlquery, (json.dumps(contact_array),))
#     print(result)
 

# def placeText(text):
#     """Places the text from the text bar on to the screen and sends it to
#     everyone this program is connected to.
 
#     """
#     global conn_array
#     global secret_array
#     global username
#     writeToScreen(text, username)
#     for person in conn_array:
#         netThrow(person, secret_array[person], text)
 
# def writeToScreen(text, username=""):
#     """Places text to main text body in format "username: text"."""
#     global main_body_text
#     global isCLI
#     if isCLI:
#         if username:
#             print(username + ": " + text)
#         else:
#             print(text)
#     else:
#         main_body_text.config(state=NORMAL)
#         main_body_text.insert(END, '\n')
#         if username:
#             main_body_text.insert(END, username + ": ")
#         main_body_text.insert(END, text)
#         main_body_text.yview(END)
#         main_body_text.config(state=DISABLED)
 
# def processUserText(event):
#     """Takes text from text bar input and calls processUserCommands if it
#     begins with '/'.
 
#     """
#     data = text_input.get()
#     if data[0] != "/":  # is not a command
#         placeText(data)
#     else:
#         if data.find(" ") == -1:
#             command = data[1:]
#         else:
#             command = data[1:data.find(" ")]
#         params = data[data.find(" ") + 1:].split(" ")
#         processUserCommands(command, params)
#     text_input.delete(0, END)



# def processUserTextHighlight(event):
#     """Takes text from text bar input and highlights entry if it
#     begins with '/'.
 
#     """
#     global is_hinted
#     data = text_input.get()
#     if len(data)>0:
#         if data[0] != "/":  # is not a command
#                 text_input.config(background="#ffffff")
#         else:
#             text_input.config(background="#ffdfcf")
#     else: # there is no any text
#         text_input.config(background="#ffffff")
#     if len(data)==1 and not is_hinted:
#             if data[0] == "/":  # is not a command
#                 showCommandHint()
#                 is_hinted=True
#     if len(data)==0:
#         is_hinted=False

# def showCommandHint():
#     """When this function invoked a popup will have shown to user
#     that contains list of commands
 
#     """
#     try:
#         popup.tk_popup(text_input.winfo_rootx(),text_input.winfo_rooty())
#     finally:
#         popup.grab_release()

# def complete(index,array):
#     text_input.insert(1,array[index])

# def processUserInput(text):
#     """ClI version of processUserText."""
#     if text[0] != "/":
#         placeText(text)
#     else:
#         if text.find(" ") == -1:
#             command = text[1:]
#         else:
#             command = text[1:text.find(" ")]
#         params = text[text.find(" ") + 1:].split(" ")
#         processUserCommands(command, params)
 
# class RegistrationPage:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("Registration Page")
        
#         self.frame = tk.Frame(self.root, padx=10, pady=10)
#         self.frame.pack(pady=20)
        
#         # Username
#         self.label_username = tk.Label(self.frame, text="Username:")
#         self.label_username.grid(row=0, column=0, pady=5, sticky='e')
#         self.entry_username = tk.Entry(self.frame)
#         self.entry_username.grid(row=0, column=1, pady=5)
        
#         # Email
#         self.label_email = tk.Label(self.frame, text="Email:")
#         self.label_email.grid(row=1, column=0, pady=5, sticky='e')
#         self.entry_email = tk.Entry(self.frame)
#         self.entry_email.grid(row=1, column=1, pady=5)
        
#         # Password
#         self.label_password = tk.Label(self.frame, text="Password:")
#         self.label_password.grid(row=2, column=0, pady=5, sticky='e')
#         self.entry_password = tk.Entry(self.frame, show="*")
#         self.entry_password.grid(row=2, column=1, pady=5)
        
#         # Confirm Password
#         self.label_confirm_password = tk.Label(self.frame, text="Confirm Password:")
#         self.label_confirm_password.grid(row=3, column=0, pady=5, sticky='e')
#         self.entry_confirm_password = tk.Entry(self.frame, show="*")
#         self.entry_confirm_password.grid(row=3, column=1, pady=5)
        
#         # Register button
#         self.button_register = tk.Button(self.frame, text="Register", command=self.register)
#         self.button_register.grid(row=4, columnspan=2, pady=10)

#         # Login button (to switch to login page)
#         self.button_login = tk.Button(self.frame, text="Already have an account? Login", command=self.open_login)
#         self.button_login.grid(row=5, columnspan=2, pady=10)

#     def register(self):
#         username = self.entry_username.get()
#         email = self.entry_email.get()
#         password = self.entry_password.get()
#         confirm_password = self.entry_confirm_password.get()
        
#         if not all([username, email, password, confirm_password]):
#             messagebox.showerror("Error", "All fields are required")
#             return
        
#         if password != confirm_password:
#             messagebox.showerror("Error", "Passwords do not match")
#             return
        
#         try:
#             conn = pymysql.connect(
#                 host="localhost",
#                 user="root",
#                 password="root",
#                 database="lan"
#             )
#             cursor = conn.cursor()
            
#             # Check if username or email already exists
#             cursor.execute("SELECT * FROM auth_user WHERE user_name=%s OR user_email=%s", (username, email))
#             if cursor.fetchone():
#                 messagebox.showerror("Error", "Username or email already exists")
#                 return
            
#             # Generate and send OTP
#             otp = self.send_otp(email)
#             if self.verify_otp(otp):
#                 # Insert new user into database
#                 query = "INSERT INTO auth_user (user_name, user_email, user_password) VALUES (%s, %s, %s)"
#                 cursor.execute(query, (username, email, password))
#                 conn.commit()
#                 messagebox.showinfo("Success", "Registration successful!")
#                 self.open_login_after_registration(username)
#             else:
#                 messagebox.showerror("Error", "OTP verification failed")
            
#             cursor.close()
#             conn.close()
        
#         except pymysql.Error as err:
#             messagebox.showerror("Database Error", str(err))

#     def send_otp(self, email):
#         otp = str(random.randint(100000, 999999))
#         sender_email = "cyberpanacea.ca@gmail.com"  # Replace with your email
#         sender_password = "cinchfahbelkdmid"  # Replace with your email password
#         receiver_email = email

#         message = MIMEMultipart()
#         message["From"] = sender_email
#         message["To"] = receiver_email
#         message["Subject"] = "Your Registration OTP Code"

#         body = f"Your OTP code for registration is {otp}"
#         message.attach(MIMEText(body, "plain"))

#         try:
#             server = smtplib.SMTP("smtp.gmail.com", 587)
#             server.starttls()
#             server.login(sender_email, sender_password)
#             server.sendmail(sender_email, receiver_email, message.as_string())
#             server.close()
#             messagebox.showinfo("OTP Sent", "An OTP has been sent to your email.")
#         except Exception as e:
#             messagebox.showerror("Email Error", str(e))
#             return None

#         return otp

#     def verify_otp(self, otp):
#         if otp is None:
#             return False

#         def check_otp():
#             nonlocal verified
#             entered_otp = otp_entry.get()
#             if entered_otp == otp:
#                 verified = True
#                 otp_window.destroy()
#             else:
#                 messagebox.showerror("Invalid OTP", "The OTP you entered is incorrect.")

#         verified = False
#         otp_window = tk.Toplevel(self.root)
#         otp_window.title("Enter OTP")

#         tk.Label(otp_window, text="Enter OTP:").pack(pady=5)
#         otp_entry = tk.Entry(otp_window)
#         otp_entry.pack(pady=5)

#         tk.Button(otp_window, text="Verify", command=check_otp).pack(pady=10)

#         self.root.wait_window(otp_window)
#         return verified

#     def open_login(self):
#         self.root.destroy()
#         login_window = tk.Tk()
#         LoginPage(login_window)
#         login_window.mainloop()

#     def open_login_after_registration(self, username):
#         self.root.destroy()
#         login_window = tk.Tk()
#         login_page = LoginPage(login_window)
#         login_page.entry_username.insert(0, username)  # Pre-fill the username
#         login_window.mainloop()



# ###
# class LoginPage:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("Login Page")
        
#         self.frame = tk.Frame(self.root, padx=10, pady=10)
#         self.frame.pack(pady=20)
        
#         # Username label and entry
#         self.label_username = tk.Label(self.frame, text="Username:")
#         self.label_username.grid(row=0, column=0, pady=5)
#         self.entry_username = tk.Entry(self.frame)
#         self.entry_username.grid(row=0, column=1, pady=5)
        
#         # Password label and entry
#         self.label_password = tk.Label(self.frame, text="Password:")
#         self.label_password.grid(row=1, column=0, pady=5)
#         self.entry_password = tk.Entry(self.frame, show="*")
#         self.entry_password.grid(row=1, column=1, pady=5)
        
#         # Login button
#         self.button_login = tk.Button(self.frame, text="Login", command=self.login)
#         self.button_login.grid(row=2, column=0, pady=10)

#         # Register button
#         self.button_register = tk.Button(self.frame, text="Register", command=self.open_register)
#         self.button_register.grid(row=2, column=1, pady=10)

#     def login(self):
#         username = self.entry_username.get()
#         password = self.entry_password.get()

#         # Connect to MySQL database
#         try:
#             conn = pymysql.connect(
#                 host="localhost",
#                 user="root",
#                 password="root",
#                 database="lan"
#             )
#             cursor = conn.cursor()
#             query = "SELECT user_email FROM auth_user WHERE user_name=%s AND user_password=%s"
#             cursor.execute(query, (username, password))
#             result = cursor.fetchone()
            
#             if result:
#                 email = result[0]
#                 otp = self.send_otp(email)
#                 if self.verify_otp(otp):
#                     messagebox.showinfo("Login Success", f"Welcome, {username}!")
#                     self.root.destroy()
#                     start_chat(username)
#                 else:
#                     messagebox.showerror("Login Failed", "Invalid OTP")
#             else:
#                 messagebox.showerror("Login Failed", "Invalid username or password")
            
#             cursor.close()
#             conn.close()

#         except pymysql.Error as err:
#             messagebox.showerror("Database Error", str(err))

#     def send_otp(self, email):
#         otp = str(random.randint(100000, 999999))
#         sender_email = "cyberpanacea.ca@gmail.com"  # Replace with your email
#         sender_password = "cinchfahbelkdmid"  # Replace with your email password
#         receiver_email = email

#         message = MIMEMultipart()
#         message["From"] = sender_email
#         message["To"] = receiver_email
#         message["Subject"] = "Your Login OTP Code"

#         body = f"Your OTP code for login is {otp}"
#         message.attach(MIMEText(body, "plain"))

#         try:
#             server = smtplib.SMTP("smtp.gmail.com", 587)
#             server.starttls()
#             server.login(sender_email, sender_password)
#             server.sendmail(sender_email, receiver_email, message.as_string())
#             server.close()
#             messagebox.showinfo("OTP Sent", "An OTP has been sent to your email.")
#         except Exception as e:
#             messagebox.showerror("Email Error", str(e))
#             return None

#         return otp

#     def verify_otp(self, otp):
#         if otp is None:
#             return False

#         def check_otp():
#             nonlocal verified
#             entered_otp = otp_entry.get()
#             if entered_otp == otp:
#                 verified = True
#                 otp_window.destroy()
#             else:
#                 messagebox.showerror("Invalid OTP", "The OTP you entered is incorrect.")

#         verified = False
#         otp_window = tk.Toplevel(self.root)
#         otp_window.title("Enter OTP")

#         tk.Label(otp_window, text="Enter OTP:").pack(pady=5)
#         otp_entry = tk.Entry(otp_window)
#         otp_entry.pack(pady=5)

#         tk.Button(otp_window, text="Verify", command=check_otp).pack(pady=10)

#         self.root.wait_window(otp_window)
#         return verified

#     def open_register(self):
#         self.root.destroy()
#         register_window = tk.Tk()
#         RegistrationPage(register_window)
#         register_window.mainloop()


# ##



 
# #-------------------------------------------------------------------------
# class Server(threading.Thread):
#     def __init__(self, port):
#         threading.Thread.__init__(self)
#         self.port = port
#         self.clients = {}  # Dictionary to store connected clients
#         self.secret_array = {}  # Encryption keys for each client

#     def run(self):
#         global username_array
#         global contact_array
#         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         s.bind(('', self.port))
#         s.listen(5)  # Adjust backlog as needed
#         writeToScreen(f"Server started on port {self.port}.", "System")

#         while True:
#             conn, addr = s.accept()
#             client_id = str(addr[1])  # Use port number as client ID
#             self.clients[client_id] = conn
#             writeToScreen(f"Client {client_id} connected from {addr[0]}.", "System")

#             # Handle encryption (similar to the original code)
#             prime = random.randint(1000, 9000)
#             while not isPrime(prime):
#                 prime = random.randint(1000, 9000)
#             base = random.randint(20, 100)
#             a = random.randint(20, 100)

#             conn.send(formatNumber(len(str(base))).encode())
#             conn.send(str(base).encode())
#             conn.send(formatNumber(len(str(prime))).encode())
#             conn.send(str(prime).encode())
#             conn.send(formatNumber(len(str(pow(base, a) % prime))).encode())
#             conn.send(str(pow(base, a) % prime).encode())

#             data = conn.recv(4)
#             data = conn.recv(int(data.decode()))
#             b = int(data.decode())
#             secret = pow(b, a) % prime
#             self.secret_array[client_id] = secret

#             conn.send(formatNumber(len(username)).encode())
#             conn.send(username.encode())

#             data = conn.recv(4)
#             data = conn.recv(int(data.decode()))
#             if data.decode() != "Self":
#                 username_array[client_id] = data.decode()
#                 contact_array[
#                     conn.getpeername()[0]] = [conn.getpeername()[1], data.decode()]
#             else:
#                 username_array[client_id] = addr[0]
#                 contact_array[conn.getpeername()[0]] = [
#                     conn.getpeername()[1],
#                     "No_nick",
#                 ]

#             # Start a new thread to handle this client's communication
#             threading.Thread(
#                 target=self.handle_client, args=(conn, client_id, secret)
#             ).start()

#     def handle_client(self, conn, client_id, secret):
#         while True:
#             try:
#                 data = netCatch(conn, secret)
#                 if data:
#                     if data.startswith(b"FILE:"):
#                         self.handle_file_transfer(conn, data, client_id, secret)
#                     else:
#                         self.broadcast(client_id, data, secret)  # Broadcast message
#                 else:
#                     break  # Client disconnected
#             except:
#                 # Handle exceptions gracefully (e.g., connection issues)
#                 break

#     def handle_file_transfer(self, conn, data, sender_id, secret):
#         # Extract file name and file size
#         file_info = data[5:].decode().split(":")
#         file_name = file_info[0]
#         file_size = int(file_info[1])

#         # Prepare to receive the file
#         with open(file_name, 'wb') as f:
#             bytes_received = 0
#             while bytes_received < file_size:
#                 chunk = netCatch(conn, secret)
#                 if not chunk:
#                     break
#                 f.write(chunk)
#                 bytes_received += len(chunk)
#         writeToScreen(f"File {file_name} received from client {sender_id}.", "System")
#         # Optionally broadcast file received confirmation
#         self.broadcast(sender_id, f"File {file_name} received successfully".encode(), secret)

#     def broadcast(self, sender_id, message, secret):
#         for client_id, client_conn in self.clients.items():
#             if client_id != sender_id:  # Don't send to the sender
#                 netThrow(client_conn, self.secret_array[client_id], message)     



# class Client(threading.Thread):
#     """A class for a Client instance."""
#     def __init__(self, host, port):
#         threading.Thread.__init__(self)
#         self.port = port
#         self.host = host

#     def run(self):
#         global conn_array
#         global secret_array
#         conn_init = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         conn_init.settimeout(5.0)
#         try:
#             conn_init.connect((self.host, self.port))
#         except socket.timeout:
#             writeToScreen("Timeout issue. Host possibly not there.", "System")
#             connecter.config(state=NORMAL)
#             raise SystemExit(0)
#         except socket.error:
#             writeToScreen(
#                 "Connection issue. Host actively refused connection.", "System")
#             connecter.config(state=NORMAL)
#             raise SystemExit(0)
#         porta = conn_init.recv(5)
#         porte = int(porta.decode())
#         conn_init.close()
#         conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         conn.connect((self.host, porte))

#         writeToScreen(
#             f"Connected to server: {self.host} on port: {porte}", "System"
#         )

#         global statusConnect
#         statusConnect.set("Disconnect")
#         connecter.config(state=NORMAL)

#         conn_array.append(conn)
#         # Get base, prime, and A values
#         data = conn.recv(4)
#         data = conn.recv(int(data.decode()))
#         base = int(data.decode())
#         data = conn.recv(4)
#         data = conn.recv(int(data.decode()))
#         prime = int(data.decode())
#         data = conn.recv(4)
#         data = conn.recv(int(data.decode()))
#         a = int(data.decode())
#         b = random.randint(20, 100)
#         # Send the B value
#         conn.send(formatNumber(len(str(pow(base, b) % prime))).encode())
#         conn.send(str(pow(base, b) % prime).encode())
#         secret = pow(a, b) % prime
#         secret_array[conn] = secret

#         conn.send(formatNumber(len(username)).encode())
#         conn.send(username.encode())

#         data = conn.recv(4)
#         data = conn.recv(int(data.decode()))
#         if data.decode() != "Self":
#             username_array[conn] = data.decode()
#             contact_array[
#                 conn.getpeername()[0]] = [str(self.port), data.decode()]
#         else:
#             username_array[conn] = self.host
#             contact_array[conn.getpeername()[0]] = [str(self.port), "No_nick"]
        
#         threading.Thread(target=self.handle_server_communication, args=(conn, secret)).start()
#         # Server(self.port).start()
#         # ##########################################################################THIS
#         # IS GOOD, BUT I CAN'T TEST ON ONE MACHINE

#     def handle_server_communication(self, conn, secret):
#         while True:
#             try:
#                 data = netCatch(conn, secret)
#                 if data:
#                     if data.startswith(b"FILE:"):
#                         self.handle_file_transfer(data, conn, secret)
#                     else:
#                         writeToScreen(data, username)  # Received message from server
#                 else:
#                     break  # Disconnected from server
#             except:
#                 # Handle exceptions gracefully (e.g., connection issues)
#                 break

#     def handle_file_transfer(self, data, conn, secret):
#         # Extract file name and file size from data
#         file_info = data[5:].decode().split(":")
#         file_name = file_info[0]
#         file_size = int(file_info[1])

#         # Prepare to receive the file
#         with open(file_name, 'wb') as f:
#             bytes_received = 0
#             while bytes_received < file_size:
#                 chunk = netCatch(conn, secret)
#                 if not chunk:
#                     break
#                 f.write(chunk)
#                 bytes_received += len(chunk)
#         writeToScreen(f"File {file_name} received successfully.", "System")


# def Runner(conn, secret):
#     global username_array
#     while 1:
#         data = netCatch(conn, secret)
#         if data != 1:
#             writeToScreen(data, username_array[conn])
 
# #-------------------------------------------------------------------------
# # Menu helpers
 
# def QuickClient():
#     """Menu window for connection options."""
#     window = Toplevel(root)
#     window.title("Connection options")
#     window.grab_set()
#     Label(window, text="Server IP:").grid(row=0)
#     destination = Entry(window)
#     destination.grid(row=0, column=1)
#     go = Button(window, text="Connect", command=lambda:
#                 client_options_go(destination.get(), "9999", window))
#     go.grid(row=1, column=1)
 
 
# def QuickServer():
#     """Quickstarts a server."""
#     Server(9999).start()
 
# def saveHistory(username):
#     import datetime
#     """Saves chat history as JSON in MySQL database."""
#     global main_body_text
    
#     # Get the chat content
#     contents = main_body_text.get(1.0, "end-1c")  # "end-1c" removes the final newline
    
#     # Convert chat content to JSON
#     chat_json = json.dumps({"chat_content": contents})
    
#     # Get current timestamp
#     timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
#     # Connect to the database
#     try:
#         conn = pymysql.connect(
#             host="localhost",
#             user="root",
#             password="root",
#             database="lan"
#         )
#         cursor = conn.cursor()
        
#         # First, get the user_id from auth_user table
#         user_query = "SELECT id FROM auth_user WHERE user_name = %s"
#         cursor.execute(user_query, (username,))
#         result = cursor.fetchone()
        
#         if result is None:
#             messagebox.showerror("Error", f"User '{username}' not found in the database.")
#             return
        
#         user_id = result[0]
        
#         # SQL query to insert chat history
#         history_query = """
#         INSERT INTO chat_history (chat_json, user_id, timestamp)
#         VALUES (%s, %s, %s)
#         """
        
#         # Execute the query
#         cursor.execute(history_query, (chat_json, user_id, timestamp))
        
#         # Commit the changes
#         conn.commit()
        
#         messagebox.showinfo("Success", "Chat history saved successfully!")
        
#     except pymysql.Error as e:
#         messagebox.showerror("Database Error", f"An error occurred: {str(e)}")
    
#     finally:
#         if conn:
#             cursor.close()
#             conn.close()

 
# def send_file():
#     file_path = filedialog.askopenfilename()
#     if file_path:
#         Client.send_file(file_path)


 
# def connects(clientType):
#     global conn_array
#     connecter.config(state=DISABLED)
#     if len(conn_array) == 0:
#         if clientType == 0:
#             client_options_window(root)
#         if clientType == 1:
#             server_options_window(root)
#     else:
#         # connecter.config(state=NORMAL)
#         for connection in conn_array:
#             connection.send("-001".encode())
#         processFlag("-001")
        
# def resource_path(relative_path):
#     try:
#         base_path = sys._MEIPASS
#     except Exception:
#         base_path = os.path.abspath(".")

#     return os.path.join(base_path, relative_path)

 
# def toOne():
#     global clientType
#     clientType = 0
 
 
# def toTwo():
#     global clientType
#     clientType = 1
 


# def start_chat(username):
#     global root, main_body_text, text_input, conn_array, secret_array, username_array, contact_array

#     root = tk.Tk()
#     root.title(f"PyChat - {username}")
#     root.iconbitmap(resource_path('messenger.ico'))

#     # Menu bar
#     menubar = Menu(root)

#     # File menu
#     file_menu = Menu(menubar, tearoff=0)
#     file_menu.add_command(label="Save chat", command=lambda: saveHistory(username))
#     file_menu.add_command(label="Change username", command=lambda: username_options_window(root))
#     file_menu.add_command(label="Exit", command=lambda: root.destroy())
#     menubar.add_cascade(label="File", menu=file_menu)

#     # Connection menu
#     connection_menu = Menu(menubar, tearoff=0)
#     connection_menu.add_command(label="Quick Connect", command=QuickClient)
#     connection_menu.add_command(label="Connect on port", command=lambda: client_options_window(root))
#     connection_menu.add_command(label="Disconnect", command=lambda: processFlag("-001"))
#     menubar.add_cascade(label="Connect", menu=connection_menu)

#     # Server menu
#     server_menu = Menu(menubar, tearoff=0)
#     server_menu.add_command(label="Launch server", command=QuickServer)
#     server_menu.add_command(label="Listen on port", command=lambda: server_options_window(root))
#     menubar.add_cascade(label="Server", menu=server_menu)

#     # Contacts menu
#     # menubar.add_command(label="Contacts", command=lambda: contacts_window(root))

#     root.config(menu=menubar)

#     # Main chat body
#     main_body = Frame(root, height=20, width=50)

#     main_body_text = Text(main_body)
#     body_text_scroll = Scrollbar(main_body)
#     main_body_text.focus_set()
#     body_text_scroll.pack(side=RIGHT, fill=Y)
#     main_body_text.pack(side=LEFT, fill=Y)
#     body_text_scroll.config(command=main_body_text.yview)
#     main_body_text.config(yscrollcommand=body_text_scroll.set)
#     main_body.pack()

#     # Welcome message
#     main_body_text.insert(END, f"Welcome to the chat program, {username}!\nCredit to: Ved & Yash")
#     main_body_text.config(state=DISABLED)

#     # Text input area
#     text_input = Entry(root, width=60)
#     text_input.bind("<Return>", processUserText)
#     text_input.bind("<KeyRelease>", processUserTextHighlight)
#     text_input.pack()

#     # Send file button
#     send_file_button = Button(root, text="Send File", command=send_file)
#     send_file_button.pack()

#     # Connection type radio buttons
#     clientType = tk.IntVar()
#     clientType.set(1)  # Default to Server
#     Radiobutton(root, text="Client", variable=clientType, value=0, command=lambda: clientType.set(0)).pack(anchor='e')
#     Radiobutton(root, text="Server", variable=clientType, value=1, command=lambda: clientType.set(1)).pack(anchor='e')

#     # Connect/Disconnect button
#     statusConnect = tk.StringVar()
#     statusConnect.set("Connect")
#     connecter = Button(root, textvariable=statusConnect, command=lambda: connects(clientType.get()))
#     connecter.pack()

#     # Initialize global variables
#     conn_array = []
#     secret_array = {}
#     username_array = {}
#     contact_array = {}

#     # Load contacts
#     load_contacts()

#     root.mainloop()

#     # Save contacts when closing
#     dump_contacts()

# if __name__ == "__main__":
#     if len(sys.argv) > 1 and sys.argv[1] == "-cli":
#         print("Starting command line chat")
#         # Implement CLI chat logic here
#     else:
#         root = tk.Tk()
#         login_page = LoginPage(root)
#         root.mainloop()
    
    

# #-------------------------------------------------------------------------
 
 
# # if len(sys.argv) > 1 and sys.argv[1] == "-cli":
# #     print("Starting command line chat")
 
# # else:
# #     root = Tk()
# #     root.title("")
# #     root.iconbitmap(resource_path('messenger.ico'))
 
# #     menubar = Menu(root)
 
# #     file_menu = Menu(menubar, tearoff=0)
# #     file_menu.add_command(label="Save chat", command=lambda: saveHistory())
# #     file_menu.add_command(label="Change username",
# #                           command=lambda: username_options_window(root))
# #     file_menu.add_command(label="Exit", command=lambda: root.destroy())
# #     menubar.add_cascade(label="File", menu=file_menu)
 
# #     connection_menu = Menu(menubar, tearoff=0)
# #     connection_menu.add_command(label="Quick Connect", command=QuickClient)
# #     connection_menu.add_command(
# #         label="Connect on port", command=lambda: client_options_window(root))
# #     connection_menu.add_command(
# #         label="Disconnect", command=lambda: processFlag("-001"))
# #     menubar.add_cascade(label="Connect", menu=connection_menu)
 
# #     server_menu = Menu(menubar, tearoff=0)
# #     server_menu.add_command(label="Launch server", command=QuickServer)
# #     server_menu.add_command(label="Listen on port",
# #                             command=lambda: server_options_window(root))
# #     menubar.add_cascade(label="Server", menu=server_menu)
 
# #     menubar.add_command(label="Contacts", command=lambda:contacts_window(root))
 
# #     root.config(menu=menubar)
 
# #     main_body = Frame(root, height=20, width=50)
 
# #     main_body_text = Text(main_body)
# #     body_text_scroll = Scrollbar(main_body)
# #     main_body_text.focus_set()
# #     body_text_scroll.pack(side=RIGHT, fill=Y)
# #     main_body_text.pack(side=LEFT, fill=Y)
# #     body_text_scroll.config(command=main_body_text.yview)
# #     main_body_text.config(yscrollcommand=body_text_scroll.set)
# #     main_body.pack()
 
# #     main_body_text.insert(END, "Welcome to the chat program!\nCredit to : Ved & Yash")
# #     main_body_text.config(state=DISABLED)
 
# #     text_input = Entry(root, width=60)
# #     text_input.bind("<Return>", processUserText)
# #     text_input.bind("<KeyRelease>", processUserTextHighlight)
# #     text_input.pack()
# #     send_file_button = Button(root, text="Send File", command=send_file)
# #     send_file_button.pack()
 
# #     #create hint popup
# #     popup = Menu(root,tearoff=0)
# #     popup.add_command(label=commands[0],command=lambda:complete(0,commands))
# #     popup.add_command(label=commands[1],command=lambda:complete(1,commands))
# #     popup.add_command(label=commands[2],command=lambda:complete(2,commands))
# #     popup.add_command(label=commands[3],command=lambda:complete(3,commands))
        

# #     statusConnect = StringVar()
# #     statusConnect.set("Connect")
# #     clientType = 1
# #     Radiobutton(root, text="Client", variable=clientType,
# #                 value=0, command=toOne).pack(anchor=E)
# #     Radiobutton(root, text="Server", variable=clientType,
# #                 value=1, command=toTwo).pack(anchor=E)
# #     connecter = Button(root, textvariable=statusConnect,
# #                        command=lambda: connects(clientType))
# #     connecter.pack()
 
# #     load_contacts()
 
# # #------------------------------------------------------------#
 
# #     root.mainloop()
 
# #     dump_contacts()





from imports import *
import os
from tkinter import filedialog,messagebox
import tkinter as tk
import smtplib
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import pymysql
import sys
if not sys.hexversion > 0x03000000:
    version = 2
else:
    version = 3
if version == 2:
    from Tkinter import *
    from tkFileDialog import asksaveasfilename
    import os
if version == 3:
    from tkinter import *
    from tkinter.filedialog import asksaveasfilename
import threading
import socket
import random
import math

def connect_to_database(host, user, password, database):
    try:
        connection = pymysql.connect(
            host="localhost",
            user="root",
            password="",
            database="lan"
        )
        print("Connection successful")
        return connection
    except pymysql.MySQLError as e:
        print(f"Error connecting to the database: {e}")
        return None

def execute_query(connection, query, params=None):
    try:
        with connection.cursor() as cursor:
            cursor.execute(query, params)
            connection.commit()
            result = cursor.fetchall()
            return result
    except pymysql.MySQLError as e:
        print(f"Error executing query: {e}")
        return None

def close_connection(connection):
    if connection:
        connection.close()
        print("Connection closed")


if len(sys.argv) > 1 and sys.argv[1] == "-cli":
    print("Starting command line chat")
    isCLI = True
else:
    isCLI = False

        
# GLOBALS
commands = ["nick","connect","disconnect","host"]
conn_array = []  # stores open sockets
secret_array = dict()  # key: the open sockets in conn_array,
                        # value: integers for encryption
username_array = dict()  # key: the open sockets in conn_array,
                        # value: usernames for the connection
contact_array = dict()  # key: ip address as a string, value: [port, username]
 
username = "Self"
 
location = 0
port = 0
top = ""
connecter = None
conn = None
statusConnect = None

is_hinted=False

main_body_text = 0
#-GLOBALS-
 
# So,
   #  x_encode your message with the key, then pass that to
   #  refract to get a string out of it.
   # To decrypt, pass the message back to x_encode, and then back to refract
 
def binWord(word):
    """Converts the string into binary."""
    master = ""
    for letter in word:
        temp = bin(ord(letter))[2:]
        while len(temp) < 7:
            temp = '0' + temp
        master = master + temp
    return master
 
def xcrypt(message, key):
    """Encrypts the binary message by the binary key."""
    count = 0
    master = ""
    for letter in message:
        if count == len(key):
            count = 0
        master += str(int(letter) ^ int(key[count]))
        count += 1
    return master
 
def x_encode(string, number):
    """Encrypts the string by the number."""
    return xcrypt(binWord(string), bin(number)[2:])
 
def refract(binary):
    """Returns the string representation of the binary.
    Has trouble with spaces.
 
    """
    master = ""
    for x in range(0, int(len(binary) / 7)):
        master += chr(int(binary[x * 7: (x + 1) * 7], 2) + 0)
    return master
 
 
def formatNumber(number):
    """
    
    Ensures that number is at least length 4 by
    adding extra 0s to the front.
 
    """
    temp = str(number)
    while len(temp) < 4:
        temp = '0' + temp
    return temp
 
def netThrow(conn, secret, message):
    """
    Sends message through the open socket conn with the encryption key
    secret. Sends the length of the incoming message, then sends the actual
    message.
 
    """
    try:
        conn.send(formatNumber(len(x_encode(message, secret))).encode())
        conn.send(x_encode(message, secret).encode())
    except socket.error:
        if len(conn_array) != 0:
            writeToScreen(
                "Connection issue. Sending message failed.", "System")
            processFlag("-001")
 
def netCatch(conn, secret):
    """
    
    Receive and return the message through open socket conn, decrypting
    using key secret. If the message length begins with - instead of a number,
    process as a flag and return 1.
 
    """
    try:
        data = conn.recv(4)
        if data.decode()[0] == '-': 
            processFlag(data.decode(), conn)
            return 1
        data = conn.recv(int(data.decode()))
        return refract(xcrypt(data.decode(), bin(secret)[2:]))
    except socket.error:
        if len(conn_array) != 0:
            writeToScreen(
                "Connection issue. Receiving message failed.", "System")
        processFlag("-001")
 
def isPrime(number):
    """Checks to see if a number is prime."""
    x = 1
    if number == 2 or number == 3:
        return True
    while x < math.sqrt(number):
        x += 1
        if number % x == 0:
            return False
    return True
 
def processFlag(number, conn=None):
    """Process the flag corresponding to number, using open socket conn
    if necessary.
 
    """
    global statusConnect
    global conn_array
    global secret_array
    global username_array
    global contact_array
    global isCLI
    t = int(number[1:])
    if t == 1:  # disconnect
        # in the event of single connection being left or if we're just a
        # client
        if len(conn_array) == 1:
            writeToScreen("Connection closed.", "System")
            dump = secret_array.pop(conn_array[0])
            dump = conn_array.pop()
            try:
                dump.close()
            except socket.error:
                print("Issue with someone being bad about disconnecting")
            if not isCLI:
                statusConnect.set("Connect")
                connecter.config(state=NORMAL)
            return
 
        if conn != None:
            writeToScreen("Connect to " + conn.getsockname()
                          [0] + " closed.", "System")
            dump = secret_array.pop(conn)
            conn_array.remove(conn)
            conn.close()
 
    if t == 2:  # username change
        name = netCatch(conn, secret_array[conn])
        if(isUsernameFree(name)):
            writeToScreen(
                "User " + username_array[conn] + " has changed their username to " + name, "System")
            username_array[conn] = name
            contact_array[
                conn.getpeername()[0]] = [conn.getpeername()[1], name]
 

    if t == 4:
        data = conn.recv(4)
        data = conn.recv(int(data.decode()))
        Client(data.decode(),
               int(contact_array[conn.getpeername()[0]][0])).start()
 
def processUserCommands(command, param):
    """Processes commands passed in via the / text input."""
    global conn_array
    global secret_array
    global username

    
        
 
    if command == "nick":  # change nickname
        for letter in param[0]:
            if letter == " " or letter == "\n":
                if isCLI:
                    error_window(0, "Invalid username. No spaces allowed.")
                else:
                    error_window(root, "Invalid username. No spaces allowed.")
                return
        if isUsernameFree(param[0]):
            writeToScreen("Username is being changed to " + param[0], "System")
            for conn in conn_array:
                conn.send("-002".encode())
                netThrow(conn, secret_array[conn], param[0])
            username = param[0]
        else:
            writeToScreen(param[0] +
                          " is already taken as a username", "System")
    if command == "disconnect":  # disconnects from current connection
        for conn in conn_array:
            conn.send("-001".encode())
        processFlag("-001")
    if command == "connect":  # connects to passed in host port
        if(options_sanitation(param[1], param[0])):
            Client(param[0], int(param[1])).start()
    if command == "host":  # starts server on passed in port
        if(options_sanitation(param[0])):
            Server(int(param[0])).start()
 
def isUsernameFree(name):
    """Checks to see if the username name is free for use."""
    global username_array
    global username
    for conn in username_array:
        if name == username_array[conn] or name == username:
            return False
    return True
 
def passFriends(conn):
    """
    
    Sends conn all of the people currently in conn_array so they can connect
    to them.
    
    """
    global conn_array
    for connection in conn_array:
        if conn != connection:
            conn.send("-004".encode())
            conn.send(
                formatNumber(len(connection.getpeername()[0])).encode())  # pass the ip address
            conn.send(connection.getpeername()[0].encode())
            # conn.send(formatNumber(len(connection.getpeername()[1])).encode()) #pass the port number
            # conn.send(connection.getpeername()[1].encode())
 
#--------------------------------------------------------------------------
 
def client_options_window(master):
    """
    
    Launches client options window for getting destination hostname
    and port.
 
    """
    top = Toplevel(master)
    top.title("Connection options")
    top.protocol("WM_DELETE_WINDOW", lambda: optionDelete(top))
    top.grab_set()
    Label(top, text="Server IP:").grid(row=0)
    location = Entry(top)
    location.grid(row=0, column=1)
    location.focus_set()
    Label(top, text="Port:").grid(row=1)
    port = Entry(top)
    port.grid(row=1, column=1)
    go = Button(top, text="Connect", command=lambda:
                client_options_go(location.get(), port.get(), top))
    go.grid(row=2, column=1)
 
def client_options_go(dest, port, window):
    "Processes the options entered by the user in the client options window."""
    if options_sanitation(port, dest):
        if not isCLI:
            window.destroy()
        Client(dest, int(port)).start()
    elif isCLI:
        sys.exit(1)
 
def options_sanitation(por, loc=""):
    """
    
    Checks to make sure the port and destination ip are both valid.
    Launches error windows if there are any issues.
 
    """
    global root
    if version == 2:
        por = unicode(por)
    if isCLI:
        root = 0
    if not por.isdigit():
        error_window(root, "Please input a port number.")
        return False
    if int(por) < 0 or 65555 < int(por):
        error_window(root, "Please input a port number between 0 and 65555")
        return False
    if loc != "":
        if not ip_process(loc.split(".")):
            error_window(root, "Please input a valid ip address.")
            return False
    return True
 
def ip_process(ipArray):
    """
    
    Checks to make sure every section of the ip is a valid number.
    
    """
    if len(ipArray) != 4:
        return False
    for ip in ipArray:
        if version == 2:
            ip = unicode(ip)
        if not ip.isdigit():
            return False
        t = int(ip)
        if t < 0 or 255 < t:
            return False
    return True
 
#------------------------------------------------------------------------------
 
def server_options_window(master):
    """Launches server options window for getting port."""
    top = Toplevel(master)
    top.title("Connection options")
    top.grab_set()
    top.protocol("WM_DELETE_WINDOW", lambda: optionDelete(top))
    Label(top, text="Port:").grid(row=0)
    port = Entry(top)
    port.grid(row=0, column=1)
    port.focus_set()
    go = Button(top, text="Launch", command=lambda:
                server_options_go(port.get(), top))
    go.grid(row=1, column=1)
 
def server_options_go(port, window):
    """
    Processes the options entered by the user in the
    server options window.
 
 
    """
    if options_sanitation(port):
        if not isCLI:
            window.destroy()
        Server(int(port)).start()
    elif isCLI:
        sys.exit(1)
 
#-------------------------------------------------------------------------
 
def username_options_window(master):
    """Launches username options window for setting username."""
    top = Toplevel(master)
    top.title("Username options")
    top.grab_set()
    Label(top, text="Username:").grid(row=0)
    name = Entry(top)
    name.focus_set()
    name.grid(row=0, column=1)
    go = Button(top, text="Change", command=lambda:
                username_options_go(name.get(), top))
    go.grid(row=1, column=1)
 
 
def username_options_go(name, window):
    """Processes the options entered by the user in the
    server options window.
 
    """
    processUserCommands("nick", [name])
    
    window.destroy()
 
#-------------------------------------------------------------------------
 
def error_window(master, texty):
    """Launches a new window to display the message texty."""
    global isCLI
    if isCLI:
        writeToScreen(texty, "System")
    else:
        window = Toplevel(master)
        window.title("ERROR")
        window.grab_set()
        Label(window, text=texty).pack()
        go = Button(window, text="OK", command=window.destroy)
        go.pack()
        go.focus_set()
 
def optionDelete(window):
    connecter.config(state=NORMAL)
    window.destroy()
 
#-----------------------------------------------------------------------------
# Contacts window
 
def contacts_window(master):
    """Displays the contacts window, allowing the user to select a recent
    connection to reuse.
 
    """
    global contact_array
    cWindow = Toplevel(master)
    cWindow.title("Contacts")
    cWindow.grab_set()
    scrollbar = Scrollbar(cWindow, orient=VERTICAL)
    listbox = Listbox(cWindow, yscrollcommand=scrollbar.set)
    scrollbar.config(command=listbox.yview)
    scrollbar.pack(side=RIGHT, fill=Y)
    buttons = Frame(cWindow)
    cBut = Button(buttons, text="Connect",
                  command=lambda: contacts_connect(
                                      listbox.get(ACTIVE).split(" ")))
    cBut.pack(side=LEFT)
    dBut = Button(buttons, text="Remove",
                  command=lambda: contacts_remove(
                                      listbox.get(ACTIVE).split(" "), listbox))
    dBut.pack(side=LEFT)
    aBut = Button(buttons, text="Add",
                  command=lambda: contacts_add(listbox, cWindow))
    aBut.pack(side=LEFT)
    buttons.pack(side=BOTTOM)
 
    for person in contact_array:
        listbox.insert(END, contact_array[person][1] + " " +
                       person + " " + contact_array[person][0])
    listbox.pack(side=LEFT, fill=BOTH, expand=1)
 
def contacts_connect(item):
    """Establish a connection between two contacts."""
    Client(item[1], int(item[2])).start()
 
def contacts_remove(item, listbox):
    """Remove a contact."""
    if listbox.size() != 0:
        listbox.delete(ACTIVE)
        global contact_array
        h = contact_array.pop(item[1])
 
 
def contacts_add(listbox, master):
    """Add a contact."""
    aWindow = Toplevel(master)
    aWindow.title("Contact add")
    Label(aWindow, text="Username:").grid(row=0)
    name = Entry(aWindow)
    name.focus_set()
    name.grid(row=0, column=1)
    Label(aWindow, text="IP:").grid(row=1)
    ip = Entry(aWindow)
    ip.grid(row=1, column=1)
    Label(aWindow, text="Port:").grid(row=2)
    port = Entry(aWindow)
    port.grid(row=2, column=1)
    go = Button(aWindow, text="Add", command=lambda:
                contacts_add_helper(name.get(), ip.get(), port.get(),
                                    aWindow, listbox))
    go.grid(row=3, column=1)
 
 
def contacts_add_helper(username, ip, port, window, listbox):
    """Contact adding helper function. Recognizes invalid usernames and
    adds contact to listbox and contact_array.
 
    """
    for letter in username:
        if letter == " " or letter == "\n":
            error_window(root, "Invalid username. No spaces allowed.")
            return
    if options_sanitation(port, ip):
        listbox.insert(END, username + " " + ip + " " + port)
        contact_array[ip] = [port, username]
        window.destroy()
        return
 
def load_contacts():
    """Loads the recent chats out of the persistent file contacts.dat."""
    global contact_array
    try:
        filehandle = open("data\\contacts.dat", "r")
    except IOError:
        return
    line = filehandle.readline()
    while len(line) != 0:
        temp = (line.rstrip('\n')).split(" ")  # format: ip, port, name
        contact_array[temp[0]] = temp[1:]
        line = filehandle.readline()
    filehandle.close()
 
def dump_contacts():
    """Saves the recent chats to the persistent file contacts.dat."""
    global contact_array


    sqlquery = "INSERT INTO usercontacts (UC_contacts) VALUES (%s)"
    result = execute_query(connect_to_database("localhost","root","","lan"), sqlquery, (json.dumps(contact_array),))
    print(result)
 

def placeText(text):
    """Places the text from the text bar on to the screen and sends it to
    everyone this program is connected to.
    """
    global conn_array
    global secret_array
    global username
    writeToScreen(text, username)
    for person in conn_array:
        try:
            netThrow(person, secret_array[person], text)
            writeToScreen(f"Message sent to {username_array[person]}", "System")
        except Exception as e:
            writeToScreen(f"Error sending message to {username_array[person]}: {str(e)}", "System")

def writeToScreen(text, username=""):
    """Places text to main text body in format "username: text"."""
    global main_body_text
    global isCLI
    if isCLI:
        if username:
            print(username + ": " + text)
        else:
            print(text)
    else:
        main_body_text.config(state=NORMAL)
        main_body_text.insert(END, '\n')
        if username:
            main_body_text.insert(END, username + ": ")
        main_body_text.insert(END, text)
        main_body_text.yview(END)
        main_body_text.config(state=DISABLED)
 
def processUserText(event):
    """Takes text from text bar input and calls processUserCommands if it
    begins with '/'.
 
    """
    data = text_input.get()
    if data[0] != "/":  # is not a command
        placeText(data)
    else:
        if data.find(" ") == -1:
            command = data[1:]
        else:
            command = data[1:data.find(" ")]
        params = data[data.find(" ") + 1:].split(" ")
        processUserCommands(command, params)
    text_input.delete(0, END)



def processUserTextHighlight(event):
    """Takes text from text bar input and highlights entry if it
    begins with '/'.
 
    """
    global is_hinted
    data = text_input.get()
    if len(data)>0:
        if data[0] != "/":  # is not a command
                text_input.config(background="#ffffff")
        else:
            text_input.config(background="#ffdfcf")
    else: # there is no any text
        text_input.config(background="#ffffff")
    if len(data)==1 and not is_hinted:
            if data[0] == "/":  # is not a command
                showCommandHint()
                is_hinted=True
    if len(data)==0:
        is_hinted=False

def showCommandHint():
    """When this function invoked a popup will have shown to user
    that contains list of commands
 
    """
    try:
        popup.tk_popup(text_input.winfo_rootx(),text_input.winfo_rooty())
    finally:
        popup.grab_release()

def complete(index,array):
    text_input.insert(1,array[index])

def processUserInput(text):
    """ClI version of processUserText."""
    if text[0] != "/":
        placeText(text)
    else:
        if text.find(" ") == -1:
            command = text[1:]
        else:
            command = text[1:text.find(" ")]
        params = text[text.find(" ") + 1:].split(" ")
        processUserCommands(command, params)
 
class RegistrationPage:
    def __init__(self, root):
        self.root = root
        self.root.title("Registration Page")
        
        self.frame = tk.Frame(self.root, padx=10, pady=10)
        self.frame.pack(pady=20)
        
        # Username
        self.label_username = tk.Label(self.frame, text="Username:")
        self.label_username.grid(row=0, column=0, pady=5, sticky='e')
        self.entry_username = tk.Entry(self.frame)
        self.entry_username.grid(row=0, column=1, pady=5)
        
        # Email
        self.label_email = tk.Label(self.frame, text="Email:")
        self.label_email.grid(row=1, column=0, pady=5, sticky='e')
        self.entry_email = tk.Entry(self.frame)
        self.entry_email.grid(row=1, column=1, pady=5)
        
        # Password
        self.label_password = tk.Label(self.frame, text="Password:")
        self.label_password.grid(row=2, column=0, pady=5, sticky='e')
        self.entry_password = tk.Entry(self.frame, show="*")
        self.entry_password.grid(row=2, column=1, pady=5)
        
        # Confirm Password
        self.label_confirm_password = tk.Label(self.frame, text="Confirm Password:")
        self.label_confirm_password.grid(row=3, column=0, pady=5, sticky='e')
        self.entry_confirm_password = tk.Entry(self.frame, show="*")
        self.entry_confirm_password.grid(row=3, column=1, pady=5)
        
        # Register button
        self.button_register = tk.Button(self.frame, text="Register", command=self.register)
        self.button_register.grid(row=4, columnspan=2, pady=10)

        # Login button (to switch to login page)
        self.button_login = tk.Button(self.frame, text="Already have an account? Login", command=self.open_login)
        self.button_login.grid(row=5, columnspan=2, pady=10)

    def register(self):
        username = self.entry_username.get()
        email = self.entry_email.get()
        password = self.entry_password.get()
        confirm_password = self.entry_confirm_password.get()
        
        if not all([username, email, password, confirm_password]):
            messagebox.showerror("Error", "All fields are required")
            return
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        try:
            conn = pymysql.connect(
                host="localhost",
                user="root",
                password="",
                database="lan"
            )
            cursor = conn.cursor()
            
            # Check if username or email already exists
            cursor.execute("SELECT * FROM auth_user WHERE user_name=%s OR user_email=%s", (username, email))
            if cursor.fetchone():
                messagebox.showerror("Error", "Username or email already exists")
                return
            
            # Generate and send OTP
            otp = self.send_otp(email)
            if self.verify_otp(otp):
                # Insert new user into database
                query = "INSERT INTO auth_user (user_name, user_email, user_password) VALUES (%s, %s, %s)"
                cursor.execute(query, (username, email, password))
                conn.commit()
                messagebox.showinfo("Success", "Registration successful!")
                self.open_login_after_registration(username)
            else:
                messagebox.showerror("Error", "OTP verification failed")
            
            cursor.close()
            conn.close()
        
        except pymysql.Error as err:
            messagebox.showerror("Database Error", str(err))

    def send_otp(self, email):
        otp = str(random.randint(100000, 999999))
        sender_email = "cyberpanacea.ca@gmail.com"  # Replace with your email
        sender_password = "cinchfahbelkdmid"  # Replace with your email password
        receiver_email = email

        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = "Your Registration OTP Code"

        body = f"Your OTP code for registration is {otp}"
        message.attach(MIMEText(body, "plain"))

        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, message.as_string())
            server.close()
            messagebox.showinfo("OTP Sent", "An OTP has been sent to your email.")
        except Exception as e:
            messagebox.showerror("Email Error", str(e))
            return None

        return otp

    def verify_otp(self, otp):
        if otp is None:
            return False

        def check_otp():
            nonlocal verified
            entered_otp = otp_entry.get()
            if entered_otp == otp:
                verified = True
                otp_window.destroy()
            else:
                messagebox.showerror("Invalid OTP", "The OTP you entered is incorrect.")

        verified = False
        otp_window = tk.Toplevel(self.root)
        otp_window.title("Enter OTP")

        tk.Label(otp_window, text="Enter OTP:").pack(pady=5)
        otp_entry = tk.Entry(otp_window)
        otp_entry.pack(pady=5)

        tk.Button(otp_window, text="Verify", command=check_otp).pack(pady=10)

        self.root.wait_window(otp_window)
        return verified

    def open_login(self):
        self.root.destroy()
        login_window = tk.Tk()
        LoginPage(login_window)
        login_window.mainloop()

    def open_login_after_registration(self, username):
        self.root.destroy()
        login_window = tk.Tk()
        login_page = LoginPage(login_window)
        login_page.entry_username.insert(0, username)  # Pre-fill the username
        login_window.mainloop()



###
class LoginPage:
    def __init__(self, root):
        self.root = root
        self.root.title("Login Page")
        
        self.frame = tk.Frame(self.root, padx=10, pady=10)
        self.frame.pack(pady=20)
        
        # Username label and entry
        self.label_username = tk.Label(self.frame, text="Username:")
        self.label_username.grid(row=0, column=0, pady=5)
        self.entry_username = tk.Entry(self.frame)
        self.entry_username.grid(row=0, column=1, pady=5)
        
        # Password label and entry
        self.label_password = tk.Label(self.frame, text="Password:")
        self.label_password.grid(row=1, column=0, pady=5)
        self.entry_password = tk.Entry(self.frame, show="*")
        self.entry_password.grid(row=1, column=1, pady=5)
        
        # Login button
        self.button_login = tk.Button(self.frame, text="Login", command=self.login)
        self.button_login.grid(row=2, column=0, pady=10)

        # Register button
        self.button_register = tk.Button(self.frame, text="Register", command=self.open_register)
        self.button_register.grid(row=2, column=1, pady=10)

    def login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        # Connect to MySQL database
        try:
            conn = pymysql.connect(
                host="localhost",
                user="root",
                password="",
                database="lan"
            )
            cursor = conn.cursor()
            query = "SELECT user_email FROM auth_user WHERE user_name=%s AND user_password=%s"
            cursor.execute(query, (username, password))
            result = cursor.fetchone()
            
            if result:
                email = result[0]
                otp = self.send_otp(email)
                if self.verify_otp(otp):
                    messagebox.showinfo("Login Success", f"Welcome, {username}!")
                    self.root.destroy()
                    start_chat(username)
                else:
                    messagebox.showerror("Login Failed", "Invalid OTP")
            else:
                messagebox.showerror("Login Failed", "Invalid username or password")
            
            cursor.close()
            conn.close()

        except pymysql.Error as err:
            messagebox.showerror("Database Error", str(err))

    def send_otp(self, email):
        otp = str(random.randint(100000, 999999))
        sender_email = "cyberpanacea.ca@gmail.com"  # Replace with your email
        sender_password = "cinchfahbelkdmid"  # Replace with your email password
        receiver_email = email

        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = "Your Login OTP Code"

        body = f"Your OTP code for login is {otp}"
        message.attach(MIMEText(body, "plain"))

        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, message.as_string())
            server.close()
            messagebox.showinfo("OTP Sent", "An OTP has been sent to your email.")
        except Exception as e:
            messagebox.showerror("Email Error", str(e))
            return None

        return otp

    def verify_otp(self, otp):
        if otp is None:
            return False

        def check_otp():
            nonlocal verified
            entered_otp = otp_entry.get()
            if entered_otp == otp:
                verified = True
                otp_window.destroy()
            else:
                messagebox.showerror("Invalid OTP", "The OTP you entered is incorrect.")

        verified = False
        otp_window = tk.Toplevel(self.root)
        otp_window.title("Enter OTP")

        tk.Label(otp_window, text="Enter OTP:").pack(pady=5)
        otp_entry = tk.Entry(otp_window)
        otp_entry.pack(pady=5)

        tk.Button(otp_window, text="Verify", command=check_otp).pack(pady=10)

        self.root.wait_window(otp_window)
        return verified

    def open_register(self):
        self.root.destroy()
        register_window = tk.Tk()
        RegistrationPage(register_window)
        register_window.mainloop()


##



 
#-------------------------------------------------------------------------

class Server (threading.Thread):
    "A class for a Server instance."""
    def __init__(self, port):
        threading.Thread.__init__(self)
        self.port = port
 
    def run(self):
        global conn_array
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', self.port))
 
        if len(conn_array) == 0:
            writeToScreen(
                "Socket is good, waiting for connections on port: " +
                str(self.port), "System")
        s.listen(1)
        global conn_init
        conn_init, addr_init = s.accept()
        serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serv.bind(('', 0))  # get a random empty port
        serv.listen(1)
 
        portVal = str(serv.getsockname()[1])
        if len(portVal) == 5:
            conn_init.send(portVal.encode())
        else:
            conn_init.send(("0" + portVal).encode())
 
        conn_init.close()
        conn, addr = serv.accept()
        conn_array.append(conn)  # add an array entry for this connection
        writeToScreen("Connected by " + str(addr[0]), "System")
 
        global statusConnect
        statusConnect.set("Disconnect")
        connecter.config(state=NORMAL)
 
        # create the numbers for my encryption
        prime = random.randint(1000, 9000)
        while not isPrime(prime):
            prime = random.randint(1000, 9000)
        base = random.randint(20, 100)
        a = random.randint(20, 100)
 
        # send the numbers (base, prime, A)
        conn.send(formatNumber(len(str(base))).encode())
        conn.send(str(base).encode())
 
        conn.send(formatNumber(len(str(prime))).encode())
        conn.send(str(prime).encode())
 
        conn.send(formatNumber(len(str(pow(base, a) % prime))).encode())
        conn.send(str(pow(base, a) % prime).encode())
 
        # get B
        data = conn.recv(4)
        data = conn.recv(int(data.decode()))
        b = int(data.decode())
 
        # calculate the encryption key
        global secret_array
        secret = pow(b, a) % prime
        # store the encryption key by the connection
        secret_array[conn] = secret
 
        conn.send(formatNumber(len(username)).encode())
        conn.send(username.encode())
 
        data = conn.recv(4)
        data = conn.recv(int(data.decode()))
        if data.decode() != "Self":
            username_array[conn] = data.decode()
            contact_array[str(addr[0])] = [str(self.port), data.decode()]
        else:
            username_array[conn] = addr[0]
            contact_array[str(addr[0])] = [str(self.port), "No_nick"]
 
        passFriends(conn)
        threading.Thread(target=Runner, args=(conn, secret)).start()
        Server(self.port).start()
 
 
class Client (threading.Thread):
    """A class for a Client instance."""
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.port = port
        self.host = host
 
    def run(self):
        global conn_array
        global secret_array
        conn_init = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_init.settimeout(5.0)
        try:
            conn_init.connect((self.host, self.port))
        except socket.timeout:
            writeToScreen("Timeout issue. Host possible not there.", "System")
            connecter.config(state=NORMAL)
            raise SystemExit(0)
        except socket.error:
            writeToScreen(
                "Connection issue. Host actively refused connection.", "System")
            connecter.config(state=NORMAL)
            raise SystemExit(0)
        porta = conn_init.recv(5)
        porte = int(porta.decode())
        conn_init.close()
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((self.host, porte))
 
        writeToScreen("Connected to: " + self.host +
                      " on port: " + str(porte), "System")
 
        global statusConnect
        statusConnect.set("Disconnect")
        connecter.config(state=NORMAL)
 
        conn_array.append(conn)
        # get my base, prime, and A values
        data = conn.recv(4)
        data = conn.recv(int(data.decode()))
        base = int(data.decode())
        data = conn.recv(4)
        data = conn.recv(int(data.decode()))
        prime = int(data.decode())
        data = conn.recv(4)
        data = conn.recv(int(data.decode()))
        a = int(data.decode())
        b = random.randint(20, 100)
        # send the B value
        conn.send(formatNumber(len(str(pow(base, b) % prime))).encode())
        conn.send(str(pow(base, b) % prime).encode())
        secret = pow(a, b) % prime
        secret_array[conn] = secret
 
        conn.send(formatNumber(len(username)).encode())
        conn.send(username.encode())
 
        data = conn.recv(4)
        data = conn.recv(int(data.decode()))
        if data.decode() != "Self":
            username_array[conn] = data.decode()
            contact_array[
                conn.getpeername()[0]] = [str(self.port), data.decode()]
        else:
            username_array[conn] = self.host
            contact_array[conn.getpeername()[0]] = [str(self.port), "No_nick"]
        threading.Thread(target=Runner, args=(conn, secret)).start()
        # Server(self.port).start()
        # ##########################################################################THIS
        # IS GOOD, BUT I CAN'T TEST ON ONE MACHINE
 
def Runner(conn, secret):
    global username_array
    while 1:
        data = netCatch(conn, secret)
        if data != 1:
            writeToScreen(data, username_array[conn])
 
#-------------------------------------------------------------------------
# Menu helpers
 
def QuickClient():
    """Menu window for connection options."""
    window = Toplevel(root)
    window.title("Connection options")
    window.grab_set()
    Label(window, text="Server IP:").grid(row=0)
    destination = Entry(window)
    destination.grid(row=0, column=1)
    go = Button(window, text="Connect", command=lambda:
                client_options_go(destination.get(), "9999", window))
    go.grid(row=1, column=1)
 
 
def QuickServer():
    """Quickstarts a server."""
    Server(9999).start()
 
def saveHistory(username):
    import datetime
    """Saves chat history as JSON in MySQL database."""
    global main_body_text
    
    # Get the chat content
    contents = main_body_text.get(1.0, "end-1c")  # "end-1c" removes the final newline
    
    # Convert chat content to JSON
    chat_json = json.dumps({"chat_content": contents})
    
    # Get current timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Connect to the database
    try:
        conn = pymysql.connect(
            host="localhost",
            user="root",
            password="",
            database="lan"
        )
        cursor = conn.cursor()
        
        # First, get the user_id from auth_user table
        user_query = "SELECT id FROM auth_user WHERE user_name = %s"
        cursor.execute(user_query, (username,))
        result = cursor.fetchone()
        
        if result is None:
            messagebox.showerror("Error", f"User '{username}' not found in the database.")
            return
        
        user_id = result[0]
        
        # SQL query to insert chat history
        history_query = """
        INSERT INTO chat_history (chat_json, user_id, timestamp)
        VALUES (%s, %s, %s)
        """
        
        # Execute the query
        cursor.execute(history_query, (chat_json, user_id, timestamp))
        
        # Commit the changes
        conn.commit()
        
        messagebox.showinfo("Success", "Chat history saved successfully!")
        
    except pymysql.Error as e:
        messagebox.showerror("Database Error", f"An error occurred: {str(e)}")
    
    finally:
        if conn:
            cursor.close()
            conn.close()

 
def send_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        Client.send_file(file_path)


 
def connects(clientType):
    global conn_array
    connecter.config(state=DISABLED)
    if len(conn_array) == 0:
        if clientType == 0:
            client_options_window(root)
        if clientType == 1:
            server_options_window(root)
    else:
        # connecter.config(state=NORMAL)
        for connection in conn_array:
            connection.send("-001".encode())
        processFlag("-001")
        
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

 
def toOne():
    global clientType
    clientType = 0
 
 
def toTwo():
    global clientType
    clientType = 1
 


def start_chat(username):
    global root, main_body_text, text_input, conn_array, secret_array, username_array, contact_array, connecter, statusConnect

    root = tk.Tk()
    root.title(f"PyChat - {username}")
    root.iconbitmap(resource_path('messenger.ico'))

    # Menu bar
    menubar = Menu(root)

    # File menu
    file_menu = Menu(menubar, tearoff=0)
    file_menu.add_command(label="Save chat", command=lambda: saveHistory(username))
    file_menu.add_command(label="Change username", command=lambda: username_options_window(root))
    file_menu.add_command(label="Exit", command=lambda: root.destroy())
    menubar.add_cascade(label="File", menu=file_menu)

    # Connection menu
    connection_menu = Menu(menubar, tearoff=0)
    connection_menu.add_command(label="Quick Connect", command=QuickClient)
    connection_menu.add_command(label="Connect on port", command=lambda: client_options_window(root))
    connection_menu.add_command(label="Disconnect", command=lambda: processFlag("-001"))
    menubar.add_cascade(label="Connect", menu=connection_menu)

    # Server menu
    server_menu = Menu(menubar, tearoff=0)
    server_menu.add_command(label="Launch server", command=QuickServer)
    server_menu.add_command(label="Listen on port", command=lambda: server_options_window(root))
    menubar.add_cascade(label="Server", menu=server_menu)

    # Contacts menu
    # menubar.add_command(label="Contacts", command=lambda: contacts_window(root))

    root.config(menu=menubar)

    # Main chat body
    main_body = Frame(root, height=20, width=50)

    main_body_text = Text(main_body)
    body_text_scroll = Scrollbar(main_body)
    main_body_text.focus_set()
    body_text_scroll.pack(side=RIGHT, fill=Y)
    main_body_text.pack(side=LEFT, fill=Y)
    body_text_scroll.config(command=main_body_text.yview)
    main_body_text.config(yscrollcommand=body_text_scroll.set)
    main_body.pack()

    # Welcome message
    main_body_text.insert(END, f"Welcome to the chat program, {username}!\nCredit to: Ved & Yash")
    main_body_text.config(state=DISABLED)

    # Text input area
    text_input = Entry(root, width=60)
    text_input.bind("<Return>", processUserText)
    text_input.bind("<KeyRelease>", processUserTextHighlight)
    text_input.pack()

    # Send file button
    # send_file_button = Button(root, text="Send File", command=send_file)
    # send_file_button.pack()

    # Connection type radio buttons
    clientType = tk.IntVar()
    clientType.set(1)  # Default to Server
    Radiobutton(root, text="Client", variable=clientType, value=0, command=lambda: clientType.set(0)).pack(anchor='e')
    Radiobutton(root, text="Server", variable=clientType, value=1, command=lambda: clientType.set(1)).pack(anchor='e')

    # Connect/Disconnect button
    statusConnect = tk.StringVar()
    statusConnect.set("Connect")
    connecter = Button(root, textvariable=statusConnect, command=lambda: connects(clientType.get()))
    connecter.pack()

    # Initialize global variables
    conn_array = []
    secret_array = {}
    username_array = {}
    contact_array = {}

    # Load contacts
    load_contacts()

    root.mainloop()

    # Save contacts when closing
    # dump_contacts()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "-cli":
        print("Starting command line chat")
        # Implement CLI chat logic here
    else:
        root = tk.Tk()
        login_page = LoginPage(root)
        root.mainloop()
    
    

#-------------------------------------------------------------------------
 
 
# if len(sys.argv) > 1 and sys.argv[1] == "-cli":
#     print("Starting command line chat")
 
# else:
#     root = Tk()
#     root.title("")
#     root.iconbitmap(resource_path('messenger.ico'))
 
#     menubar = Menu(root)
 
#     file_menu = Menu(menubar, tearoff=0)
#     file_menu.add_command(label="Save chat", command=lambda: saveHistory())
#     file_menu.add_command(label="Change username",
#                           command=lambda: username_options_window(root))
#     file_menu.add_command(label="Exit", command=lambda: root.destroy())
#     menubar.add_cascade(label="File", menu=file_menu)
 
#     connection_menu = Menu(menubar, tearoff=0)
#     connection_menu.add_command(label="Quick Connect", command=QuickClient)
#     connection_menu.add_command(
#         label="Connect on port", command=lambda: client_options_window(root))
#     connection_menu.add_command(
#         label="Disconnect", command=lambda: processFlag("-001"))
#     menubar.add_cascade(label="Connect", menu=connection_menu)
 
#     server_menu = Menu(menubar, tearoff=0)
#     server_menu.add_command(label="Launch server", command=QuickServer)
#     server_menu.add_command(label="Listen on port",
#                             command=lambda: server_options_window(root))
#     menubar.add_cascade(label="Server", menu=server_menu)
 
#     menubar.add_command(label="Contacts", command=lambda:contacts_window(root))
 
#     root.config(menu=menubar)
 
#     main_body = Frame(root, height=20, width=50)
 
#     main_body_text = Text(main_body)
#     body_text_scroll = Scrollbar(main_body)
#     main_body_text.focus_set()
#     body_text_scroll.pack(side=RIGHT, fill=Y)
#     main_body_text.pack(side=LEFT, fill=Y)
#     body_text_scroll.config(command=main_body_text.yview)
#     main_body_text.config(yscrollcommand=body_text_scroll.set)
#     main_body.pack()
 
#     main_body_text.insert(END, "Welcome to the chat program!\nCredit to : Ved & Yash")
#     main_body_text.config(state=DISABLED)
 
#     text_input = Entry(root, width=60)
#     text_input.bind("<Return>", processUserText)
#     text_input.bind("<KeyRelease>", processUserTextHighlight)
#     text_input.pack()
#     send_file_button = Button(root, text="Send File", command=send_file)
#     send_file_button.pack()
 
#     #create hint popup
#     popup = Menu(root,tearoff=0)
#     popup.add_command(label=commands[0],command=lambda:complete(0,commands))
#     popup.add_command(label=commands[1],command=lambda:complete(1,commands))
#     popup.add_command(label=commands[2],command=lambda:complete(2,commands))
#     popup.add_command(label=commands[3],command=lambda:complete(3,commands))
        

#     statusConnect = StringVar()
#     statusConnect.set("Connect")
#     clientType = 1
#     Radiobutton(root, text="Client", variable=clientType,
#                 value=0, command=toOne).pack(anchor=E)
#     Radiobutton(root, text="Server", variable=clientType,
#                 value=1, command=toTwo).pack(anchor=E)
#     connecter = Button(root, textvariable=statusConnect,
#                        command=lambda: connects(clientType))
#     connecter.pack()
 
#     load_contacts()
 
# #------------------------------------------------------------#
 
#     root.mainloop()
 
#     dump_contacts()

