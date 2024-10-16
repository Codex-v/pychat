import tkinter as tk
from tkinter import messagebox
import mysql.connector
import smtplib
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import subprocess

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
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="root",
                database="lanchat"
            )
            cursor = conn.cursor()
            query = "SELECT user_email FROM auth_user WHERE user_name=%s AND user_password=%s"
            cursor.execute(query, (username, password))
            result = cursor.fetchone()
            
            if result:
                email = result[0]
                otp = self.send_otp(email)
                self.verify_otp(otp)
            else:
                messagebox.showerror("Login Failed", "Invalid username or password")
            
            cursor.close()
            conn.close()

        except mysql.connector.Error as err:
            messagebox.showerror("Database Error", str(err))

    def send_otp(self, email):
        otp = str(random.randint(100000, 999999))
        sender_email = "cyberpanacea.ca@gmail.com"
        sender_password = "cinchfahbelkdmid"
        receiver_email = email

        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = "Your OTP Code"

        body = f"Your OTP code is {otp}"
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

        return otp

    def verify_otp(self, otp):
        def check_otp():
            entered_otp = otp_entry.get()
            if entered_otp == otp:
                messagebox.showinfo("Login Success", "Welcome!")
                otp_window.destroy()
                self.root.destroy()  # Close the login window
                self.open_pychat()  # Open pychat.py
            else:
                messagebox.showerror("Invalid OTP", "The OTP you entered is incorrect.")

        otp_window = tk.Toplevel(self.root)
        otp_window.title("Enter OTP")

        tk.Label(otp_window, text="Enter OTP:").pack(pady=5)
        otp_entry = tk.Entry(otp_window)
        otp_entry.pack(pady=5)

        tk.Button(otp_window, text="Verify", command=check_otp).pack(pady=10)

    def open_pychat(self):
        subprocess.Popen(["python", "main.py"])

    def open_register(self):
        self.root.destroy()  # Close the login window
        subprocess.Popen(["python", "resgiter.py"])

# Create the main window
root = tk.Tk()

login_page = LoginPage(root)

root.mainloop()