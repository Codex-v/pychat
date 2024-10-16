import tkinter as tk
from tkinter import messagebox
import mysql.connector
import smtplib
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import subprocess

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

        # Login button
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
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="root",
                database="lanchat"
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
                self.open_login()  # Open login page after successful registration
            else:
                messagebox.showerror("Error", "OTP verification failed")
            
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
        self.root.destroy()  # Close the registration window
        subprocess.Popen(["python", "login.py"])

# Create the main window
root = tk.Tk()

# Create an instance of the RegistrationPage class
registration_page = RegistrationPage(root)

# Run the Tkinter event loop
root.mainloop()