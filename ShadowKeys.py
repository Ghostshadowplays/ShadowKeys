import ctypes
import os
import sys
import json
from cryptography.fernet import Fernet
import customtkinter as ctk
from tkinter import messagebox, filedialog
from PIL import Image, ImageTk
from io import BytesIO
import requests

def is_admin():
    """Check if the user has admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        print(f"Error checking admin status: {e}")
        return False

def elevate_privileges():
    """Attempt to elevate the script's privileges."""
    script = os.path.abspath(sys.argv[0])
    params = ' '.join([script] + sys.argv[1:])
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    except Exception as e:
        print(f"Failed to elevate privileges: {e}")
    sys.exit()

if not is_admin():
    elevate_privileges()

class PasswordManager:
    """Class to manage passwords securely."""
    def __init__(self):
        self.key = None
        self.cipher = None
        self.passwords = {}
        self.password_file_path = None
        self.load_key()
        self.prompt_for_password_file()

    def set_key(self, key):
        """Set the encryption key."""
        self.key = key
        self.cipher = Fernet(self.key)

    def load_key(self):
        """Load or create an encryption key."""
        choice = messagebox.askquestion("Select Key File", "Do you want to find an existing key file?", icon='question')
        if choice == 'yes':
            key_file_path = filedialog.askopenfilename(title="Select Key File", filetypes=[("Key Files", "*.key")])
            if key_file_path and os.path.exists(key_file_path):
                with open(key_file_path, "rb") as kf:
                    self.set_key(kf.read())
            else:
                messagebox.showwarning("File Not Found", "No key file found. A new key file will be created.")
                self.create_key_file()
        else:
            self.create_key_file()

    def create_key_file(self):
        """Create a new encryption key file."""
        key_file_path = filedialog.asksaveasfilename(title="Create New Key File", defaultextension=".key", filetypes=[("Key Files", "*.key")])
        if key_file_path:
            self.key = Fernet.generate_key()
            with open(key_file_path, "wb") as kf:
                kf.write(self.key)
            self.set_key(self.key)

    def prompt_for_password_file(self):
        """Prompt the user for a password file."""
        choice = messagebox.askquestion("Select Password File", "Do you want to find an existing password file?", icon='question')
        if choice == 'yes':
            self.password_file_path = filedialog.askopenfilename(title="Select Password File", filetypes=[("JSON Files", "*.json")])
            if self.password_file_path and os.path.exists(self.password_file_path):
                self.load_passwords()
            else:
                messagebox.showwarning("File Not Found", "No password file found. A new file will be created.")
                self.create_password_file()
        else:
            self.create_password_file()

    def create_password_file(self):
        """Create a new password file."""
        self.password_file_path = filedialog.asksaveasfilename(title="Create New Password File", defaultextension=".json", filetypes=[("JSON Files", "*.json")])
        if self.password_file_path:
            with open(self.password_file_path, "w") as f:
                json.dump({}, f)

    def load_passwords(self):
        """Load passwords from the JSON file."""
        if self.password_file_path and os.path.exists(self.password_file_path):
            with open(self.password_file_path, "r") as f:
                self.passwords = json.load(f)
                self.passwords = {site: self.decrypt(pw.encode()) for site, pw in self.passwords.items()}

    def save_to_file(self):
        """Save passwords to the JSON file."""
        if self.password_file_path:
            with open(self.password_file_path, "w") as f:
                encrypted_passwords = {site: self.encrypt(pw).decode() for site, pw in self.passwords.items()}
                json.dump(encrypted_passwords, f, indent=4)

    def encrypt(self, password):
        """Encrypt a password."""
        return self.cipher.encrypt(password.encode())

    def decrypt(self, encrypted_password):
        """Decrypt a password."""
        return self.cipher.decrypt(encrypted_password).decode()

    def save_password(self, site, password):
        """Save a password for a specific site."""
        if self.is_safe_input(site) and self.is_safe_input(password):
            self.passwords[site] = password
            self.save_to_file()
        else:
            messagebox.showwarning("Input Error", "Site or password contains invalid characters.")

    def delete_password(self, site):
        """Delete a password for a specific site."""
        if site in self.passwords:
            del self.passwords[site]
            self.save_to_file()
            return True
        return False

    @staticmethod
    def is_safe_input(user_input):
        """Check if input is safe (allows certain special characters)."""
        # You can adjust allowed_special_chars based on your requirements
        allowed_special_chars = "!@#$%^&*()-_=+[]{}|;:'\",.<>?/"
        return isinstance(user_input, str) and all(c.isalnum() or c in (' ', '-', '_') or c in allowed_special_chars for c in user_input)

def load_image_from_url(image_url, size=(85, 85)):
    """Load an image from a URL."""
    try:
        response = requests.get(image_url)
        response.raise_for_status()  # Raise an error for bad responses
        image = Image.open(BytesIO(response.content))
        image = image.resize(size, Image.LANCZOS)
        return ImageTk.PhotoImage(image)
    except Exception as e:
        print(f"Error loading image from URL {image_url}: {e}")
        return None

def create_label_with_image(master, text, image_url, text_color="#993cda"):
    """Create a label with an image."""
    loaded_image = load_image_from_url(image_url, size=(85, 85))
    if loaded_image:
        label = ctk.CTkLabel(master, text=text, font=("Helvetica", 25, "bold"),
                             image=loaded_image, text_color=text_color, compound="left")
        label.image = loaded_image  
        label.pack(pady=(30, 0))  
        return label  
    else:
        print("Failed to load image.")

class App:
    """Main application class."""
    def __init__(self, master):
        self.master = master
        master.title("ShadowKeys")
        master.geometry("400x450")
        master.resizable(False, False)

        logo_url = "https://raw.githubusercontent.com/Ghostshadowplays/Ghostyware-Logo/main/GhostywareLogo.png"
        create_label_with_image(master, "ShadowKeys", logo_url)  

        self.manager = PasswordManager()

        self.site_label = ctk.CTkLabel(master, text="Site:")
        self.site_label.pack(pady=10)

        self.site_entry = ctk.CTkEntry(master, width=300)
        self.site_entry.pack(pady=5)

        self.password_label = ctk.CTkLabel(master, text="Password:")
        self.password_label.pack(pady=10)

        self.password_entry = ctk.CTkEntry(master, show="*", width=300)
        self.password_entry.pack(pady=5)

        self.save_button = ctk.CTkButton(master, text="Save Password", command=self.save_password,
                                         fg_color="#4158D0", hover_color="#993cda",
                                         border_color="#e7e7e7", border_width=2, width=200)
        self.save_button.pack(pady=10)

        self.load_button = ctk.CTkButton(master, text="Load Password", command=self.load_password,
                                         fg_color="#4158D0", hover_color="#993cda",
                                         border_color="#e7e7e7", border_width=2, width=200)
        self.load_button.pack(pady=10)

        self.delete_button = ctk.CTkButton(master, text="Delete Password", command=self.delete_password,
                                           fg_color="#D03535", hover_color="#FF5757",
                                           border_color="#e7e7e7", border_width=2, width=200)
        self.delete_button.pack(pady=10)

    def save_password(self):
        """Save a password using the PasswordManager."""
        site = self.site_entry.get()
        password = self.password_entry.get()
        if site and password:
            self.manager.save_password(site, password)
            messagebox.showinfo("Success", "Password saved successfully!")
        else:
            messagebox.showwarning("Input Error", "Please enter both site and password.")

    def load_password(self):
        """Load a password for the specified site."""
        site = self.site_entry.get()
        if site in self.manager.passwords:
            password = self.manager.passwords[site]
            messagebox.showinfo("Loaded Password", f"Password for {site}: {password}")
        else:
            messagebox.showwarning("Not Found", "No password found for this site.")

    def delete_password(self):
        """Delete a password for the specified site."""
        site = self.site_entry.get()
        if self.manager.delete_password(site):
            messagebox.showinfo("Success", "Password deleted successfully!")
        else:
            messagebox.showwarning("Not Found", "No password found for this site.")

if __name__ == "__main__":
    root = ctk.CTk()
    app = App(root)
    root.mainloop()
