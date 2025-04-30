import ctypes
import os
import sys
import json
from cryptography.fernet import Fernet
import customtkinter as ctk
from tkinter import messagebox, filedialog, Toplevel
from PIL import Image, ImageTk
from io import BytesIO
import requests
import pyperclip


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        print(f"Error checking admin status: {e}")
        return False


def elevate_privileges():
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
    def __init__(self):
        self.key = None
        self.cipher = None
        self.passwords = {}
        self.password_file_path = None
        self.load_key()
        self.prompt_for_password_file()

    def set_key(self, key):
        self.key = key
        self.cipher = Fernet(self.key)

    def load_key(self):
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
        key_file_path = filedialog.asksaveasfilename(title="Create New Key File", defaultextension=".key", filetypes=[("Key Files", "*.key")])
        if key_file_path:
            self.key = Fernet.generate_key()
            with open(key_file_path, "wb") as kf:
                kf.write(self.key)
            self.set_key(self.key)

    def prompt_for_password_file(self):
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
        self.password_file_path = filedialog.asksaveasfilename(title="Create New Password File", defaultextension=".json", filetypes=[("JSON Files", "*.json")])
        if self.password_file_path:
            with open(self.password_file_path, "w") as f:
                json.dump({}, f)

    def load_passwords(self):
        if self.password_file_path and os.path.exists(self.password_file_path):
            with open(self.password_file_path, "r") as f:
                self.passwords = json.load(f)
                self.passwords = {site: self.decrypt(pw.encode()) for site, pw in self.passwords.items()}

    def save_to_file(self):
        if self.password_file_path:
            with open(self.password_file_path, "w") as f:
                encrypted_passwords = {site: self.encrypt(pw).decode() for site, pw in self.passwords.items()}
                json.dump(encrypted_passwords, f, indent=4)

    def encrypt(self, password):
        return self.cipher.encrypt(password.encode())

    def decrypt(self, encrypted_password):
        return self.cipher.decrypt(encrypted_password).decode()

    def save_password(self, site, password):
        if self.is_safe_input(site) and self.is_safe_input(password):
            self.passwords[site] = password
            self.save_to_file()

    def delete_password(self, site):
        if site in self.passwords:
            del self.passwords[site]
            self.save_to_file()
            return True
        return False

    @staticmethod
    def is_safe_input(user_input):
        allowed_special_chars = "!#$%&'()*+,-./:;<=\\>?@[]^_{|}~\"`"
        return isinstance(user_input, str) and all(c.isalnum() or c in (' ', '-', '_') or c in allowed_special_chars for c in user_input)

    def get_all_sites(self):
        return list(self.passwords.keys())

class App:
    def __init__(self, master):
        self.master = master
        master.title("ShadowKeys")
        master.geometry("400x680")
        master.resizable(False, False)

        
        self.title_label = ctk.CTkLabel(master, text="ShadowKeys Password Manager", font=("Arial", 20, "bold"))
        self.title_label.pack(pady=(15, 20))

        self.manager = PasswordManager()

        self.site_label = ctk.CTkLabel(master, text="Service / Website / App Name:")
        self.site_label.pack(pady=10)

        self.site_entry = ctk.CTkEntry(master, width=300)
        self.site_entry.pack(pady=5)

        self.password_label = ctk.CTkLabel(master, text="Password:")
        self.password_label.pack(pady=10)

        self.password_entry = ctk.CTkEntry(master, show="*", width=300)
        self.password_entry.pack(pady=5)

        self.show_password_button = ctk.CTkButton(master, text="Show", command=self.toggle_password, fg_color="#4158D0", hover_color="#993cda", border_color="#e7e7e7", border_width=2, width=200)
        self.show_password_button.pack(pady=10)

        self.save_button = ctk.CTkButton(master, text="Save Password", command=self.save_password, fg_color="#4158D0", hover_color="#993cda", border_color="#e7e7e7", border_width=2, width=200)
        self.save_button.pack(pady=10)

        self.load_button = ctk.CTkButton(master, text="Load Password", command=self.load_password, fg_color="#4158D0", hover_color="#993cda", border_color="#e7e7e7", border_width=2, width=200)
        self.load_button.pack(pady=10)

        self.copy_button = ctk.CTkButton(master, text="Copy to Clipboard", command=self.copy_to_clipboard, fg_color="#4158D0", hover_color="#993cda", border_color="#e7e7e7", border_width=2, width=200)
        self.copy_button.pack(pady=10)

        self.delete_button = ctk.CTkButton(master, text="Delete Password", command=self.delete_password, fg_color="#4158D0", hover_color="#993cda", border_color="#e7e7e7", border_width=2, width=200)
        self.delete_button.pack(pady=10)

        self.site_display = ctk.CTkTextbox(master, width=350, height=120)
        self.site_display.pack(pady=15)
        self.site_display.configure(state="disabled")

        self.update_site_display()

        self.disclaimer_button = ctk.CTkButton(master, text="Disclaimer & Code of Conduct", command=self.show_disclaimer, fg_color="#4158D0", hover_color="#993cda", border_color="#e7e7e7", border_width=2, width=200)
        self.disclaimer_button.pack(pady=10)

    def update_site_display(self):
        self.site_display.configure(state="normal")
        self.site_display.delete("1.0", ctk.END)
        sites = self.manager.get_all_sites()
        if sites:
            self.site_display.insert(ctk.END, "\n".join(sites))
        else:
            self.site_display.insert(ctk.END, "No saved services or apps.")
        self.site_display.configure(state="disabled")

    def toggle_password(self):
        if self.password_entry.cget("show") == "*":
            self.password_entry.configure(show="")
            self.show_password_button.configure(text="Hide")
        else:
            self.password_entry.configure(show="*")
            self.show_password_button.configure(text="Show")

    def save_password(self):
        site = self.site_entry.get()
        password = self.password_entry.get()
        if site and password:
            self.manager.save_password(site, password)
            messagebox.showinfo("Success", f"Password for {site} saved successfully!")
            self.update_site_display()

    def load_password(self):
        site = self.site_entry.get()
        if site in self.manager.passwords:
            self.password_entry.delete(0, ctk.END)
            self.password_entry.insert(0, self.manager.passwords[site])
        else:
            messagebox.showwarning("Not Found", f"No password found for {site}.")

    def copy_to_clipboard(self):
        site = self.site_entry.get()
        if site in self.manager.passwords:
            pyperclip.copy(self.manager.passwords[site])
            messagebox.showinfo("Success", f"Password for {site} copied to clipboard!")
        else:
            messagebox.showwarning("Not Found", f"No password found for {site}.")

    def delete_password(self):
        site = self.site_entry.get()
        if site and self.manager.delete_password(site):
            messagebox.showinfo("Success", f"Password for {site} deleted successfully!")
            self.update_site_display()
        else:
            messagebox.showwarning("Not Found", f"No password found for {site}.")

    def show_disclaimer(self):
        disclaimer_window = Toplevel(self.master)
        disclaimer_window.title("Disclaimer & Code of Conduct")
        disclaimer_window.geometry("450x200")
        disclaimer_window.configure(bg="black")
        disclaimer_window.resizable(False, False)
        disclaimer_text = """By using this tool, you agree to the following terms:

1. Do not share your key file with others.
2. Respect the privacy and security of others' data.
3. Use this tool at your own risk.
4. The developer is not responsible for any damage or loss.

Please follow all applicable laws and guidelines when using this tool."""
        disclaimer_label = ctk.CTkLabel(disclaimer_window, text=disclaimer_text, text_color="white", bg_color="black", justify="left", anchor="w")
        disclaimer_label.pack(padx=10, pady=10)


if __name__ == "__main__":
    root = ctk.CTk()
    app = App(root)
    root.mainloop()