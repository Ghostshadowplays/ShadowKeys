import customtkinter as ctk
import secrets
import string
import re
import os
from io import BytesIO
import requests
import pyperclip  # Import pyperclip for clipboard functionality
from PIL import Image, ImageTk
import pygame  # Import pygame

# Initialize the main application window with dark theme settings
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# Initialize pygame mixer
pygame.mixer.init()

# Function to download sound from a URL and return the file path
def download_sound(url):
    response = requests.get(url)
    if response.status_code == 200:
        sound_file_path = "button_click.mp3"
        with open(sound_file_path, 'wb') as sound_file:
            sound_file.write(response.content)
        return sound_file_path
    else:
        print("Failed to download sound.")
        return None

# Download the click sound
click_sound_path = download_sound("https://raw.githubusercontent.com/Ghostshadowplays/Ghostyware-Logo/main/button_click.mp3")

# Password generation and strength checking functions
def generate_password():
    length = int(length_var.get())
    use_upper = upper_var.get()
    use_digits = digit_var.get()
    use_special = special_var.get()
    
    characters = string.ascii_lowercase
    if use_upper:
        characters += string.ascii_uppercase
    if use_digits:
        characters += string.digits
    if use_special:
        characters += string.punctuation
    
    password = ''.join(secrets.choice(characters) for _ in range(length))
    password_entry.delete(0, "end")
    password_entry.insert(0, password)
    
    # Play click sound
    if click_sound_path:
        pygame.mixer.music.load(click_sound_path)
        pygame.mixer.music.play()

    # Update the strength label based on the generated password
    password_strength, analysis = check_password_strength(password)
    strength_label.configure(text="Strength: " + password_strength)
    strength_analysis_label.configure(text=analysis)  # Update the strength analysis label
    update_strength_bar(password_strength)
    password_history.append(password)
    update_password_history()

def check_password_strength(password):
    length = len(password)
    has_upper = re.search(r"[A-Z]", password)
    has_lower = re.search(r"[a-z]", password)
    has_digit = re.search(r"[0-9]", password)
    has_special = re.search(r"[!@#\$%\^&\*\(\)_\+\-=\[\]\{\};':\",.<>/?|]", password)
    
    score = 0
    analysis = []

    if length >= 8:
        score += 1
        analysis.append("✓ Length: Sufficient")
    else:
        analysis.append("✗ Length: Too short (min 8 characters)")
    
    if length >= 12:
        score += 1
        analysis.append("✓ Length: Excellent")
    
    if has_upper:
        score += 1
        analysis.append("✓ Uppercase letters included")
    else:
        analysis.append("✗ No uppercase letters")

    if has_lower:
        score += 1
        analysis.append("✓ Lowercase letters included")
    else:
        analysis.append("✗ No lowercase letters")

    if has_digit:
        score += 1
        analysis.append("✓ Digits included")
    else:
        analysis.append("✗ No digits")

    if has_special:
        score += 1
        analysis.append("✓ Special characters included")
    else:
        analysis.append("✗ No special characters")
    
    if score <= 2:
        return "Weak", "\n".join(analysis)
    elif score == 3 or score == 4:
        return "Moderate", "\n".join(analysis)
    else:
        return "Strong", "\n".join(analysis)

# Set up the main window
root = ctk.CTk()
root.title("Ghosty's Password Generator")
root.geometry("470x730")  # Adjusted height for additional labels
root.resizable(False, False)

# Function to load images
def load_image_from_url(image_url, size=(85, 85)):
    try:
        response = requests.get(image_url)
        response.raise_for_status()
        image = Image.open(BytesIO(response.content))
        image = image.resize(size, Image.LANCZOS)
        return ImageTk.PhotoImage(image)
    except Exception as e:
        print(f"Error loading image from URL {image_url}: {e}")
        return None

def create_label_with_image(root, text, image_url, text_color="#993cda"):
    loaded_image = load_image_from_url(image_url, size=(85, 85))
    if loaded_image:
        label = ctk.CTkLabel(root, text=text, font=("Helvetica", 25, "bold"),
                             image=loaded_image, text_color=text_color, compound="left")
        label.image = loaded_image  # Keep a reference
        label.pack(pady=(30, 0))
        return label
    else:
        print("Failed to load image.")

# Logo URL and creating label with logo
logo_url = "https://raw.githubusercontent.com/Ghostshadowplays/Ghostyware-Logo/main/GhostywareLogo.png"
create_label_with_image(root, "Ghosty's Password Generator", logo_url)

# Password Options Frame
options_frame = ctk.CTkFrame(root)
options_frame.pack(pady=(10, 20), padx=20, fill="x")

# Variables for options
length_var = ctk.IntVar(value=12)
upper_var = ctk.BooleanVar(value=True)
digit_var = ctk.BooleanVar(value=True)
special_var = ctk.BooleanVar(value=True)

# Label and entry for password length
ctk.CTkLabel(options_frame, text="Password Length:", text_color="#e7e7e7").pack(pady=5)
ctk.CTkEntry(options_frame, textvariable=length_var, width=60, fg_color="#444444", text_color="#ffffff", border_width=2).pack()

# Checkboxes for character options
ctk.CTkCheckBox(options_frame, text="Include Uppercase Letters", variable=upper_var, hover_color="#993cda", border_color="#e7e7e7", text_color="#e7e7e7", fg_color="#4158D0").pack()
ctk.CTkCheckBox(options_frame, text="Include Digits", variable=digit_var, hover_color="#993cda", border_color="#e7e7e7", text_color="#e7e7e7", fg_color="#4158D0").pack()
ctk.CTkCheckBox(options_frame, text="Include Special Characters", variable=special_var, hover_color="#993cda", border_color="#e7e7e7", text_color="#e7e7e7", fg_color="#4158D0").pack()

# Button to generate password
generate_button = ctk.CTkButton(
    root, 
    text="Generate Password", 
    command=generate_password, 
    fg_color="#4158D0", 
    hover_color="#993cda", 
    border_color="#e7e7e7", 
    border_width=2, 
    width=200
)
generate_button.pack(pady=10)

# Entry to display generated password
password_entry = ctk.CTkEntry(root, width=200, font=('Arial', 14), fg_color="#444444", text_color="#ffffff")
password_entry.pack()

# Button to copy password to clipboard
def copy_to_clipboard():
    password = password_entry.get()
    pyperclip.copy(password)
    copy_button.configure(text="Copied!", text_color="#00FF00")  # Change button text to indicate success

copy_button = ctk.CTkButton(
    root,
    text="Copy to Clipboard",
    command=copy_to_clipboard,
    fg_color="#4158D0",
    hover_color="#993cda",
    border_color="#e7e7e7",
    border_width=2,
    width=200
)
copy_button.pack(pady=10)

# Label for password strength
strength_label = ctk.CTkLabel(root, text="Strength: ", font=('Arial', 12), text_color="#e7e7e7")
strength_label.pack(pady=5)

# Progress bar for password strength
strength_bar = ctk.CTkProgressBar(root, width=200, height=10, fg_color="#444444")
strength_bar.pack(pady=5)

def update_strength_bar(strength):
    if strength == "Weak":
        strength_bar.set(0.33)
        strength_bar.configure(progress_color="#D03535")  # Red for weak
    elif strength == "Moderate":
        strength_bar.set(0.66)
        strength_bar.configure(progress_color="#FFFF00")  # Yellow for moderate
    else:
        strength_bar.set(1.0)
        strength_bar.configure(progress_color="#00FF00")  # Green for strong

# Label for strength analysis
strength_analysis_label = ctk.CTkLabel(root, text="", font=('Arial', 10), text_color="#e7e7e7")
strength_analysis_label.pack(pady=5)

# Password History
password_history = []

def update_password_history():
    history_text = "\n".join(password_history[-5:])  # Show the last 5 passwords
    history_label.configure(text=f"Password History:\n{history_text}")

# Password history label
history_label = ctk.CTkLabel(root, text="Password History:\n", font=('Arial', 12), text_color="#e7e7e7")
history_label.pack(pady=10)

# Toggle for password visibility
def toggle_password():
    if password_entry.cget("show") == "":
        password_entry.configure(show="•")
    else:
        password_entry.configure(show="")

toggle_button = ctk.CTkButton(
    root, 
    text="Show Password", 
    command=toggle_password, 
    fg_color="#4158D0", 
    hover_color="#993cda", 
    border_color="#e7e7e7", 
    border_width=2, 
    width=200
)
toggle_button.pack(pady=10)

# Disclaimer button and window
def show_disclaimer():
    disclaimer_window = ctk.CTkToplevel(root)
    disclaimer_window.title("Code of Conduct Disclaimer")
    disclaimer_window.geometry("400x300")
    ctk.CTkLabel(disclaimer_window, text="Code of Conduct:", font=("Helvetica", 16)).pack(pady=10)
    ctk.CTkLabel(disclaimer_window, text=(
        "1. Respect others.\n"
        "2. Use appropriate language.\n"
        "3. No spamming.\n"
        "4. Share knowledge, not personal information.\n"
        "5. Be inclusive and welcoming.\n"
        "6. Report any issues.\n"
        "7. Have fun and enjoy!\n"
    ), font=("Helvetica", 12)).pack(pady=10)
    ctk.CTkButton(disclaimer_window, text="Close", command=disclaimer_window.destroy).pack(pady=10)

disclaimer_button = ctk.CTkButton(
    root, 
    text="Disclaimer", 
    command=show_disclaimer, 
    fg_color="#4158D0", 
    hover_color="#993cda", 
    border_color="#e7e7e7", 
    border_width=2, 
    width=200
)
disclaimer_button.pack(pady=10)

# Run the application
root.mainloop()
