from customtkinter import *
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from cryptography.fernet import Fernet, InvalidToken
import base64
import hashlib
from stegano import lsb

root = CTk()
root.title("StegLock - Secure Image Steganography")
root.geometry("650x500")

# --- Password Encryption Helpers ---
def generate_key(password: str) -> bytes:
    hashed = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

def encrypt_message(message: str, password: str) -> str:
    key = generate_key(password)
    fernet = Fernet(key)
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message: str, password: str) -> str:
    key = generate_key(password)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message.encode()).decode()

def clear_inputs():
    input_path.set("")
    output_path.set("")
    message_text.delete('1.0', 'end')
    password_entry.delete(0, 'end')
    decoder_input_path.set("")

# --- GUI Logic ---
def encoder():
    input_image = input_path.get()
    output_image = output_path.get()
    message = message_text.get('1.0', 'end-1c')
    password = password_entry.get()

    if not password:
        messagebox.showerror("Error", "Password required to encrypt message.")
        return

    try:
        encrypted_msg = encrypt_message(message, password)
        secret = lsb.hide(input_image, encrypted_msg)
        secret.save(output_image)
        result_label.configure(text="✅ Message successfully encrypted and hidden.")
        clear_inputs()
    except Exception as e:
        result_label.configure(text=f"Error: {e}")

def decoder():
    input_image_path = decoder_input_path.get()
    password = password_entry.get()

    if not password:
        messagebox.showerror("Error", "Password required to decrypt message.")
        return

    try:
        encrypted_msg = lsb.reveal(input_image_path)
        if not encrypted_msg:
            decoder_result_label.configure(text="No message found in image.")
            return

        decrypted_msg = decrypt_message(encrypted_msg, password)
        decoder_result_label.configure(text=f"🔓 Decrypted Message:\n{decrypted_msg}")
        clear_inputs()
    except InvalidToken:
        decoder_result_label.configure(text="❌ Incorrect password. Access Denied.")
    except Exception as e:
        decoder_result_label.configure(text=f"Error: {e}")

def fileopen():
    file_path = filedialog.askopenfilename()
    input_path.set(file_path)

def fileopen_decoder():
    file_path = filedialog.askopenfilename()
    decoder_input_path.set(file_path)

def img2():
    file_path = filedialog.asksaveasfilename(defaultextension=".png")
    output_path.set(file_path)

def toggle_password_visibility():
    if password_entry.cget("show") == "*":
        password_entry.configure(show="")
        show_password_button.configure(text="Hide")
    else:
        password_entry.configure(show="*")
        show_password_button.configure(text="Show")

# --- Variables ---
input_path = StringVar()
output_path = StringVar()
decoder_input_path = StringVar()

# --- UI Components ---
input_label = CTkLabel(root, text="Select Image:", text_color="White")
input_entry = CTkEntry(root, textvariable=input_path, fg_color="Black", border_color="Purple", border_width=2)
input_button = CTkButton(root, text="Open", corner_radius=32, command=fileopen, fg_color="Purple")

output_label = CTkLabel(root, text="Save Image As:", text_color="White")
output_entry = CTkEntry(root, textvariable=output_path, fg_color="Black", border_color="Purple", border_width=2)
output_button = CTkButton(root, text="Save As", corner_radius=32, command=img2, fg_color="Purple")

message_label = CTkLabel(root, text="Message to Hide:", text_color="White")
message_text = CTkTextbox(root, width=450, fg_color="Black", corner_radius=16, border_color="Purple", border_width=2)

password_label = CTkLabel(root, text="Encryption Password:", text_color="White")
password_entry = CTkEntry(root, show="*", fg_color="Black", border_color="Purple", border_width=2, width=200)
show_password_button = CTkButton(root, text="Show", width=60, command=toggle_password_visibility, fg_color="Purple")

encode_button = CTkButton(root, text="🔐 Encode", text_color="White", fg_color="Purple", corner_radius=32, command=encoder)
result_label = CTkLabel(root, text="", text_color="White")

decoded_message_label = CTkLabel(root, text="🔎 Decode Message:", text_color="White")
decoded_input_label = CTkLabel(root, text="Select Image:", text_color="White")
decoded_input_entry = CTkEntry(root, textvariable=decoder_input_path, fg_color="Black", border_color="Purple", border_width=2)
decoder_input_button = CTkButton(root, text="Open", fg_color="Purple", corner_radius=32, command=fileopen_decoder)
decoder_button = CTkButton(root, text="🔓 Decode", fg_color="Purple", font=("Arial", 13), corner_radius=32, command=decoder)
decoder_result_label = CTkLabel(root, text="", height=5, text_color="White")

# --- Layout ---
root.grid_columnconfigure((0, 1, 2), weight=1)

input_label.grid(row=0, column=0)
input_entry.grid(row=0, column=1)
input_button.grid(row=0, column=2)

output_label.grid(row=1, column=0)
output_entry.grid(row=1, column=1)
output_button.grid(row=1, column=2)

message_label.grid(row=2, column=0, columnspan=3)
message_text.grid(row=3, column=0, columnspan=3)

password_label.grid(row=4, column=0)
password_entry.grid(row=4, column=1)
show_password_button.grid(row=4, column=2)

encode_button.grid(row=5, column=0, columnspan=3)
result_label.grid(row=6, column=0, columnspan=3)

decoded_message_label.grid(row=7, column=0, columnspan=3)
decoded_input_label.grid(row=8, column=0)
decoded_input_entry.grid(row=8, column=0, columnspan=2)
decoder_input_button.grid(row=8, column=2)

decoder_button.grid(row=9, column=0, columnspan=3)
decoder_result_label.grid(row=10, column=0, columnspan=3)

root.mainloop()
