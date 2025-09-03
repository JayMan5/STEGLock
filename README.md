# STEGLock - Secure Image Steganography

StegLock is a Python desktop application that allows you to securely hide (encode) and retrieve (decode) encrypted messages inside images using steganography and password-based encryption. The app features a modern GUI built with CustomTkinter.

## Features
- Hide (encode) secret messages inside images with password protection
- Retrieve (decode) and decrypt hidden messages from images
- Modern, user-friendly interface
- Uses strong encryption (Fernet/AES)

## Requirements
- Python 3.8+
- Packages:
  - customtkinter
  - tkinter (usually included with Python)
  - cryptography
  - stegano

## Installation
1. Install Python 3.8 or newer from [python.org](https://www.python.org/).
2. Install required packages:
   ```bash
   pip install customtkinter cryptography stegano
   ```

## Usage
1. Run the application:
   ```bash
   python "StegLock Ultimate.py"
   ```
2. Use the GUI to:
   - Select an image to hide a message in
   - Enter your secret message and a password
   - Save the output image
   - To decode, select an image and enter the password to reveal the hidden message

## Packaging as an EXE
To create a standalone Windows executable:
1. Install PyInstaller:
   ```powershell
   pip install pyinstaller
   ```
2. Run:
   ```powershell
   pyinstaller --onefile --noconsole --add-data "App Images;App Images" "StegLock Ultimate.py"
   ```
   The EXE will be in the `dist` folder.

## Notes
- The password is required for both encoding and decoding.
- Only PNG images are recommended for best results.
- All encryption is local; no data is sent over the internet.

## License
Apache 2.0

## Disclaimer
This software is provided for educational and research purposes only. The author is not responsible for any improper, illegal, or inappropriate use of this application. Users are solely responsible for complying with all applicable laws and regulations in their jurisdiction.


