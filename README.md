# Steganography Tool

This project is a **Steganography Tool** built using **Python** and **Tkinter** for securely hiding and extracting encrypted messages within images using **Least Significant Bit (LSB) steganography**. The tool also supports encrypting and hiding entire text documents inside images.

## Features
- **AES Encryption**: Encrypt messages before hiding them within images.
- **Steganography with LSB**: Modify the least significant bits of image pixels to store secret data.
- **Support for Image Conversion**: Converts non-PNG images to PNG format before processing.
- **Secure Extraction**: Decrypt and retrieve hidden messages from images.
- **Graphical User Interface (GUI)**: Built using **Tkinter** for ease of use.
- **Supports Text and File Steganography**: Allows hiding both user-input messages and text documents.

## Installation

### Prerequisites
Ensure you have the following installed:
- Python 3.x
- Required dependencies (install via pip)

### Install Dependencies
Run the following command to install necessary dependencies:
```sh
pip install pillow cryptography tkinter
```

## How It Works

### Encryption and Hiding Data
1. Select an image where you want to hide the message.
2. Enter the secret message or choose a document file.
3. Provide a strong password for AES encryption.
4. Choose an output path for the modified image.
5. Click **"Encrypt Message"** or **"Encrypt File"** to hide the data within the image.

### Extraction and Decryption
1. Select the steganographic image containing the hidden message.
2. Enter the password used for encryption.
3. Click **"Extract Message"** to retrieve and decrypt the message.
4. To save as a file, use the **"Extract File"** button.

## Project Structure
```
├── steganography_tool.py  # Main script containing encryption, decryption, and GUI code
├── README.md              # Documentation file
```

## Code Overview

### 1. **Encryption & Decryption**
- Uses **AES encryption** with a **password-derived key**.
- Utilizes **PBKDF2** for key derivation with a random **salt**.
- Messages are padded using **PKCS7** before encryption.
- The initialization vector (IV) ensures security in **CFB mode**.

### 2. **Steganography (LSB Encoding & Decoding)**
- Converts text into **binary** format.
- Embeds bits into the least significant bits of **image pixels**.
- Retrieves binary-encoded message and reconstructs the **original text**.

## Usage
### Running the Application
Execute the script:
```sh
python steganography_tool.py
```

## Example Queries
### Encrypt and Hide Message
```python
hide_data("image.png", "Secret Message", "password123", "output.png")
```

### Extract Hidden Message
```python
extract_data("output.png", "password123")
```

## Supported File Formats
- Images: PNG, BMP, TIFF (automatically converts JPEG & other formats to PNG)
- Documents: TXT (for hiding text files)

## Limitations
- Can only hide **text-based** messages.
- Image size determines the **maximum message size**.
- Lossy formats (JPEG) are not recommended.

## Future Enhancements
- Support for **other file types (PDF, DOCX, etc.)**.
- Improved **error handling** for incorrect passwords.
- GUI improvements with additional styling.

## License
This project is licensed under the **MIT License**.

---

## Author
**Chanukya Keerthi**

If you find any issues or have suggestions, feel free to contribute! 🚀


