import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from PIL import Image
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives import padding

# Function to convert data to binary format as string
def convert_to_bin(data):
    return ''.join(format(ord(i), '08b') for i in data)

# Function to modify the least significant bit of a pixel
def modify_pixel(pixel, bit):
    pixel = list(pixel)
    pixel[-1] = int(pixel[-1] & 254 | int(bit))
    return tuple(pixel)

# Function to encrypt the message using AES
def encrypt_message(message, password):
    password = password.encode()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
    return urlsafe_b64encode(salt + iv + encrypted_message).decode()

# Function to decrypt the message using AES
def decrypt_message(encrypted_message, password):
    password = password.encode()
    data = urlsafe_b64decode(encrypted_message.encode())
    salt = data[:16]
    iv = data[16:32]
    encrypted_message = data[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    return decrypted_message.decode()

# Function to check the image format and convert to PNG if necessary
def check_and_convert_image(image_path, output_path):
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"The image file {image_path} does not exist.")
    
    supported_formats = ('.png', '.bmp', '.tiff')
    if not image_path.lower().endswith(supported_formats):
        print(f"Converting {image_path} to PNG format...")
        image = Image.open(image_path)
        image.save(output_path, 'PNG')
        print(f"Converted image saved as {output_path}")
        return output_path
    return image_path

# Function to ensure the output path has a file extension
def ensure_file_extension(output_path, default_extension='.png'):
    if not any(output_path.endswith(ext) for ext in ['.png', '.bmp', '.tiff']):
        output_path += default_extension
    return output_path

# Function to read the contents of a document
def read_document(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The document file {file_path} does not exist.")
    
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.read()

# Function to hide data within an image using LSB
def hide_data(image_path, secret_message, password, output_path):
    output_path = ensure_file_extension(output_path)
    image_path = check_and_convert_image(image_path, output_path)
    
    encrypted_message = encrypt_message(secret_message, password)
    binary_message = convert_to_bin(encrypted_message)
    index = 0

    image = Image.open(image_path)
    pixels = list(image.getdata())
    new_pixels = []

    for pixel in pixels:
        if index < len(binary_message):
            new_pixel = modify_pixel(pixel, binary_message[index])
            new_pixels.append(new_pixel)
            index += 1
        else:
            new_pixels.append(pixel)

    new_image = Image.new(image.mode, image.size)
    new_image.putdata(new_pixels)
    new_image.save(output_path)
    messagebox.showinfo("Success", f"Message hidden successfully in {output_path}")

# Function to extract data from an image using LSB
def extract_data(image_path, password, save_as_file=False):
    image_path = check_and_convert_image(image_path, image_path)
    
    image = Image.open(image_path)
    pixels = list(image.getdata())
    binary_message = ''

    for pixel in pixels:
        binary_message += str(pixel[-1] & 1)

    binary_message = binary_message.split('00000000')[0]  # Split at null character
    encrypted_message = ''.join(chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8))
    secret_message = decrypt_message(encrypted_message, password)

    if save_as_file:
        output_file = filedialog.asksaveasfilename(title="Save Extracted File", defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as file:
                file.write(secret_message)
            messagebox.showinfo("Success", f"Extracted message saved to {output_file}")
    else:
        messagebox.showinfo("Extracted Message", secret_message)

# Function to reset the form
def reset_form():
    entry_message.delete(0, tk.END)
    entry_password.delete(0, tk.END)
    entry_output_path.delete(0, tk.END)
    entry_document_path.delete(0, tk.END)
    entry_image_path.delete(0, tk.END)

# Function to exit the application
def exit_app():
    root.destroy()

# Main GUI application
root = tk.Tk()
root.title("Steganography Tool")

# Get screen width and height
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

# Set window size to fit the screen
root.geometry(f"{screen_width}x{screen_height}")

# Create a frame for better layout management
frame = tk.Frame(root)
frame.pack(pady=20)

# Labels and entries
tk.Label(frame, text="Image Path:").grid(row=0, column=0, padx=10, pady=10)
entry_image_path = tk.Entry(frame, width=50)
entry_image_path.grid(row=0, column=1, padx=10, pady=10)
tk.Button(frame, text="Browse", command=lambda: entry_image_path.insert(0, filedialog.askopenfilename())).grid(row=0, column=2, padx=10, pady=10)

tk.Label(frame, text="Message:").grid(row=1, column=0, padx=10, pady=10)
entry_message = tk.Entry(frame, width=50)
entry_message.grid(row=1, column=1, padx=10, pady=10)

tk.Label(frame, text="Password:").grid(row=2, column=0, padx=10, pady=10)
entry_password = tk.Entry(frame, width=50, show='*')
entry_password.grid(row=2, column=1, padx=10, pady=10)

tk.Label(frame, text="Output Path:").grid(row=3, column=0, padx=10, pady=10)
entry_output_path = tk.Entry(frame, width=50)
entry_output_path.grid(row=3, column=1, padx=10, pady=10)
tk.Button(frame, text="Browse", command=lambda: entry_output_path.insert(0, filedialog.asksaveasfilename())).grid(row=3, column=2, padx=10, pady=10)

tk.Label(frame, text="Document Path:").grid(row=4, column=0, padx=10, pady=10)
entry_document_path = tk.Entry(frame, width=50)
entry_document_path.grid(row=4, column=1, padx=10, pady=10)
tk.Button(frame, text="Browse", command=lambda: entry_document_path.insert(0, filedialog.askopenfilename())).grid(row=4, column=2, padx=10, pady=10)

# Buttons
tk.Button(frame, text="Encrypt Message", command=lambda: hide_data(entry_image_path.get(), entry_message.get(), entry_password.get(), entry_output_path.get())).grid(row=5, column=0, padx=10, pady=10)
tk.Button(frame, text="Encrypt File", command=lambda: hide_data(entry_image_path.get(), read_document(entry_document_path.get()), entry_password.get(), entry_output_path.get())).grid(row=5, column=1, padx=10, pady=10)
tk.Button(frame, text="Extract Message", command=lambda: extract_data(entry_image_path.get(), entry_password.get())).grid(row=6, column=0, padx=10, pady=10)
tk.Button(frame, text="Extract File", command=lambda: extract_data(entry_image_path.get(), entry_password.get(), save_as_file=True)).grid(row=6, column=1, padx=10, pady=10)
tk.Button(frame, text="Reset", command=reset_form).grid(row=7, column=0, padx=10, pady=10)
tk.Button(frame, text="Exit", command=exit_app).grid(row=7, column=1, padx=10, pady=10)

root.mainloop()