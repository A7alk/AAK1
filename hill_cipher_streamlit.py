import numpy as np
from sympy import Matrix
import streamlit as st


        # Hill Cipher Functions with GUI Output
def mod_inverse(matrix, mod, step_output):
    try:
        inv_matrix = Matrix(matrix).inv_mod(mod)
        step_output.insert(END, f"\nModular Inverse of Key Matrix (mod {mod}):\n{inv_matrix}\n")
        return np.array(inv_matrix).astype(int)
    except:
        step_output.insert(END, "Matrix is not invertible under modulo {mod}.\n")
        return None

def matrix_mod_mult(matrix, vector, mod, step_output):
    # Display the matrix multiplication step in the text widget
    step_output.insert(END, f"Matrix:\n{matrix}\n")
    step_output.insert(END, f"Vector:\n{vector}\n")
    result = np.dot(matrix, vector)
    step_output.insert(END, f"Matrix Multiplication Result (before mod {mod}):\n{result}\n")
    result_mod = result % mod
    step_output.insert(END, f"Result after Modulo {mod} Operation:\n{result_mod}\n\n")
    return result_mod

def text_to_numeric(text, step_output):
    numeric = [ord(char.upper()) - ord('A') for char in text]
    step_output.insert(END, f"Text '{text}' to Numeric: {numeric}\n")
    return numeric

def numeric_to_text(numbers, step_output):
    text = ''.join([chr((num % 26) + ord('A')) for num in numbers])
    step_output.insert(END, f"Numeric {numbers} to Text: '{text}'\n")
    return text

def pad_text(text, size, step_output):
    step_output.insert(END, f"Original Text: '{text}'\n")
    while len(text) % size != 0:
        text += 'X'
    step_output.insert(END, f"Padded Text: '{text}' (to match matrix size {size})\n\n")
    return text

def hill_encrypt(plain_text, key_matrix, step_output):
    mod = 26
    plain_text = pad_text(plain_text, len(key_matrix), step_output)
    numeric_plain = text_to_numeric(plain_text, step_output)
    cipher_text = ''

    # Break text into chunks and encrypt using the key matrix
    for i in range(0, len(numeric_plain), len(key_matrix)):
        chunk = numeric_plain[i:i + len(key_matrix)]
        step_output.insert(END, f"\nEncrypting Chunk: {chunk}\n")
        encrypted_chunk = matrix_mod_mult(key_matrix, chunk, mod, step_output)
        cipher_text += numeric_to_text(encrypted_chunk, step_output)

    return cipher_text

def hill_decrypt(cipher_text, key_matrix, step_output):
    mod = 26
    step_output.insert(END, "\n--- Decryption Process ---\n")
    step_output.insert(END, f"Cipher Text: {cipher_text}\n\n")
    inv_key_matrix = mod_inverse(key_matrix, mod, step_output)
    if inv_key_matrix is None:
        return None

    numeric_cipher = text_to_numeric(cipher_text, step_output)
    plain_text = ''



# Break cipher text into chunks and decrypt using the inverse matrix
    for i in range(0, len(numeric_cipher), len(key_matrix)):
        chunk = numeric_cipher[i:i + len(key_matrix)]
        step_output.insert(END, f"\nDecrypting Chunk: {chunk}\n")
        decrypted_chunk = matrix_mod_mult(inv_key_matrix, chunk, mod, step_output)
        plain_text += numeric_to_text(decrypted_chunk, step_output)

    return plain_text

# Tkinter UI
def main():
    def encrypt_message():
        try:
            step_output.delete(1.0, END)  # Clear previous steps
            message = input_message.get().replace(" ", "").upper()
            size = int(input_size.get())

            key_values = list(map(int, key_matrix.get().split()))
            key_matrix_np = np.array(key_values).reshape(size, size)

            step_output.insert(END, "\n--- Encryption Process ---\n")
            step_output.insert(END, f"Key Matrix:\n{key_matrix_np}\n\n")

            encrypted_message = hill_encrypt(message, key_matrix_np, step_output)
            output_message.set(f"Encrypted Message: {encrypted_message}")
        except Exception as e:
            step_output.insert(END, f"Error during encryption: {e}\n")
            output_message.set("Error in encryption. Check inputs.")

    def decrypt_message():
        try:
            step_output.delete(1.0, END)  # Clear previous steps
            message = input_message.get().replace(" ", "").upper()
            size = int(input_size.get())

            key_values = list(map(int, key_matrix.get().split()))
            key_matrix_np = np.array(key_values).reshape(size, size)

            step_output.insert(END, "\n--- Decryption Process ---\n")
            step_output.insert(END, f"Key Matrix:\n{key_matrix_np}\n\n")

            decrypted_message = hill_decrypt(message, key_matrix_np, step_output)
            if decrypted_message:
                output_message.set(f"Decrypted Message: {decrypted_message}")
            else:
                output_message.set("Decryption failed. Key may not be invertible.")
        except Exception as e:
            step_output.insert(END, f"Error during decryption: {e}\n")
            output_message.set("Error in decryption. Check inputs.")

    # Setup the window
    root = Tk()
    root.title("Hill Cipher with Intermediate Steps in GUI")
    root.geometry("800x600")

     # Inputs and Outputs
    Label(root, text="Message: ").pack()
    input_message = StringVar()
    Entry(root, textvariable=input_message, width=50).pack()

    Label(root, text="Matrix Size (2 or 3): ").pack()
    input_size = StringVar()
    Entry(root, textvariable=input_size, width=5).pack()

    Label(root, text="Key Matrix (space-separated values): ").pack()
    key_matrix = StringVar()
    Entry(root, textvariable=key_matrix, width=50).pack()

    output_message = StringVar()
    Label(root, textvariable=output_message, wraplength=400).pack(pady=20)

    # Multi-line Text Widget for Intermediate Steps
    step_output = Text(root, height=15, width=90)
    step_output.pack(pady=10)

    # Buttons
    Button(root, text="Encrypt", command=encrypt_message).pack(pady=5)
    Button(root, text="Decrypt", command=decrypt_message).pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    main()

