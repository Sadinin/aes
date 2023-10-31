from tkinter import Tk, Label, Entry, Button

# S-Box substitution table for S-AES
S_BOX = [9, 4, 10, 11, 13, 1, 8, 5, 6, 2, 0, 3, 12, 14, 15, 7]


def saes_encrypt(input_data, key):
    # AddRoundKey step
    result = input_data ^ key

    # Substitution step using S-Box
    result = S_BOX[result]

    return result


def saes_decrypt(ciphertext, key):
    # Inverse Substitution step using inverse S-Box
    result = S_BOX.index(ciphertext)

    # AddRoundKey step
    result = result ^ key

    return result


def encrypt():
    input_data = int(input_entry.get(), 16)
    key = int(key_entry.get(), 16)
    ciphertext = saes_encrypt(input_data, key)
    output_label.config(text="Ciphertext: " + hex(ciphertext)[2:].zfill(2))


def decrypt():
    ciphertext = int(input_entry.get(), 16)
    key = int(key_entry.get(), 16)
    decrypted_text = saes_decrypt(ciphertext, key)
    output_label.config(text="Decrypted Text: " + hex(decrypted_text)[2:].zfill(2))


# GUI setup
root = Tk()
root.title("S-AES Encryption and Decryption")

input_label = Label(root, text="Enter 16-bit Data:")
input_label.pack()

input_entry = Entry(root)
input_entry.pack()

key_label = Label(root, text="Enter 16-bit Key:")
key_label.pack()

key_entry = Entry(root)
key_entry.pack()

encrypt_button = Button(root, text="Encrypt", command=encrypt)
encrypt_button.pack()

decrypt_button = Button(root, text="Decrypt", command=decrypt)
decrypt_button.pack()

output_label = Label(root, text="")
output_label.pack()

root.mainloop()
