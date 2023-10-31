from tkinter import Tk, Label, Entry, Button

# S-Box substitution table for S-AES
S_BOX = [9, 4, 10, 11, 13, 1, 8, 5, 6, 2, 0, 3, 12, 14, 15, 7]


def saes_encrypt(input_data, key):
    # AddRoundKey step
    result = int(input_data, 2) ^ int(key, 2)

    # Substitution step using S-Box
    result = S_BOX[result]

    return format(result, '04b')


def saes_decrypt(ciphertext, key):
    # Inverse Substitution step using inverse S-Box
    result = S_BOX.index(int(ciphertext, 2))

    # AddRoundKey step
    result = result ^ int(key, 2)

    return format(result, '04b')


def encrypt():
    input_data = input_entry.get()
    key = key_entry.get()
    ciphertext = saes_encrypt(input_data, key)
    output_label.config(text="Ciphertext: " + ciphertext)


def decrypt():
    ciphertext = input_entry.get()
    key = key_entry.get()
    decrypted_text = saes_decrypt(ciphertext, key)
    output_label.config(text="Decrypted Text: " + decrypted_text)


# GUI setup
root = Tk()
root.title("S-AES Encryption and Decryption")

input_label = Label(root, text="Enter 16-bit Binary Data:")
input_label.pack
input_entry = Entry(root)
input_entry.pack()

key_label = Label(root, text="Enter 16-bit Binary Key:")
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
