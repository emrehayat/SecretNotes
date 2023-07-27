from tkinter import *
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def encryptMessage():
    title = my_entry.get()
    message = my_text.get("1.0",END)
    master_secret = my_entry_2.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
            messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        message_encrypted = encode(master_secret, message)

        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        finally:
            my_entry.delete(0, END)
            my_entry_2.delete(0, END)
            my_text.delete("1.0",END)

def decryptMessage():
    message_encrypted = my_text.get("1.0", END)
    master_secret = my_entry_2.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        try:
            decrypted_message = decode(master_secret,message_encrypted)
            my_text.delete("1.0", END)
            my_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")

window = Tk()
window.title("Secret Notes")
window.minsize(width=400, height=700)

photo = PhotoImage(file = "Top-secret-Stamp-Rubber-Grunge-on-transparent-background-PNG.png")
photo = photo.subsample(5, 5)
photo_label = Label(image=photo)
photo_label.place(x=140,y=20)

my_label = Label(text="Enter your title")
my_label.place(x=160,y=150)

my_entry = Entry()
my_entry.place(x=140, y=175)

my_label_2 = Label(text="Enter your secret")
my_label_2.place(x=150,y=225)

my_text = Text(width=25, height=15)
my_text.place(x=100, y=250)

my_label_3 = Label(text="Enter master key")
my_label_3.place(x=160,y=500)

my_entry_2 = Entry()
my_entry_2.place(x=140, y=525)

my_button = Button(text="Save and Encrypt", command=encryptMessage)
my_button.place(x=150, y=580)

my_button_2 = Button(text="Decrypt", bg="green", command=decryptMessage)
my_button_2.place(x=175, y=620)

window.mainloop()