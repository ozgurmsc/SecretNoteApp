from tkinter import *
from PIL import Image, ImageTk
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



def save_encrypt():
    title = title_input.get()
    message = textbox_input.get("1.0", END)
    master_key = master_key_input.get()

    if len(title) == 0 or len(message) == 0 or len(master_key) ==0:
        messagebox.showerror(title="Error!", message="Please enter all info ")
    else:
        #encryption
        message_encrypted = encode(master_key,message)
        try:
            with open("my_secret.txt","a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        except FileNotFoundError:
            with open("my_secret.txt","w") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        finally:
            title_input.delete(0, END)
            master_key_input.delete(0, END)
            textbox_input.delete("1.0", END)

def decrypt_notes():
    message_encrypted = textbox_input.get("1.0", END)
    master_secret = master_key_input.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showerror(title="Error!", message="Please enter all info")
    else:
        try:
            decrypted_message = decode(master_secret,message_encrypted)
            textbox_input.delete("1.0", END)
            textbox_input.insert("1.0", decrypted_message)
        except:
            messagebox.showerror(title="Error!", message="Please enter encrypted text")










win = Tk()
win.title("Secret Notes")
win.config(height=900, width=500)


#ui
title_input_label = Label(text="Enter your title",font=10)
title_input_label.place(relx=0.5, rely=0.25, anchor='center')
title_input = Entry(width=35)
title_input.place(relx=0.5, rely=0.3, anchor='center')
textbox_label = Label(text="Enter yout secret", font=10)
textbox_label.place(relx=0.5, rely=0.35, anchor='center')
textbox_input = Text(height=20, width=40)
textbox_input.place(relx=0.5, rely=0.58, anchor='center')
encrypt_button = Button(text="Save & Encrypt", command=save_encrypt)
encrypt_button.place(relx=0.5, rely=0.88, anchor='center')
decrypt_button = Button(text="Decrypt", command=decrypt_notes)
decrypt_button.place(relx=0.5, rely=0.92, anchor='center')
img1 =Image.open("topsecret.png")
resized= img1.resize((150,150), Image.LANCZOS)
new_img = ImageTk.PhotoImage(resized)
label = Label(win, image=new_img)
label.place(relx=0.5, rely=0.13, anchor='center')
master_key_label = Label( text="Enter your master key", font=10)
master_key_label.place(relx=0.5, rely=0.8, anchor='center')
master_key_input = Entry(width=35)
master_key_input.place(relx=0.5, rely=0.84, anchor='center')








win.mainloop()