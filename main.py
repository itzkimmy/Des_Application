import tkinter as gui
from tkinter import messagebox
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64
import os

class DESApplication:
    def __init__(self, root):
        self.root = root
        self.root.title("DES Application")
        self.root.geometry("500x400")
        self.create_widgets()
    
    #Gui Creation
    def create_widgets(self):
        #Text Input
        gui.Label(self.root, text="Enter Text:").pack(pady=(10, 0))
        self.text_input = gui.Text(self.root, height=5, width=50)
        self.text_input.pack(padx=10)
        
        #Key Frame
        key_frame = gui.Frame(self.root)
        key_frame.pack()
        
        #Key Input
        gui.Label(key_frame, text="8-Character Key:").grid(row=0, column=0, sticky="w", padx=5)
        self.key_input = gui.Entry(key_frame, width=50, show="*")
        self.key_input.grid(row=1, column=0, pady=5)

        #Show Key kbutton
        self.show_key = gui.IntVar()
        self.show_key_check = gui.Checkbutton(key_frame, text="Show Key", variable=self.show_key,
                                        command=self.toggle_key_visibility)
        self.show_key_check.grid(row=1, column=1, sticky="w")
        
        #Button Frame
        button_frame = gui.Frame(self.root)
        button_frame.pack(pady=10)
        
        #Buttons
        gui.Button(
            button_frame, text="Encrypt", width=10, command=self.encrypt,bg="#4287f5", fg="white", activebackground="#6ba3ff"
        ).grid(row=0, column=0, padx=5)

        gui.Button(
            button_frame, text="Decrypt", width=10, command=self.decrypt,bg="#f5e342", fg="black", activebackground="#fff176" 
        ).grid(row=0, column=1, padx=5)

        gui.Button(
            button_frame, text="Clear", width=10, command=self.clear, bg="#f54242", fg="white", activebackground="#ff6b6b" 
        ).grid(row=0, column=2, padx=5)

        gui.Button(
            button_frame, text="Generate Key", width=10, command=self.generate_key, bg="#a042f5", fg="white",activebackground="#c176ff"
        ).grid(row=0, column=3, padx=5)
        
        #Result
        gui.Label(self.root, text="Result:").pack()
        self.result_output = gui.Text(self.root, height=5, width=50)
        self.result_output.pack(padx=10, pady=(0, 10))
    
    #key visibility function
    def toggle_key_visibility(self):
        if self.show_key.get():
            self.key_input.config(show="")
        else:
            self.key_input.config(show="*")
    
    #Encryption functions
    def encrypt(self):
        text = self.text_input.get("1.0", gui.END).strip()
        key = self.key_input.get()
        
        if not text:
            messagebox.showerror("Error", "Please enter text to encrypt")
            return
        
        if len(key) != 8:
            messagebox.showerror("Error", "Key must be exactly 8 characters long")
            return
        
        try:
            cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
            padded_text = pad(text.encode('utf-8'), DES.block_size)
            encrypted = cipher.encrypt(padded_text)
            self.result_output.delete("1.0", gui.END)
            self.result_output.insert("1.0", base64.b64encode(encrypted).decode('utf-8'))
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    #Decryption functions
    def decrypt(self):
        text = self.text_input.get("1.0", gui.END).strip()
        key = self.key_input.get()
        
        if not text:
            messagebox.showerror("Error", "Please enter text to decrypt")
            return
        
        if len(key) != 8:
            messagebox.showerror("Error", "Key must be exactly 8 characters long")
            return
        
        try:
            cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
            encrypted = base64.b64decode(text)
            decrypted = unpad(cipher.decrypt(encrypted), DES.block_size)
            self.result_output.delete("1.0", gui.END)
            self.result_output.insert("1.0", decrypted.decode('utf-8'))
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    #Generate Key function
    def generate_key(self):
        random_key = base64.b64encode(os.urandom(8)).decode('utf-8')[:8]
        self.key_input.delete(0, gui.END)
        self.key_input.insert(0, random_key)
        self.show_key.set(1)
        self.key_input.config(show="")
        messagebox.showinfo("New Key", f"Generated key: {random_key}")

    #Clear function
    def clear(self):
        self.text_input.delete("1.0", gui.END)
        self.result_output.delete("1.0", gui.END)

#Launcher
if __name__ == "__main__":
    root = gui.Tk()
    app = DESApplication(root)
    root.mainloop()