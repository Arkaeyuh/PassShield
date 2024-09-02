# password_manager_gui.py

import tkinter as tk
from tkinter import messagebox, simpledialog
from password_manager_logic import generate_password, encrypt_password, decrypt_password, store_passwords, retrieve_passwords

PASSWORDS_FILE = "passwords.json"

# GUI Application
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PassShield Password Manager")

        # Load existing passwords
        self.encrypted_passwords = retrieve_passwords(PASSWORDS_FILE)

        # Labels and Entries
        self.master_key_label = tk.Label(root, text="Master Key:")
        self.master_key_label.pack(pady=5)
        self.master_key_entry = tk.Entry(root, show="*")
        self.master_key_entry.pack(pady=5)

        self.password_label = tk.Label(root, text="Generated Password:")
        self.password_label.pack(pady=5)
        self.password_entry = tk.Entry(root)
        self.password_entry.pack(pady=5)

        # Buttons
        self.generate_button = tk.Button(root, text="Generate Password", command=self.generate_password)
        self.generate_button.pack(pady=5)

        self.encrypt_button = tk.Button(root, text="Encrypt & Store Password", command=self.encrypt_store_password)
        self.encrypt_button.pack(pady=5)

        self.retrieve_button = tk.Button(root, text="Retrieve Password", command=self.retrieve_decrypt_password)
        self.retrieve_button.pack(pady=5)

        self.view_button = tk.Button(root, text="View All Passwords", command=self.view_passwords)
        self.view_button.pack(pady=5)

    def generate_password(self):
        password = generate_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        messagebox.showinfo("Success", "Password generated successfully!")

    def encrypt_store_password(self):
        master_key = self.master_key_entry.get()
        password = self.password_entry.get()

        if not master_key or not password:
            messagebox.showwarning("Warning", "Please provide both a master key and a password.")
            return

        label = simpledialog.askstring("Label", "Enter a label for this password:")
        if not label:
            messagebox.showwarning("Warning", "Please provide a label.")
            return

        encrypted_password = encrypt_password(password, master_key)
        self.encrypted_passwords[label] = encrypted_password
        store_passwords(PASSWORDS_FILE, self.encrypted_passwords)
        messagebox.showinfo("Success", "Password encrypted and stored successfully!")

    def retrieve_decrypt_password(self):
        master_key = self.master_key_entry.get()

        if not master_key:
            messagebox.showwarning("Warning", "Please provide a master key.")
            return

        label = simpledialog.askstring("Label", "Enter the label of the password to retrieve:")
        if label not in self.encrypted_passwords:
            messagebox.showwarning("Warning", "No password found with that label.")
            return

        try:
            encrypted_password = self.encrypted_passwords[label]
            decrypted_password = decrypt_password(encrypted_password, master_key)
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, decrypted_password)
            messagebox.showinfo("Success", "Password retrieved and decrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def view_passwords(self):
        password_list = "\n".join(self.encrypted_passwords.keys())
        messagebox.showinfo("Stored Passwords", f"Labels:\n{password_list}")

# Main function to start the Tkinter application
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
