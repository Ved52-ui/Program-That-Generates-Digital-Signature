import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization

class DigitalSignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Signature with Public Key Infrastructure")
        self.root.geometry("400x400")

        self.private_key = None
        self.public_key = None

        # Create the UI components
        self.label = tk.Label(root, text="Digital Signature Generator")
        self.label.pack(pady=10)

        self.generate_keys_button = tk.Button(root, text="Generate RSA Keys", command=self.generate_keys)
        self.generate_keys_button.pack(pady=10)

        self.sign_button = tk.Button(root, text="Sign Document", command=self.sign_document, state=tk.DISABLED)
        self.sign_button.pack(pady=10)

        self.verify_button = tk.Button(root, text="Verify Signature", command=self.verify_signature, state=tk.DISABLED)
        self.verify_button.pack(pady=10)

        self.status_label = tk.Label(root, text="")
        self.status_label.pack(pady=10)

    def generate_keys(self):
        # Generate RSA keys
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()

        # Serialize keys (Optional, if you want to store them)
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Save keys to files
        with open("private_key.pem", "wb") as f:
            f.write(private_pem)

        with open("public_key.pem", "wb") as f:
            f.write(public_pem)

        messagebox.showinfo("Info", "RSA Keys Generated and Saved as PEM Files")
        self.status_label.config(text="Keys generated.")
        self.sign_button.config(state=tk.NORMAL)
        self.verify_button.config(state=tk.NORMAL)

    def sign_document(self):
        file_path = filedialog.askopenfilename(title="Select Document to Sign")
        if file_path:
            with open(file_path, "rb") as f:
                document = f.read()

            signature = self.private_key.sign(
                document,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            with open("signature.bin", "wb") as sig_file:
                sig_file.write(signature)

            messagebox.showinfo("Info", f"Document signed and signature saved as 'signature.bin'")
            self.status_label.config(text="Document signed successfully.")

    def verify_signature(self):
        doc_file_path = filedialog.askopenfilename(title="Select Document to Verify")
        sig_file_path = filedialog.askopenfilename(title="Select Signature to Verify")

        if doc_file_path and sig_file_path:
            with open(doc_file_path, "rb") as f:
                document = f.read()

            with open(sig_file_path, "rb") as sig_file:
                signature = sig_file.read()

            try:
                self.public_key.verify(
                    signature,
                    document,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                messagebox.showinfo("Success", "Signature is valid.")
                self.status_label.config(text="Signature is valid.")
            except Exception as e:
                messagebox.showerror("Error", "Signature is invalid.")
                self.status_label.config(text="Signature is invalid.")

if __name__ == "__main__":
    root = tk.Tk()
    app = DigitalSignatureApp(root)
    root.mainloop()
