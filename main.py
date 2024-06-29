import tkinter as tk
from tkinter import filedialog, messagebox
import numpy as np
from sympy import mod_inverse
import random

class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cipher and Decipher Application")

        # Initialize action attribute
        self.action = None

        # Add Menu
        self.menu = tk.Menu(root)
        root.config(menu=self.menu)
        
        self.theme_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Theme", menu=self.theme_menu)
        self.theme_menu.add_command(label="Light Mode", command=self.light_mode)
        self.theme_menu.add_command(label="Dark Mode", command=self.dark_mode)

        # Input Frame
        self.input_frame = tk.Frame(root)
        self.input_frame.pack(padx=10, pady=10)

        self.input_label = tk.Label(self.input_frame, text="Enter a phrase or word:")
        self.input_label.pack(side=tk.LEFT)

        self.input_text = tk.Entry(self.input_frame, width=50)
        self.input_text.pack(side=tk.LEFT, padx=5)

        self.browse_button = tk.Button(self.input_frame, text="Browse", command=self.browse_file)
        self.browse_button.pack(side=tk.LEFT)

        # Action Buttons Frame
        self.action_frame = tk.Frame(root)
        self.action_frame.pack(padx=10, pady=10)

        self.cipher_button = tk.Button(self.action_frame, text="Cipher", command=lambda: self.choose_algorithm("cipher"))
        self.cipher_button.pack(side=tk.LEFT, padx=5)

        self.decipher_button = tk.Button(self.action_frame, text="Decipher", command=lambda: self.choose_algorithm("decipher"))
        self.decipher_button.pack(side=tk.LEFT, padx=5)

        # Cipher Algorithm Buttons Frame
        self.algorithm_frame = tk.Frame(root)
        self.algorithm_frame.pack(padx=10, pady=10)

        self.algorithms = ["Caesar Cipher", "Vigenere", "Affine", "Hill", "Substitution Cipher", "OTP", "RSA"]
        for algo in self.algorithms:
            button = tk.Button(self.algorithm_frame, text=algo, command=lambda a=algo: self.get_key(a))
            button.pack(side=tk.LEFT, padx=5, pady=5)

        # Key Input Frame
        self.key_frame = tk.Frame(root)
        self.key_frame.pack(padx=10, pady=10)

        self.key_label = tk.Label(self.key_frame, text="Enter the key(s) if required:")
        self.key_label.pack(side=tk.LEFT)

        self.key_text = tk.Entry(self.key_frame, width=50)
        self.key_text.pack(side=tk.LEFT, padx=5)

        # Exit Button Frame
        self.exit_frame = tk.Frame(root)
        self.exit_frame.pack(padx=10, pady=10)

        self.exit_button = tk.Button(self.exit_frame, text="Exit", command=root.quit)
        self.exit_button.pack(pady=5)

        # Footer Frame
        self.footer_frame = tk.Frame(root)
        self.footer_frame.pack(padx=10, pady=10)

        self.footer_label = tk.Label(self.footer_frame, text="Constantinos Tzokas©️ 2024 - All rights Reserved", font=("Arial", 10))
        self.footer_label.pack()

        # Set initial theme
        self.light_mode()

    def light_mode(self):
        self.root.config(bg="white")
        for frame in [self.input_frame, self.action_frame, self.algorithm_frame, self.key_frame, self.exit_frame, self.footer_frame]:
            frame.config(bg="white")
        for widget in self.input_frame.winfo_children() + self.action_frame.winfo_children() + self.algorithm_frame.winfo_children() + self.key_frame.winfo_children() + self.exit_frame.winfo_children() + self.footer_frame.winfo_children():
            if isinstance(widget, tk.Label):
                widget.config(bg="white", fg="black")
            elif isinstance(widget, tk.Entry):
                widget.config(bg="white", fg="black", insertbackground="black")
            elif isinstance(widget, tk.Button):
                widget.config(bg="white", fg="black")

    def dark_mode(self):
        self.root.config(bg="black")
        for frame in [self.input_frame, self.action_frame, self.algorithm_frame, self.key_frame, self.exit_frame, self.footer_frame]:
            frame.config(bg="black")
        for widget in self.input_frame.winfo_children() + self.action_frame.winfo_children() + self.algorithm_frame.winfo_children() + self.key_frame.winfo_children() + self.exit_frame.winfo_children() + self.footer_frame.winfo_children():
            if isinstance(widget, tk.Label):
                widget.config(bg="black", fg="white")
            elif isinstance(widget, tk.Entry):
                widget.config(bg="black", fg="white", insertbackground="white")
            elif isinstance(widget, tk.Button):
                widget.config(bg="black", fg="white")

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'r') as file:
                self.input_text.insert(0, file.read())

    def choose_algorithm(self, action):
        self.action = action
        messagebox.showinfo("Action", f"Please choose an algorithm to {action} the text")

    def get_key(self, algorithm):
        self.algorithm = algorithm
        key = self.key_text.get()
        if self.algorithm == "Caesar Cipher" and not key.isdigit():
            messagebox.showerror("Error", "Key must be a number for Caesar Cipher")
            self.prompt_for_correct_key_or_exit()
            return
        if self.algorithm == "Vigenere" and not key.isalpha():
            messagebox.showerror("Error", "Key must be alphabetic for Vigenere Cipher")
            self.prompt_for_correct_key_or_exit()
            return
        if self.algorithm == "Affine":
            keys = key.split(',')
            if len(keys) != 2 or not all(k.isdigit() for k in keys):
                messagebox.showerror("Error", "Keys for Affine Cipher must be two integers separated by a comma")
                self.prompt_for_correct_key_or_exit()
                return
            a, b = int(keys[0]), int(keys[1])
            if self.gcd(a, 26) != 1:
                messagebox.showerror("Error", "Key 'a' must be coprime with 26 for Affine Cipher")
                self.prompt_for_correct_key_or_exit()
                return
        if self.algorithm == "Hill":
            key = key.lower().replace(' ', '')
            key_length = len(key)
            if key_length != 4 and key_length != 9:
                messagebox.showerror("Error", "Key length must be 4 (2x2 matrix) or 9 (3x3 matrix) for Hill Cipher")
                self.prompt_for_correct_key_or_exit()
                return
            if key_length == 4:
                key_matrix = np.array([ord(char) - ord('a') for char in key]).reshape(2, 2)
            else:
                key_matrix = np.array([ord(char) - ord('a') for char in key]).reshape(3, 3)
            if not self.is_invertible(key_matrix):
                messagebox.showerror("Error", "Key matrix must be invertible for Hill Cipher")
                self.prompt_for_correct_key_or_exit()
                return
        if self.algorithm == "Substitution Cipher" and len(key) != 26:
            messagebox.showerror("Error", "Key must be 26 characters long for Substitution Cipher")
            self.prompt_for_correct_key_or_exit()
            return
        if self.algorithm == "OTP" and len(key) < len(self.input_text.get()):
            messagebox.showerror("Error", "Key must be at least as long as the input text for OTP")
            self.prompt_for_correct_key_or_exit()
            return
        if self.action == "cipher":
            self.cipher_text(algorithm, key)
        elif self.action == "decipher":
            self.decipher_text(algorithm, key)

    def cipher_text(self, algorithm, key):
        input_text = self.input_text.get()
        if algorithm == "Caesar Cipher":
            ciphered_text = self.caesar_cipher(input_text, int(key))
            messagebox.showinfo("Cipher Result", f"Ciphered text: {ciphered_text}")
        elif algorithm == "Vigenere":
            ciphered_text = self.vigenere_cipher(input_text, key, encrypt=True)
            messagebox.showinfo("Cipher Result", f"Ciphered text: {ciphered_text}")
        elif algorithm == "Affine":
            a, b = map(int, key.split(','))
            ciphered_text = self.affine_cipher(input_text, a, b, encrypt=True)
            messagebox.showinfo("Cipher Result", f"Ciphered text: {ciphered_text}")
        elif algorithm == "Hill":
            key = key.lower().replace(' ', '')
            key_length = len(key)
            if key_length == 4:
                key_matrix = np.array([ord(char) - ord('a') for char in key]).reshape(2, 2)
            else:
                key_matrix = np.array([ord(char) - ord('a') for char in key]).reshape(3, 3)
            ciphered_text = self.hill_cipher(input_text, key_matrix, encrypt=True)
            messagebox.showinfo("Cipher Result", f"Ciphered text: {ciphered_text}")
        elif algorithm == "Substitution Cipher":
            ciphered_text = self.substitution_cipher(input_text, key, encrypt=True)
            messagebox.showinfo("Cipher Result", f"Ciphered text: {ciphered_text}")
        elif algorithm == "OTP":
            ciphered_text = self.otp_cipher(input_text, key, encrypt=True)
            messagebox.showinfo("Cipher Result", f"Ciphered text: {ciphered_text}")
        elif algorithm == "RSA":
            ciphered_text = self.rsa_cipher(input_text, encrypt=True)
            messagebox.showinfo("Cipher Result", f"Ciphered text: {ciphered_text}")

    def decipher_text(self, algorithm, key):
        input_text = self.input_text.get()
        if algorithm == "Caesar Cipher":
            deciphered_text = self.caesar_cipher(input_text, -int(key))
            messagebox.showinfo("Decipher Result", f"Deciphered text: {deciphered_text}")
        elif algorithm == "Vigenere":
            deciphered_text = self.vigenere_cipher(input_text, key, encrypt=False)
            messagebox.showinfo("Decipher Result", f"Deciphered text: {deciphered_text}")
        elif algorithm == "Affine":
            a, b = map(int, key.split(','))
            deciphered_text = self.affine_cipher(input_text, a, b, encrypt=False)
            messagebox.showinfo("Decipher Result", f"Deciphered text: {deciphered_text}")
        elif algorithm == "Hill":
            key = key.lower().replace(' ', '')
            key_length = len(key)
            if key_length == 4:
                key_matrix = np.array([ord(char) - ord('a') for char in key]).reshape(2, 2)
            else:
                key_matrix = np.array([ord(char) - ord('a') for char in key]).reshape(3, 3)
            deciphered_text = self.hill_cipher(input_text, key_matrix, encrypt=False)
            messagebox.showinfo("Decipher Result", f"Deciphered text: {deciphered_text}")
        elif algorithm == "Substitution Cipher":
            deciphered_text = self.substitution_cipher(input_text, key, encrypt=False)
            messagebox.showinfo("Decipher Result", f"Deciphered text: {deciphered_text}")
        elif algorithm == "OTP":
            deciphered_text = self.otp_cipher(input_text, key, encrypt=False)
            messagebox.showinfo("Decipher Result", f"Deciphered text: {deciphered_text}")
        elif algorithm == "RSA":
            deciphered_text = self.rsa_cipher(input_text, encrypt=False)
            messagebox.showinfo("Decipher Result", f"Deciphered text: {deciphered_text}")

    def caesar_cipher(self, text, shift):
        result = ""
        for i in range(len(text)):
            char = text[i]
            if char.isupper():
                result += chr((ord(char) + shift - 65) % 26 + 65)
            else:
                result += chr((ord(char) + shift - 97) % 26 + 97)
        return result

    def vigenere_cipher(self, text, key, encrypt=True):
        result = ""
        key_length = len(key)
        key_as_int = [ord(i) for i in key]
        text_as_int = [ord(i) for i in text]
        for i in range(len(text_as_int)):
            if encrypt:
                value = (text_as_int[i] + key_as_int[i % key_length]) % 26
            else:
                value = (text_as_int[i] - key_as_int[i % key_length]) % 26
            result += chr(value + 65)
        return result

    def affine_cipher(self, text, a, b, encrypt=True):
        result = ""
        if encrypt:
            for char in text:
                if char.isalpha():
                    char_code = ord(char.lower()) - ord('a')
                    new_char_code = (a * char_code + b) % 26
                    result += chr(new_char_code + ord('a'))
                else:
                    result += char
        else:
            a_inv = mod_inverse(a, 26)
            for char in text:
                if char.isalpha():
                    char_code = ord(char.lower()) - ord('a')
                    new_char_code = (a_inv * (char_code - b)) % 26
                    result += chr(new_char_code + ord('a'))
                else:
                    result += char
        return result

    def hill_cipher(self, text, key_matrix, encrypt=True):
        text = text.lower().replace(' ', '')
        if len(key_matrix) == 2:
            while len(text) % 2 != 0:
                text += 'x'
            n = 2
        else:
            while len(text) % 3 != 0:
                text += 'x'
            n = 3

        text_vector = [ord(char) - ord('a') for char in text]
        result_vector = []
        for i in range(0, len(text_vector), n):
            block = np.array(text_vector[i:i+n]).reshape(n, 1)
            if encrypt:
                result_block = np.dot(key_matrix, block) % 26
            else:
                key_matrix_inv = mod_inverse(key_matrix, 26)
                result_block = np.dot(key_matrix_inv, block) % 26
            result_vector.extend(result_block.flatten())
        result = ''.join(chr(int(num) + ord('a')) for num in result_vector)
        return result

    def substitution_cipher(self, text, key, encrypt=True):
        alphabet = 'abcdefghijklmnopqrstuvwxyz'
        if encrypt:
            key_map = {alphabet[i]: key[i] for i in range(26)}
        else:
            key_map = {key[i]: alphabet[i] for i in range(26)}
        result = ''.join(key_map[char] if char in key_map else char for char in text.lower())
        return result

    def otp_cipher(self, text, key, encrypt=True):
        result = ""
        for i in range(len(text)):
            if encrypt:
                result += chr((ord(text[i]) + ord(key[i])) % 256)
            else:
                result += chr((ord(text[i]) - ord(key[i])) % 256)
        return result

    def rsa_cipher(self, text, encrypt=True):
        # Dummy RSA key pairs for demonstration; for real applications, use securely generated keys.
        e, d, n = 65537, 413557, 2147483647
        if encrypt:
            return ' '.join(str(pow(ord(char), e, n)) for char in text)
        else:
            try:
                return ''.join(chr(pow(int(char), d, n)) for char in text.split())
            except ValueError:
                messagebox.showerror("Error", "Invalid input for RSA decryption. Please provide numeric input.")
                return ""

    def gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a

    def is_invertible(self, matrix):
        det = int(np.round(np.linalg.det(matrix))) % 26
        if det == 0 or self.gcd(det, 26) != 1:
            return False
        return True

    def prompt_for_correct_key_or_exit(self):
        response = messagebox.askretrycancel("Invalid Key", "The key you entered is invalid. Would you like to retry with a different key or cancel?")
        if response == False:
            self.root.quit()

if __name__ == "__main__":
    root = tk.Tk()
    app = CipherApp(root)
    root.mainloop()
