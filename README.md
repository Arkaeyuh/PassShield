# PassShield

PassShield is a simple and secure password manager application built using Python. It provides functionalities to generate, encrypt, store, retrieve, and decrypt passwords securely. The GUI is created using `tkinter`, and password encryption is handled using the `pycryptodome` library.

## Features

- **Generate Random Passwords**: Create secure random passwords using cryptographic random generators.
- **Encrypt Passwords**: Securely encrypt passwords using AES (Advanced Encryption Standard) with GCM mode for authenticated encryption.
- **Store Encrypted Passwords**: Save encrypted passwords to a file securely.
- **Retrieve and Decrypt Passwords**: Load encrypted passwords from a file and decrypt them using a master key.

## Requirements

- Python 3
- `pycryptodome` library

## Installation

1. **Clone the Repository**:

    ```bash
    git clone https://github.com/arkaeyuh/PassShield.git
    cd PassShield
    ```

2. **Install the Required Python Libraries**:

    Install the `pycryptodome` library using pip:

    ```bash
    pip install pycryptodome
    ```

## Usage

1. **Run the Application**:

    Execute the `password_manager_gui.py` file to start the PassShield application:

    ```bash
    python password_manager_gui.py
    ```

2. **Using PassShield**:

    - **Master Key**: Enter a master key in the provided input field. This key is required to encrypt and decrypt your passwords.
    - **Generate Password**: Click the "Generate Password" button to create a new random password. The generated password will be displayed in the password field.
    - **Encrypt & Store Password**: After generating or entering a password, click this button to encrypt and store the password in a binary file (`passwords.bin`) using the provided master key.
    - **Retrieve & Decrypt Password**: Click this button to retrieve the encrypted password from the file and decrypt it using the provided master key.

## Project Structure

- `password_manager_logic.py`: Contains the core logic for generating, encrypting, decrypting, storing, and retrieving passwords.
- `password_manager_gui.py`: Contains the GUI implementation using `tkinter` and interacts with the logic defined in `password_manager_logic.py`.

## How It Works

- **Encryption**: PassShield uses AES encryption in GCM mode to ensure both confidentiality and integrity. A master key is used to derive a unique encryption key for each session using PBKDF2 with a salt.
- **Password Generation**: Random passwords are generated using secure cryptographic functions provided by the `pycryptodome` library.
- **Storage**: Encrypted passwords are stored in a binary file (`passwords.bin`) for security. Only someone with the correct master key can decrypt and access these passwords.

## Security Considerations

- Always remember your master key. If you lose it, you won't be able to decrypt your stored passwords.
- Use a strong master key to enhance security.
