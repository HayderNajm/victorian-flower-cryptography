# Victorian Flower Cryptography

A Python project that combines Victorian floriography with modern block cipher cryptography to send secret messages encoded in flower bouquets.

## Features

- Uses the PRESENT lightweight block cipher for encryption
- Maps encrypted messages to Victorian flower arrangements
- Interactive command-line interface for creating and decoding bouquets
- Includes a comprehensive Victorian flower dictionary
- Cryptographically secure random number generation

## How It Works

1. **Encryption**: Your secret message is encrypted using the PRESENT block cipher
2. **Flower Mapping**: The encrypted data is converted into a sequence of flowers using nibble encoding
3. **Bouquet Creation**: The flowers are arranged into a bouquet that can be shared
4. **Decoding**: The recipient uses the decryption key to convert the flowers back into the original message

## Installation

No external libraries required! This project uses only Python's standard library.

After Run 
Main Menu:
1. Create a secret message bouquet
2. Decode a secret message from a bouquet
3. View flower dictionary
4. Generate a secure key
5. View cipher information
6. Exit

Enter your choice (1-6): 1

==================================================
CREATE A SECRET MESSAGE BOUQUET
==================================================

Enter your secret message: Meet me at midnight

Key options:
1. Generate a secure random key
2. Provide my own key (10 bytes in base64)
Enter your choice (1-2): 1

Generated key (base64): oWLD5O9qt4jQ4fKj

🌸 VICTORIAN SECRET BOUQUET 🌸
========================================
1. Red Rose - Love, passion
2. Gardenia - Secret love
3. Lily of the Valley - Return of happiness
4. Ivy - Fidelity, marriage
5. Forget-me-not - True love, memories
6. Violet - Faithfulness, modesty
7. Lavender - Devotion
8. Tulip (red) - Declaration of love
========================================
Secret Message: Meet me at midnight
