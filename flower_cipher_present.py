import base64
import secrets
from typing import List, Dict, Tuple, Optional

class PresentCipher:
    """
    Implementation of the PRESENT block cipher (lightweight cipher).
    Block size: 64 bits
    Key size: 80 bits (or 128 bits, but we'll use 80-bit for this implementation)
    Rounds: 31
    """
    
    # PRESENT S-box (4-bit input to 4-bit output)
    SBOX = [
        0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
    ]
    
    # PRESENT permutation layer (bit permutation)
    # pLayer[i] = position where bit i moves to
    PLAYERS = [
        0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
        4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
        8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
        12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
    ]
    
    def __init__(self, key: bytes):
        """Initialize with a 10-byte (80-bit) key."""
        if len(key) != 10:
            raise ValueError("Key must be 10 bytes (80 bits)")
        
        self.key = key
        self.round_keys = self._key_schedule()
        self.block_size = 8  # 64 bits = 8 bytes
    
    def _key_schedule(self) -> List[bytes]:
        """Generate 31 round keys from the master key."""
        # Convert key to list of 80 bits
        key_bits = []
        for byte in self.key:
            key_bits.extend([(byte >> i) & 1 for i in range(7, -1, -1)])
        
        round_keys = []
        
        for i in range(1, 32):  # 31 rounds
            # Extract 64 bits for the round key (bits 0 to 63)
            round_key_bits = key_bits[:64]
            round_key = 0
            for bit in round_key_bits:
                round_key = (round_key << 1) | bit
            round_keys.append(round_key.to_bytes(8, byteorder='big'))
            
            # Update key for next round
            # 1. Rotate left by 61 bits
            key_bits = key_bits[61:] + key_bits[:61]
            
            # 2. Apply S-box to leftmost 4 bits
            nibble = (key_bits[0] << 3) | (key_bits[1] << 2) | (key_bits[2] << 1) | key_bits[3]
            nibble = self.SBOX[nibble]
            key_bits[0] = (nibble >> 3) & 1
            key_bits[1] = (nibble >> 2) & 1
            key_bits[2] = (nibble >> 1) & 1
            key_bits[3] = nibble & 1
            
            # 3. XOR round counter (5 bits) to bits 19-15
            round_counter = i
            for j in range(5):
                key_bits[19 - j] ^= (round_counter >> j) & 1
        
        return round_keys
    
    def _sbox_layer(self, state: int) -> int:
        """Apply the S-box to each 4-bit nibble of the state."""
        result = 0
        for i in range(16):  # 16 nibbles in 64 bits
            nibble = (state >> (4 * i)) & 0xF
            result |= self.SBOX[nibble] << (4 * i)
        return result
    
    def _p_layer(self, state: int) -> int:
        """Apply the bit permutation layer."""
        result = 0
        for i in range(64):
            if (state >> i) & 1:
                result |= 1 << self.PLAYERS[i]
        return result
    
    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt an 8-byte block."""
        if len(block) != 8:
            raise ValueError("Block must be 8 bytes")
        
        # Convert block to 64-bit integer
        state = int.from_bytes(block, byteorder='big')
        
        # 31 rounds
        for i in range(31):
            # AddRoundKey
            round_key = int.from_bytes(self.round_keys[i], byteorder='big')
            state ^= round_key
            
            # sBoxLayer
            state = self._sbox_layer(state)
            
            # pLayer (except in last round)
            if i < 30:
                state = self._p_layer(state)
        
        return state.to_bytes(8, byteorder='big')
    
    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt an 8-byte block."""
        if len(block) != 8:
            raise ValueError("Block must be 8 bytes")
        
        # Convert block to 64-bit integer
        state = int.from_bytes(block, byteorder='big')
        
        # 31 rounds in reverse
        for i in range(30, -1, -1):
            # Inverse pLayer (except in first round)
            if i < 30:
                # Inverse permutation: PLAYERS_inv[PLAYERS[i]] = i
                inv_state = 0
                for j in range(64):
                    if (state >> j) & 1:
                        inv_state |= 1 << self.PLAYERS.index(j)
                state = inv_state
            
            # Inverse sBoxLayer
            inv_sbox = [0] * 16
            for idx, val in enumerate(self.SBOX):
                inv_sbox[val] = idx
            
            result = 0
            for j in range(16):  # 16 nibbles in 64 bits
                nibble = (state >> (4 * j)) & 0xF
                result |= inv_sbox[nibble] << (4 * j)
            state = result
            
            # AddRoundKey
            round_key = int.from_bytes(self.round_keys[i], byteorder='big')
            state ^= round_key
        
        return state.to_bytes(8, byteorder='big')
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt bytes using ECB mode with PKCS#7 padding."""
        # Pad the plaintext
        padding_length = self.block_size - (len(plaintext) % self.block_size)
        padded = plaintext + bytes([padding_length] * padding_length)
        
        # Encrypt in ECB mode
        ciphertext = b''
        for i in range(0, len(padded), self.block_size):
            block = padded[i:i+self.block_size]
            encrypted_block = self.encrypt_block(block)
            ciphertext += encrypted_block
        
        return ciphertext
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt bytes using ECB mode with PKCS#7 padding."""
        if len(ciphertext) % self.block_size != 0:
            raise ValueError("Invalid ciphertext length")
        
        # Decrypt in ECB mode
        plaintext = b''
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i+self.block_size]
            decrypted_block = self.decrypt_block(block)
            plaintext += decrypted_block
        
        # Remove padding
        padding_length = plaintext[-1]
        if padding_length > self.block_size:
            raise ValueError("Invalid padding")
        return plaintext[:-padding_length]


class SecureFlowerCipher:
    """
    Combines Victorian floriography with the PRESENT block cipher.
    """
    
    # Victorian flower meanings dictionary
    FLOWER_DICTIONARY = {
        'Red Rose': 'Love, passion',
        'White Rose': 'Purity, innocence',
        'Pink Rose': 'Grace, admiration',
        'Yellow Rose': 'Friendship, jealousy',
        'Lily of the Valley': 'Return of happiness',
        'Forget-me-not': 'True love, memories',
        'Ivy': 'Fidelity, marriage',
        'Gardenia': 'Secret love',
        'Lavender': 'Devotion',
        'Violet': 'Faithfulness, modesty',
        'Tulip (red)': 'Declaration of love',
        'Hyacinth (blue)': 'Constancy',
        'Hyacinth (purple)': 'Sorrow, regret',
        'Sweet Pea': 'Goodbye, departure',
        'Zinnia': 'Thoughts of absent friends',
        'Sunflower': 'Adoration, loyalty',
        'Daisy': 'Innocence, new beginnings',
        'Orchid': 'Luxury, beauty',
        'Peony': 'Prosperity, romance',
        'Chrysanthemum': 'Friendship, optimism',
        'Marigold': 'Passion, creativity',
        'Poppy': 'Remembrance, sacrifice',
        'Daffodil': 'New beginnings, rebirth',
        'Carnation (red)': 'Deep love, admiration',
        'Carnation (white)': 'Pure love, good luck',
        'Carnation (pink)': 'Gratitude, motherly love',
        'Lily (white)': 'Purity, majesty',
        'Lily (orange)': 'Passion, confidence',
        'Magnolia': 'Dignity, perseverance',
        'Camellia (red)': 'Passion, desire',
        'Camellia (pink)': 'Longing, admiration',
        'Camellia (white)': 'Adoration, perfection',
        'Azalea': 'Femininity, fragility',
        'Bluebell': 'Gratitude, constancy',
        'Buttercup': 'Humility, neatness',
        'Dahlia': 'Elegance, inner strength',
        'Freesia': 'Trust, friendship',
        'Gladiolus': 'Strength, moral integrity',
        'Hibiscus': 'Delicate beauty, femininity',
        'Holly': 'Protection, domestic happiness',
        'Honeysuckle': 'Devotion, happiness',
        'Iris': 'Wisdom, courage',
        'Jasmine': 'Grace, elegance',
        'Larkspur': 'Strong attachment, lightness',
        'Lilac': 'First love, confidence',
        'Lupine': 'Imagination, admiration',
        'Marigold': 'Passion, creativity',
        'Narcissus': 'Egotism, self-love',
        'Pansy': 'Loving thoughts, remembrance',
        'Rhododendron': 'Beware, danger',
        'Rosemary': 'Remembrance, fidelity',
        'Snapdragon': 'Deception, graciousness',
        'Stock': 'Lasting beauty, happy life',
        'Tansy': 'Resistance, declaration of war',
        'Verbena': 'Sensitivity, healing',
        'Wisteria': 'Poetic beauty, welcome',
        'Yarrow': 'Good health, everlasting love',
        'Yucca': 'Protection, purification',
        'Zinnia (mixed)': 'Thinking of absent friends',
        'Aster': 'Patience, elegance',
        'Begonia': 'Caution, deep thinking',
        'Bleeding Heart': 'Passionate love, compassion',
        'Bluebonnet': 'Valor, pride',
        'Bougainvillea': 'Passion, dramatic flair',
        'Calla Lily': 'Magnificent beauty, purity',
        'Cosmos': 'Peace, tranquility',
        'Dandelion': 'Happiness, wishes come true',
        'Foxglove': 'Insincerity, ambition',
        'Goldenrod': 'Encouragement, success',
        'Heather': 'Protection, admiration',
        'Hellebore': 'Scandal, anxiety',
        'Hibiscus': 'Delicate beauty, femininity',
        'Hollyhock': 'Ambition, fertility',
        'Ivy (variegated)': 'Fidelity, wedded love',
        'Laurel': 'Glory, accomplishment',
        'Lemon Balm': 'Sympathy, kindness',
        'Lobelia': 'Malevolence, ill will',
        'Magnolia': 'Dignity, perseverance',
        'Morning Glory': 'Affection, mortality',
        'Myrtle': 'Love, marriage',
        'Oleander': 'Caution, beware',
        'Pachysandra': 'Protection, security',
        'Periwinkle': 'Early friendship, memories',
        'Petunia': 'Anger, resentment',
        'Phlox': 'Unification, sweet dreams',
        'Primrose': 'Young love, eternal existence',
        'Ranunculus': 'Radiant charm, attractiveness',
        'Snowdrop': 'Hope, consolation',
        'Spider Flower': 'Elope with me',
        'Tiger Lily': 'Wealth, pride',
        'Verbena': 'Sensitivity, healing',
        'Violet (white)': 'Candor, innocence',
        'Violet (yellow)': 'Rural happiness, worthiness',
        'Wallflower': 'Faithful in adversity',
        'Water Lily': 'Purity, enlightenment',
        'Wheat': 'Prosperity, fruitfulness',
        'Wisteria': 'Poetic beauty, welcome',
        'Yarrow': 'Good health, everlasting love',
        'Yucca': 'Protection, purification'
    }
    
    def __init__(self, key: Optional[bytes] = None):
        """Initialize with an optional 10-byte (80-bit) key."""
        if key is None:
            # Generate cryptographically secure key (80-bit)
            self.key = secrets.token_bytes(10)
        else:
            if len(key) != 10:
                raise ValueError("Key must be 10 bytes (80 bits)")
            self.key = key
        
        self.cipher = PresentCipher(self.key)
        self.flower_list = list(self.FLOWER_DICTIONARY.keys())
    
    def _bytes_to_flowers(self, data: bytes) -> List[str]:
        """
        Convert bytes to a sequence of flowers using nibble encoding.
        Each byte is split into two 4-bit nibbles, each mapped to a flower.
        """
        flowers = []
        for byte in data:
            # Split byte into two nibbles
            high_nibble = (byte >> 4) & 0x0F
            low_nibble = byte & 0x0F
            
            # Map each nibble to a flower
            flowers.append(self.flower_list[high_nibble % len(self.flower_list)])
            flowers.append(self.flower_list[low_nibble % len(self.flower_list)])
        
        return flowers
    
    def _flowers_to_bytes(self, flowers: List[str]) -> bytes:
        """
        Convert a sequence of flowers back to bytes using nibble encoding.
        Each pair of flowers represents one byte.
        """
        if len(flowers) % 2 != 0:
            raise ValueError("Odd number of flowers - must be even for nibble encoding")
        
        byte_array = bytearray()
        for i in range(0, len(flowers), 2):
            # Get the two flowers for this byte
            flower_high = flowers[i]
            flower_low = flowers[i+1]
            
            # Get their indices
            high_index = self.flower_list.index(flower_high)
            low_index = self.flower_list.index(flower_low)
            
            # Extract the nibbles (using modulo 16 to get 4 bits)
            high_nibble = high_index % 16
            low_nibble = low_index % 16
            
            # Combine into a byte
            byte = (high_nibble << 4) | low_nibble
            byte_array.append(byte)
        
        return bytes(byte_array)
    
    def create_bouquet(self, message: str) -> Dict:
        """
        Create a bouquet that encodes a secret message using PRESENT cipher.
        
        Returns:
            Dictionary with:
            - 'bouquet': List of flowers
            - 'key': Encryption key (base64 encoded)
        """
        # Encrypt the message
        message_bytes = message.encode('utf-8')
        ciphertext = self.cipher.encrypt(message_bytes)
        
        # Convert encrypted data to flowers
        bouquet = self._bytes_to_flowers(ciphertext)
        
        return {
            'bouquet': bouquet,
            'key': base64.b64encode(self.key).decode('utf-8')
        }
    
    def decode_bouquet(self, bouquet: List[str], key_b64: str) -> str:
        """
        Decode a secret message from a bouquet using PRESENT cipher.
        
        Returns:
            Decrypted message
        """
        # Decode base64 key
        key = base64.b64decode(key_b64)
        
        # Create a new cipher instance with the key
        cipher = PresentCipher(key)
        
        # Convert flowers back to bytes
        ciphertext = self._flowers_to_bytes(bouquet)
        
        # Decrypt the message
        plaintext_bytes = cipher.decrypt(ciphertext)
        return plaintext_bytes.decode('utf-8')
    
    def print_bouquet(self, bouquet: List[str], message: str = None):
        """Print a beautiful representation of the bouquet with optional message."""
        print("\n🌸 VICTORIAN SECRET BOUQUET 🌸")
        print("=" * 40)
        
        for i, flower in enumerate(bouquet):
            meaning = self.FLOWER_DICTIONARY.get(flower, "Unknown meaning")
            print(f"{i+1}. {flower} - {meaning}")
        
        print("=" * 40)
        if message:
            print(f"Secret Message: {message}")
        print("\n")
    
    def print_flower_menu(self):
        """Print a menu of available flowers."""
        print("\nAvailable Flowers:")
        print("-" * 40)
        for i, flower in enumerate(self.flower_list, 1):
            print(f"{i:2d}. {flower}")
        print("-" * 40)


def get_user_choice(options: List[str], prompt: str) -> int:
    """Get a valid choice from the user."""
    while True:
        try:
            choice = int(input(prompt))
            if 1 <= choice <= len(options):
                return choice
            print(f"Please enter a number between 1 and {len(options)}")
        except ValueError:
            print("Please enter a valid number.")


def get_flower_list(cipher: SecureFlowerCipher) -> List[str]:
    """Get a list of flowers from the user."""
    cipher.print_flower_menu()
    print("\nEnter flower numbers (comma separated) or 'done' to finish:")
    flower_numbers = []
    
    while True:
        user_input = input("> ").strip()
        if user_input.lower() == 'done':
            break
        
        try:
            numbers = [int(num.strip()) for num in user_input.split(',')]
            for num in numbers:
                if 1 <= num <= len(cipher.flower_list):
                    flower_numbers.append(num)
                else:
                    print(f"Invalid flower number: {num}. Skipping.")
        except ValueError:
            print("Invalid input. Please enter numbers separated by commas or 'done'.")
    
    return [cipher.flower_list[num-1] for num in flower_numbers]


def generate_secure_key():
    """Generate a cryptographically secure key and display its properties."""
    print("\n" + "="*50)
    print("SECURE KEY GENERATION")
    print("="*50)
    
    # Generate an 80-bit key
    key = secrets.token_bytes(10)
    print(f"Generated Key (hex): {key.hex()}")
    print(f"Key Length: {len(key) * 8} bits")
    print(f"Key Entropy: {len(key) * 8} bits (maximum for this key size)")
    
    # Verify key randomness (simplified test)
    print("\nKey Randomness Verification:")
    # Count byte distribution
    byte_counts = [0] * 256
    for byte in key:
        byte_counts[byte] += 1
    
    # Calculate chi-squared statistic (simplified)
    expected = len(key) / 256
    chi_squared = sum((count - expected) ** 2 / expected for count in byte_counts)
    print(f"Chi-squared statistic: {chi_squared:.2f}")
    
    if chi_squared < 50:  # Rough threshold for randomness
        print("✓ Key appears to have good randomness")
    else:
        print("⚠ Key may not have sufficient randomness")
    
    return key


def main():
    """Interactive Victorian Flower Cryptography program with PRESENT."""
    print("🔐 SECURE VICTORIAN FLOWER CRYPTOGRAPHY 🔐")
    print("Combining 19th-century floriography with PRESENT block cipher\n")
    
    while True:
        print("\nMain Menu:")
        print("1. Create a secret message bouquet")
        print("2. Decode a secret message from a bouquet")
        print("3. View flower dictionary")
        print("4. Generate a secure key")
        print("5. View cipher information")
        print("6. Exit")
        
        choice = get_user_choice([1, 2, 3, 4, 5, 6], "\nEnter your choice (1-6): ")
        
        if choice == 1:
            # Create a bouquet
            print("\n" + "="*50)
            print("CREATE A SECRET MESSAGE BOUQUET")
            print("="*50)
            
            # Get message from user
            message = input("\nEnter your secret message: ").strip()
            if not message:
                print("Message cannot be empty!")
                continue
            
            # Ask about key
            print("\nKey options:")
            print("1. Generate a secure random key")
            print("2. Provide my own key (10 bytes in base64)")
            key_choice = get_user_choice([1, 2], "Enter your choice (1-2): ")
            
            if key_choice == 1:
                key = generate_secure_key()
                cipher = SecureFlowerCipher(key)
                print(f"\nGenerated key (base64): {base64.b64encode(key).decode('utf-8')}")
            else:
                key_b64 = input("\nEnter your key (base64): ").strip()
                try:
                    key = base64.b64decode(key_b64)
                    if len(key) != 10:
                        print("Key must be 10 bytes!")
                        continue
                    cipher = SecureFlowerCipher(key)
                except Exception as e:
                    print(f"Invalid key: {e}")
                    continue
            
            # Create bouquet
            bouquet_data = cipher.create_bouquet(message)
            cipher.print_bouquet(bouquet_data['bouquet'], message)
            print(f"Decryption Key: {bouquet_data['key']}")
            
            # Test decoding
            print("\nTesting decryption...")
            decoded = cipher.decode_bouquet(bouquet_data['bouquet'], bouquet_data['key'])
            print(f"Decoded message: {decoded}")
            
        elif choice == 2:
            # Decode a bouquet
            print("\n" + "="*50)
            print("DECODE A SECRET MESSAGE FROM A BOUQUET")
            print("="*50)
            
            # Get key from user
            key_b64 = input("\nEnter the decryption key (base64): ").strip()
            try:
                key = base64.b64decode(key_b64)
                if len(key) != 10:
                    print("Key must be 10 bytes!")
                    continue
            except Exception as e:
                print(f"Invalid key: {e}")
                continue
            
            # Get flowers from user
            cipher = SecureFlowerCipher(key)
            print("\nSelect flowers for the bouquet:")
            flowers = get_flower_list(cipher)
            
            if len(flowers) % 2 != 0:
                print("\nError: Number of flowers must be even!")
                continue
            
            # Decode the message
            try:
                decoded = cipher.decode_bouquet(flowers, key_b64)
                cipher.print_bouquet(flowers)
                print(f"Decoded Message: {decoded}")
            except Exception as e:
                print(f"Error decoding message: {e}")
                
        elif choice == 3:
            # View flower dictionary
            print("\n" + "="*50)
            print("VICTORIAN FLOWER DICTIONARY")
            print("="*50)
            
            cipher = SecureFlowerCipher()
            for flower, meaning in cipher.FLOWER_DICTIONARY.items():
                print(f"{flower}: {meaning}")
                
        elif choice == 4:
            # Generate secure key
            key = generate_secure_key()
            print(f"\nKey (base64): {base64.b64encode(key).decode('utf-8')}")
            
        elif choice == 5:
            # View cipher information
            print("\n" + "="*50)
            print("CIPHER INFORMATION")
            print("="*50)
            print("Cipher: PRESENT")
            print("Block Size: 64 bits")
            print("Key Size: 80 bits")
            print("Rounds: 31")
            print("Mode: ECB (Electronic Codebook)")
            print("Padding: PKCS#7")
            print("\nCryptographic Properties:")
            print("- PRESENT is a lightweight block cipher")
            print("- Designed for resource-constrained environments")
            print("- Resistant to known cryptanalytic attacks")
            print("- Provides 80-bit security level")
            print("\nRandom Number Generation:")
            print("- Uses cryptographically secure random number generators")
            print("- Generated keys have maximum entropy")
            
        elif choice == 6:
            # Exit
            print("\nThank you for using Secure Victorian Flower Cryptography!")
            break


if __name__ == "__main__":
    main()