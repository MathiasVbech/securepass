#!/usr/bin/env python3
"""
Password Generator Module

This module provides functionality to generate secure passwords and memorable passphrases
with various configuration options.
"""

import random
import string
import os
import argparse
from typing import List, Dict, Any, Tuple, Optional

class PasswordGenerator:
    """Password generator with various options for strong passwords and passphrases"""
    
    # Word lists for memorable passphrases
    WORD_LISTS = {
        'common': None,  # Will be loaded from file
        'short': None,   # Words with length < 5
        'medium': None,  # Words with length 5-7
        'long': None     # Words with length > 7
    }
    
    # Standard character sets
    CHARS_LOWER = string.ascii_lowercase
    CHARS_UPPER = string.ascii_uppercase
    CHARS_DIGITS = string.digits
    CHARS_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?/"
    
    @classmethod
    def load_word_list(cls, word_list_path: str) -> bool:
        """Load word list from file"""
        try:
            with open(word_list_path, 'r', encoding='utf-8') as f:
                # Process each line
                words = []
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                        
                    # Handle EFF wordlist format (number + tab + word)
                    if '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            word = parts[1].strip().lower()
                    else:
                        word = line.lower()
                    
                    if word:
                        words.append(word)
                
                # Main word list
                cls.WORD_LISTS['common'] = words
                
                # Create filtered lists by length
                cls.WORD_LISTS['short'] = [w for w in words if len(w) < 5]
                cls.WORD_LISTS['medium'] = [w for w in words if 5 <= len(w) <= 7]
                cls.WORD_LISTS['long'] = [w for w in words if len(w) > 7]
                
                return True
        except Exception as e:
            print(f"Error loading word list: {e}")
            return False
    
    @staticmethod
    def generate_random_password(
        length: int = 16,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
        avoid_similar: bool = False,
        avoid_ambiguous: bool = False
    ) -> str:
        """Generate a random password with specified options"""
        # Build character set
        charset = ""
        if use_lowercase:
            charset += PasswordGenerator.CHARS_LOWER
        if use_uppercase:
            charset += PasswordGenerator.CHARS_UPPER
        if use_digits:
            charset += PasswordGenerator.CHARS_DIGITS
        if use_symbols:
            charset += PasswordGenerator.CHARS_SYMBOLS
        
        # Apply filters if requested
        if avoid_similar:
            # Remove similar looking characters
            for c in "il1Lo0O":
                charset = charset.replace(c, "")
        
        if avoid_ambiguous:
            # Remove ambiguous symbols
            for c in "`'\"|,.;:><()[]{}/\\":
                charset = charset.replace(c, "")
        
        # Ensure we have at least some characters to work with
        if not charset:
            raise ValueError("No character set available after applying all filters")
        
        # Create constraints to ensure password has requested character types
        constraints = []
        if use_lowercase and any(c in PasswordGenerator.CHARS_LOWER for c in charset):
            constraints.append(random.choice([c for c in charset if c in PasswordGenerator.CHARS_LOWER]))
        if use_uppercase and any(c in PasswordGenerator.CHARS_UPPER for c in charset):
            constraints.append(random.choice([c for c in charset if c in PasswordGenerator.CHARS_UPPER]))
        if use_digits and any(c in PasswordGenerator.CHARS_DIGITS for c in charset):
            constraints.append(random.choice([c for c in charset if c in PasswordGenerator.CHARS_DIGITS]))
        if use_symbols and any(c in PasswordGenerator.CHARS_SYMBOLS for c in charset):
            constraints.append(random.choice([c for c in charset if c in PasswordGenerator.CHARS_SYMBOLS]))
        
        # Fill the rest with random characters
        remaining_length = length - len(constraints)
        if remaining_length < 0:
            raise ValueError(f"Password length ({length}) is too short to satisfy all constraints")
        
        # Generate the password
        pwd_chars = constraints + [random.choice(charset) for _ in range(remaining_length)]
        random.shuffle(pwd_chars)  # Mix the constrained characters in
        
        return ''.join(pwd_chars)
    
    @classmethod
    def generate_passphrase(
        cls,
        num_words: int = 4,
        separator: str = "-",
        capitalize: bool = False,
        add_number: bool = False,
        add_symbol: bool = False,
        word_length: str = 'medium'  # 'short', 'medium', 'long', or 'mixed'
    ) -> str:
        """Generate a memorable passphrase from dictionary words"""
        # Ensure we have words loaded
        if not cls.WORD_LISTS['common']:
            raise ValueError("Word list not loaded. Call load_word_list() first.")
        
        # Select appropriate word list
        if word_length == 'mixed':
            words_list = cls.WORD_LISTS['common']
        else:
            if word_length not in cls.WORD_LISTS or not cls.WORD_LISTS[word_length]:
                raise ValueError(f"Invalid word length: {word_length}")
            words_list = cls.WORD_LISTS[word_length]
        
        # Select random words
        selected_words = [random.choice(words_list) for _ in range(num_words)]
        
        # Apply capitalization if requested
        if capitalize:
            selected_words = [word.capitalize() for word in selected_words]
        
        # Join with separator
        passphrase = separator.join(selected_words)
        
        # Add number if requested
        if add_number:
            passphrase += separator + str(random.randint(100, 9999))
        
        # Add symbol if requested
        if add_symbol:
            passphrase += random.choice(cls.CHARS_SYMBOLS)
        
        return passphrase
    
    @staticmethod
    def generate_pin(length: int = 4, no_repeats: bool = False) -> str:
        """Generate a numeric PIN"""
        if no_repeats and length > 10:
            raise ValueError("Cannot generate PIN longer than 10 digits with no repeats")
        
        if no_repeats:
            digits = list(PasswordGenerator.CHARS_DIGITS)
            random.shuffle(digits)
            return ''.join(digits[:length])
        else:
            return ''.join(random.choice(PasswordGenerator.CHARS_DIGITS) for _ in range(length))
    
    @staticmethod
    def generate_cryptographically_secure_password(length: int = 16) -> str:
        """Generate a cryptographically secure random password using os.urandom"""
        # Define character set
        charset = string.ascii_letters + string.digits + PasswordGenerator.CHARS_SYMBOLS
        charset_length = len(charset)
        
        # Generate random bytes
        random_bytes = os.urandom(length)
        
        # Convert to password characters
        password = ''.join(charset[byte % charset_length] for byte in random_bytes)
        return password


def main():
    """Command-line interface for password generator"""
    parser = argparse.ArgumentParser(description="Generate secure passwords and passphrases")
    
    # Create subparsers for different generation modes
    subparsers = parser.add_subparsers(dest='mode', help='Generation mode')
    subparsers.required = True
    
    # Password parser
    pwd_parser = subparsers.add_parser('password', help='Generate random password')
    pwd_parser.add_argument('--length', type=int, default=16, help='Password length')
    pwd_parser.add_argument('--no-uppercase', action='store_true', help='Exclude uppercase letters')
    pwd_parser.add_argument('--no-lowercase', action='store_true', help='Exclude lowercase letters')
    pwd_parser.add_argument('--no-digits', action='store_true', help='Exclude digits')
    pwd_parser.add_argument('--no-symbols', action='store_true', help='Exclude symbols')
    pwd_parser.add_argument('--avoid-similar', action='store_true', help='Avoid similar characters (1, l, I, etc.)')
    pwd_parser.add_argument('--avoid-ambiguous', action='store_true', help='Avoid ambiguous symbols')
    pwd_parser.add_argument('--count', type=int, default=1, help='Number of passwords to generate')
    
    # Passphrase parser
    phrase_parser = subparsers.add_parser('passphrase', help='Generate memorable passphrase')
    phrase_parser.add_argument('--words', type=int, default=4, help='Number of words')
    phrase_parser.add_argument('--separator', default='-', help='Word separator')
    phrase_parser.add_argument('--capitalize', action='store_true', help='Capitalize each word')
    phrase_parser.add_argument('--add-number', action='store_true', help='Add a number')
    phrase_parser.add_argument('--add-symbol', action='store_true', help='Add a symbol')
    phrase_parser.add_argument('--word-length', choices=['short', 'medium', 'long', 'mixed'], 
                              default='medium', help='Word length preference')
    phrase_parser.add_argument('--word-list', required=True, help='Path to word list file')
    phrase_parser.add_argument('--count', type=int, default=1, help='Number of passphrases to generate')
    
    # PIN parser
    pin_parser = subparsers.add_parser('pin', help='Generate PIN code')
    pin_parser.add_argument('--length', type=int, default=4, help='PIN length')
    pin_parser.add_argument('--no-repeats', action='store_true', help='No repeated digits')
    pin_parser.add_argument('--count', type=int, default=1, help='Number of PINs to generate')
    
    args = parser.parse_args()
    
    # Generate based on mode
    if args.mode == 'password':
        for i in range(args.count):
            pwd = PasswordGenerator.generate_random_password(
                length=args.length,
                use_uppercase=not args.no_uppercase,
                use_lowercase=not args.no_lowercase,
                use_digits=not args.no_digits,
                use_symbols=not args.no_symbols,
                avoid_similar=args.avoid_similar,
                avoid_ambiguous=args.avoid_ambiguous
            )
            print(pwd)
    
    elif args.mode == 'passphrase':
        # Load word list
        if not PasswordGenerator.load_word_list(args.word_list):
            print(f"Error: Could not load word list from {args.word_list}")
            return 1
        
        for i in range(args.count):
            phrase = PasswordGenerator.generate_passphrase(
                num_words=args.words,
                separator=args.separator,
                capitalize=args.capitalize,
                add_number=args.add_number,
                add_symbol=args.add_symbol,
                word_length=args.word_length
            )
            print(phrase)
    
    elif args.mode == 'pin':
        for i in range(args.count):
            pin = PasswordGenerator.generate_pin(
                length=args.length,
                no_repeats=args.no_repeats
            )
            print(pin)
    
    return 0


if __name__ == "__main__":
    main()