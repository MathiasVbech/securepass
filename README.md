# SecurePass

A comprehensive password security toolkit that can check password strength, generate secure passwords, and perform advanced pattern analysis to identify vulnerabilities.

![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

### Password Strength Analysis
- Evaluates password strength with detailed metrics
- Detects common passwords
- Calculates password entropy
- Analyzes character composition

### Password Generation
- Creates strong random passwords with configurable options
- Generates memorable passphrases from wordlists
- Creates secure PINs

### Advanced Password Analytics
- Detects keyboard patterns (e.g., "qwerty", "asdf")
- Identifies sequential characters and repeated patterns
- Detects dictionary words, names, and surnames
- Recognizes common patterns like dates, years, and word+number combinations

## Installation

1. Clone the repository:
```
git clone https://github.com/MathiasVbech/securepass.git
cd securepass
```

2. No external dependencies are required! This project uses only the Python standard library.

## Usage

### Check Password Strength

```bash
# Basic interactive mode
python3 securepass.py check -i --common-passwords dictionaries/common_passwords.txt

# Advanced analysis with pattern detection
python3 securepass.py check -i --advanced --common-passwords dictionaries/common_passwords.txt --dict-dir dictionaries/
```

### Generate Secure Passwords

```bash
# Generate a random password
python3 securepass.py generate --common-passwords dictionaries/common_passwords.txt

# Generate a memorable passphrase
python3 securepass.py generate --type passphrase --word-list dictionaries/wordlists/wordlist.txt --common-passwords dictionaries/common_passwords.txt
```

### Batch Processing

```bash
# Check multiple passwords from a file
python3 securepass.py check -f passwords.txt --common-passwords dictionaries/common_passwords.txt

# Generate multiple passwords
python3 securepass.py generate --count 10 --common-passwords dictionaries/common_passwords.txt
```

## Running Tests

```bash
# Run all tests
python3 -m unittest tests/test_securepass.py

# Run test directly
python3 tests/test_securepass.py
```

## Sample Output

### Password Strength Check

```
Password: ***********
Length: 11 characters
Strength: MODERATE (55/100)

Character Composition:
  Lowercase letters: Yes
  Uppercase letters: Yes
  Numbers: Yes
  Special symbols: No
  Character variety: 3 of 4 possible types

Entropy: 65.32 bits

Advanced Analysis:
Risk Score: 45/100

Vulnerabilities Detected:
  Dictionary word: 'secure' - high risk
  Common number suffix: '123' - very high risk

Suggestions:
  - Add special characters
  - Avoid simple patterns like adding numbers at the end of words
  - Increase length to at least 12 characters
```

## Expanding the Dictionaries

For more comprehensive analysis, you can replace the included sample files with larger dictionaries:

- **common_passwords.txt**: Lists of common passwords
- **first_names.txt**: Common first names
- **last_names.txt**: Common surnames
- **dictionary.txt**: Dictionary words
- **wordlist.txt**: Words for passphrase generation

Larger dictionaries can be found at:
- [EFF Wordlists](https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases)
- [SecLists](https://github.com/danielmiessler/SecLists)

## Project Structure

```
securepass/
  ├── securepass.py           # Main command-line interface
  │
  ├── src/                    # Core package
  │   ├── __init__.py         # Package definition
  │   ├── password_checker.py # Password strength evaluation
  │   ├── password_generator.py # Password generation 
  │   └── advanced_analytics.py # Advanced pattern detection
  │
  ├── dictionaries/           # Dictionary files
  │   ├── common_passwords.txt
  │   ├── first_names.txt     
  │   ├── last_names.txt     
  │   ├── dictionary.txt    
  │   └── wordlists/
  │       └── wordlist.txt  
  │
  └── tests/                  # Test suite
      └── test_securepass.py  # Comprehensive tests
```

## License

This project is licensed under the MIT License - see the LICENSE.txt file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- Inspired by NIST password guidelines
- Wordlist approach based on EFF's Diceware method
- Pattern detection influenced by common password cracking techniques