#!/usr/bin/env python3
"""
Advanced Password Analytics Module

This module provides advanced password analysis capabilities including:
- Pattern detection (keyboard patterns, sequences, etc.)
- Linguistic analysis (dictionary words, name patterns)
- Advanced vulnerability detection
"""

import re
import string
from typing import List, Dict, Any, Tuple, Set, Optional
import os.path

class AdvancedAnalyzer:
    """Advanced password analysis capabilities"""
    
    # Common keyboard layouts
    QWERTY_ROWS = [
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm"
    ]
    
    QWERTY_COLS = [
        "qaz",
        "wsx",
        "edc",
        "rfv",
        "tgb",
        "yhn",
        "ujm",
        "ik,",
        "ol.",
        "p;/"
    ]
    
    # Common sequences
    SEQUENCES = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm"
    ]
    
    # Various dictionaries
    DICTIONARIES = {
        'names': set(),       # Common first names
        'surnames': set(),    # Common last names
        'english': set(),     # Common English words
        'leetspeak': {        # Leetspeak substitutions
            'a': ['4', '@'],
            'b': ['8'],
            'e': ['3'],
            'i': ['1', '!'],
            'l': ['1'],
            'o': ['0'],
            's': ['5', '$'],
            't': ['7'],
            'z': ['2']
        }
    }
    
    # Regex patterns
    PATTERNS = {
        'years': re.compile(r'(19\d\d|20\d\d)'),
        'dates': re.compile(r'(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])([12]\d{3})'),
        'phone': re.compile(r'\d{3}\d{3}\d{4}'),
        'repeats': re.compile(r'(.+?)\1+'),
        'word_plus_number': re.compile(r'^([a-zA-Z]{3,})(\d+)$'),
        'word_plus_symbols': re.compile(r'^([a-zA-Z]{3,})([^a-zA-Z0-9]+)$'),
        'number_suffix': re.compile(r'.*[a-zA-Z](\d{1,4})$')
    }
    
    @classmethod
    def load_dictionaries(cls, dict_dir: str) -> Dict[str, int]:
        """Load dictionaries from files in the specified directory"""
        result = {}
        
        # Define filenames to look for - using standardized names
        dict_files = {
            'names': ['first_names.txt'],
            'surnames': ['last_names.txt'], 
            'english': ['dictionary.txt']
        }
        
        # Try to load each dictionary
        for dict_type, filenames in dict_files.items():
            for filename in filenames:
                path = os.path.join(dict_dir, filename)
                if os.path.exists(path):
                    try:
                        with open(path, 'r', encoding='utf-8') as f:
                            words = {line.strip().lower() for line in f if line.strip()}
                            cls.DICTIONARIES[dict_type] = words
                            result[dict_type] = len(words)
                        break  # Stop after first successful file for this dict type
                    except Exception as e:
                        print(f"Error loading {dict_type} dictionary from {path}: {e}")
        
        return result
    
    @classmethod
    def detect_keyboard_patterns(cls, password: str) -> List[Dict[str, Any]]:
        """Detect keyboard patterns in the password"""
        patterns = []
        lower_pwd = password.lower()
        
        # Check for horizontal keyboard patterns
        for row in cls.QWERTY_ROWS:
            for i in range(len(row) - 2):
                pattern = row[i:i+3]  # Look for 3+ consecutive keys
                if pattern in lower_pwd:
                    patterns.append({
                        'type': 'keyboard_horizontal',
                        'pattern': pattern,
                        'risk': 'high'
                    })
        
        # Check for vertical keyboard patterns
        for col in cls.QWERTY_COLS:
            for i in range(len(col) - 2):
                pattern = col[i:i+3]
                if pattern in lower_pwd:
                    patterns.append({
                        'type': 'keyboard_vertical',
                        'pattern': pattern,
                        'risk': 'high'
                    })
        
        return patterns
    
    @classmethod
    def detect_sequences(cls, password: str) -> List[Dict[str, Any]]:
        """Detect common sequences in the password"""
        sequences = []
        lower_pwd = password.lower()
        
        for seq in cls.SEQUENCES:
            for i in range(len(seq) - 2):
                pattern = seq[i:i+3]  # Look for 3+ consecutive chars
                if pattern in lower_pwd:
                    sequences.append({
                        'type': 'sequence',
                        'pattern': pattern,
                        'risk': 'high' if len(pattern) > 3 else 'medium'
                    })
                
                # Also check for reverse sequences
                rev_pattern = pattern[::-1]
                if rev_pattern in lower_pwd:
                    sequences.append({
                        'type': 'reverse_sequence',
                        'pattern': rev_pattern,
                        'risk': 'high' if len(rev_pattern) > 3 else 'medium'
                    })
        
        # Check for repeated characters
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                sequences.append({
                    'type': 'repeated_chars',
                    'pattern': password[i] * 3,
                    'risk': 'high'
                })
        
        return sequences
    
    @classmethod
    def detect_dictionary_words(cls, password: str) -> List[Dict[str, Any]]:
        """Detect dictionary words in the password"""
        results = []
        lower_pwd = password.lower()
        
        # Function to check if a word is in the password
        def check_word_in_password(word: str, dict_type: str) -> bool:
            if word in lower_pwd and len(word) > 3:  # Only report words with length > 3
                results.append({
                    'type': f'{dict_type}_word',
                    'word': word,
                    'risk': 'high' if dict_type in ['names', 'surnames'] or len(word) > 5 else 'medium'
                })
                return True
            return False
        
        # Check for names
        for name in cls.DICTIONARIES['names']:
            check_word_in_password(name, 'name')
        
        # Check for surnames
        for surname in cls.DICTIONARIES['surnames']:
            check_word_in_password(surname, 'surname')
        
        # Check for English words (only if not already matched as name)
        for word in cls.DICTIONARIES['english']:
            if word not in cls.DICTIONARIES['names'] and word not in cls.DICTIONARIES['surnames']:
                check_word_in_password(word, 'dictionary')
        
        return results
    
    @classmethod
    def detect_leetspeak(cls, password: str) -> List[Dict[str, Any]]:
        """Detect leetspeak variations of dictionary words"""
        results = []
        
        # No dictionaries loaded
        if not cls.DICTIONARIES['english']:
            return results
        
        # Convert possible leetspeak to normal text for dictionary matching
        def deleet(text: str) -> List[str]:
            """Generate all possible deleet versions of the text"""
            if not text:
                return [""]
            
            first, rest = text[0].lower(), text[1:]
            rest_variations = deleet(rest)
            
            variations = []
            if first in cls.DICTIONARIES['leetspeak']:
                for substitute in cls.DICTIONARIES['leetspeak'][first]:
                    if substitute in password.lower():
                        for rest_var in rest_variations:
                            variations.append(first + rest_var)
            else:
                for rest_var in rest_variations:
                    variations.append(first + rest_var)
            
            return variations
        
        # Check each word
        for word in cls.DICTIONARIES['english']:
            if len(word) > 3:  # Only check longer words
                potential_variations = deleet(word)
                for variation in potential_variations:
                    if variation.lower() in password.lower():
                        results.append({
                            'type': 'leetspeak',
                            'original': word,
                            'variant': variation,
                            'risk': 'medium'
                        })
        
        return results
    
    @classmethod
    def detect_patterns(cls, password: str) -> List[Dict[str, Any]]:
        """Detect various patterns in the password"""
        patterns = []
        
        # Check for years
        year_match = cls.PATTERNS['years'].search(password)
        if year_match:
            patterns.append({
                'type': 'year',
                'pattern': year_match.group(0),
                'risk': 'high'
            })
        
        # Check for dates
        date_match = cls.PATTERNS['dates'].search(password)
        if date_match:
            patterns.append({
                'type': 'date',
                'pattern': date_match.group(0),
                'risk': 'high'
            })
        
        # Check for phone numbers
        phone_match = cls.PATTERNS['phone'].search(password)
        if phone_match:
            patterns.append({
                'type': 'phone_number',
                'pattern': phone_match.group(0),
                'risk': 'high'
            })
        
        # Check for repeating patterns
        repeat_match = cls.PATTERNS['repeats'].search(password)
        if repeat_match:
            patterns.append({
                'type': 'repeated_pattern',
                'pattern': repeat_match.group(1),
                'risk': 'high'
            })
        
        # Check for word+number pattern
        word_num_match = cls.PATTERNS['word_plus_number'].search(password)
        if word_num_match:
            patterns.append({
                'type': 'word_plus_number',
                'word': word_num_match.group(1),
                'number': word_num_match.group(2),
                'risk': 'high'
            })
        
        # Check for common number suffix (e.g. password1, admin123)
        num_suffix_match = cls.PATTERNS['number_suffix'].search(password)
        if num_suffix_match:
            suffix = num_suffix_match.group(1)
            if suffix in ['1', '123', '12345', '2020', '2021', '2022', '2023', '2024', '2025']:
                patterns.append({
                    'type': 'common_suffix',
                    'suffix': suffix,
                    'risk': 'very_high'
                })
        
        return patterns
    
    @classmethod
    def analyze_password(cls, password: str) -> Dict[str, Any]:
        """Perform full advanced analysis of a password"""
        results = {
            'password_length': len(password),
            'vulnerabilities': [],
            'risk_score': 0  # 0-100, higher is riskier
        }
        
        # Run all detection methods
        keyboard_patterns = cls.detect_keyboard_patterns(password)
        sequence_patterns = cls.detect_sequences(password)
        dictionary_words = cls.detect_dictionary_words(password)
        leetspeak_words = cls.detect_leetspeak(password)
        other_patterns = cls.detect_patterns(password)
        
        # Combine all vulnerabilities
        all_vulnerabilities = keyboard_patterns + sequence_patterns + dictionary_words + leetspeak_words + other_patterns
        results['vulnerabilities'] = all_vulnerabilities
        
        # Calculate risk score based on vulnerabilities
        risk_score = 0
        risk_weights = {
            'very_high': 30,
            'high': 20,
            'medium': 10,
            'low': 5
        }
        
        for vuln in all_vulnerabilities:
            risk_score += risk_weights.get(vuln.get('risk', 'medium'), 10)
        
        # Cap at 100
        results['risk_score'] = min(100, risk_score)
        
        # Generate improvement suggestions
        suggestions = []
        
        if keyboard_patterns:
            suggestions.append("Avoid keyboard patterns like 'qwerty' or 'asdf'")
        
        if sequence_patterns:
            suggestions.append("Avoid sequential characters like '12345' or 'abc'")
        
        if dictionary_words:
            suggestions.append("Avoid using common words, names, or simple substitutions")
        
        if other_patterns:
            other_types = set(p['type'] for p in other_patterns)
            if 'year' in other_types or 'date' in other_types:
                suggestions.append("Avoid using dates or years that might be associated with you")
            if 'word_plus_number' in other_types or 'common_suffix' in other_types:
                suggestions.append("Avoid simple patterns like adding numbers at the end of words")
        
        results['suggestions'] = suggestions
        
        return results


def main():
    """Command-line interface for testing the advanced analyzer"""
    import argparse
    import json
    
    parser = argparse.ArgumentParser(description="Advanced password analysis")
    parser.add_argument("password", help="Password to analyze")
    parser.add_argument("--dict-dir", help="Directory containing dictionary files")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                        help="Output format")
    
    args = parser.parse_args()
    
    # Load dictionaries if directory provided
    if args.dict_dir:
        loaded = AdvancedAnalyzer.load_dictionaries(args.dict_dir)
        print(f"Loaded dictionaries: {loaded}")
    
    # Analyze the password
    results = AdvancedAnalyzer.analyze_password(args.password)
    
    # Output results
    if args.format == "json":
        print(json.dumps(results, indent=2))
    else:
        print(f"Analysis of password: {'*' * len(args.password)}")
        print(f"Length: {results['password_length']} characters")
        print(f"Risk score: {results['risk_score']}/100")
        
        print("\nVulnerabilities detected:")
        if not results['vulnerabilities']:
            print("  No specific vulnerabilities detected")
        else:
            for vuln in results['vulnerabilities']:
                vuln_type = vuln.get('type', 'unknown')
                risk = vuln.get('risk', 'unknown')
                
                if vuln_type == 'keyboard_horizontal':
                    print(f"  Keyboard pattern (horizontal): '{vuln.get('pattern')}' - {risk} risk")
                elif vuln_type == 'keyboard_vertical':
                    print(f"  Keyboard pattern (vertical): '{vuln.get('pattern')}' - {risk} risk")
                elif vuln_type == 'sequence':
                    print(f"  Sequential characters: '{vuln.get('pattern')}' - {risk} risk")
                elif vuln_type == 'reverse_sequence':
                    print(f"  Reverse sequential characters: '{vuln.get('pattern')}' - {risk} risk")
                elif vuln_type == 'repeated_chars':
                    print(f"  Repeated characters: '{vuln.get('pattern')}' - {risk} risk")
                elif vuln_type == 'name_word':
                    print(f"  Common name: '{vuln.get('word')}' - {risk} risk")
                elif vuln_type == 'surname_word':
                    print(f"  Common surname: '{vuln.get('word')}' - {risk} risk")
                elif vuln_type == 'dictionary_word':
                    print(f"  Dictionary word: '{vuln.get('word')}' - {risk} risk")
                elif vuln_type == 'leetspeak':
                    print(f"  Leetspeak word: '{vuln.get('original')}' as '{vuln.get('variant')}' - {risk} risk")
                elif vuln_type == 'year':
                    print(f"  Year detected: {vuln.get('pattern')} - {risk} risk")
                elif vuln_type == 'date':
                    print(f"  Date detected: {vuln.get('pattern')} - {risk} risk")
                elif vuln_type == 'phone_number':
                    print(f"  Phone number detected: {vuln.get('pattern')} - {risk} risk")
                elif vuln_type == 'word_plus_number':
                    print(f"  Word+number pattern: {vuln.get('word')}{vuln.get('number')} - {risk} risk")
                elif vuln_type == 'common_suffix':
                    print(f"  Common number suffix: '{vuln.get('suffix')}' - {risk} risk")
                else:
                    print(f"  {vuln_type}: {vuln}")
        
        if results['suggestions']:
            print("\nSuggestions:")
            for suggestion in results['suggestions']:
                print(f"  - {suggestion}")


if __name__ == "__main__":
    main()