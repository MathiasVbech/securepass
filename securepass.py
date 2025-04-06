#!/usr/bin/env python3
"""
Enhanced Password Checker Demo

This script demonstrates how to integrate the password checker with
the new password generator and advanced analytics modules.
"""

import argparse
import sys
import os
from typing import List, Dict, Any

# Import our modules
from src.password_checker import PasswordChecker, PasswordAnalyzer, ReportFormatter
from src.password_generator import PasswordGenerator
from src.advanced_analytics import AdvancedAnalyzer

class EnhancedPasswordChecker:
    """Enhanced password checker with generation and advanced analytics"""
    
    def __init__(self, common_passwords_file=None, word_list_file=None, dict_dir=None):
        """Initialize the enhanced password checker"""
        # Initialize the base checker
        self.checker = PasswordChecker(common_passwords_file)
        self.word_list_loaded = False
        self.dictionaries_loaded = False
        
        # Load word list for password generation if provided
        if word_list_file and os.path.exists(word_list_file):
            self.word_list_loaded = PasswordGenerator.load_word_list(word_list_file)
            if self.word_list_loaded:
                print(f"Loaded word list for password generation from '{word_list_file}'")
        
        # Load dictionaries for advanced analysis if provided
        if dict_dir and os.path.isdir(dict_dir):
            loaded_dicts = AdvancedAnalyzer.load_dictionaries(dict_dir)
            if loaded_dicts:
                self.dictionaries_loaded = True
                print(f"Loaded dictionaries for advanced analysis from {dict_dir}:")
                for dict_name, count in loaded_dicts.items():
                    print(f"  - {dict_name.capitalize()}: {count} entries")
    
    def generate_password(self, 
                          length=16, 
                          uppercase=True, 
                          lowercase=True, 
                          digits=True, 
                          symbols=True,
                          avoid_similar=False) -> str:
        """Generate a random password"""
        return PasswordGenerator.generate_random_password(
            length=length,
            use_uppercase=uppercase,
            use_lowercase=lowercase,
            use_digits=digits,
            use_symbols=symbols,
            avoid_similar=avoid_similar
        )
    
    def generate_passphrase(self, 
                           words=4, 
                           separator="-", 
                           capitalize=False, 
                           add_number=False,
                           word_length="medium") -> str:
        """Generate a memorable passphrase"""
        if not self.word_list_loaded:
            raise ValueError("Word list is required for passphrase generation")
        
        return PasswordGenerator.generate_passphrase(
            num_words=words,
            separator=separator,
            capitalize=capitalize,
            add_number=add_number,
            word_length=word_length
        )
    
    def advanced_check(self, password: str) -> Dict[str, Any]:
        """Run advanced analysis on a password"""
        # Get basic analysis first
        basic_analysis = PasswordAnalyzer.evaluate_strength(password)
        
        # Get advanced analysis
        advanced_analysis = AdvancedAnalyzer.analyze_password(password)
        
        # Combine results
        results = {**basic_analysis}
        results['vulnerabilities'] = advanced_analysis['vulnerabilities']
        results['risk_score'] = advanced_analysis['risk_score']
        
        # Combine suggestions
        all_suggestions = set(results.get('suggestions', []))
        all_suggestions.update(advanced_analysis.get('suggestions', []))
        results['suggestions'] = list(all_suggestions)
        
        return results
    
    def format_enhanced_results(self, password: str, results: Dict[str, Any], 
                               format="text", verbose=False) -> str:
        """Format enhanced analysis results"""
        if format == "json":
            import json
            return json.dumps(results, indent=2)
        
        # Start with the basic formatter output
        formatter = ReportFormatter()
        output = formatter.format_text(password, results, verbose)
        
        # Add vulnerability information
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            output += "\n\nAdvanced Analysis:\n"
            output += f"Risk Score: {results.get('risk_score', 0)}/100\n"
            output += "\nVulnerabilities Detected:\n"
            
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', 'unknown')
                risk = vuln.get('risk', 'unknown')
                
                if vuln_type == 'keyboard_horizontal':
                    output += f"  Keyboard pattern (horizontal): '{vuln.get('pattern')}' - {risk} risk\n"
                elif vuln_type == 'keyboard_vertical':
                    output += f"  Keyboard pattern (vertical): '{vuln.get('pattern')}' - {risk} risk\n"
                elif vuln_type == 'sequence':
                    output += f"  Sequential characters: '{vuln.get('pattern')}' - {risk} risk\n"
                elif vuln_type == 'repeated_chars':
                    output += f"  Repeated characters: '{vuln.get('pattern')}' - {risk} risk\n"
                elif vuln_type == 'name_word':
                    output += f"  Common name: '{vuln.get('word')}' - {risk} risk\n"
                elif vuln_type == 'surname_word':
                    output += f"  Common surname: '{vuln.get('word')}' - {risk} risk\n"
                elif vuln_type == 'dictionary_word':
                    output += f"  Dictionary word: '{vuln.get('word')}' - {risk} risk\n"
                elif vuln_type == 'leetspeak':
                    output += f"  Leetspeak word: '{vuln.get('original')}' as '{vuln.get('variant')}' - {risk} risk\n"
                elif vuln_type == 'year':
                    output += f"  Year detected: {vuln.get('pattern')} - {risk} risk\n"
                elif vuln_type == 'date':
                    output += f"  Date detected: {vuln.get('pattern')} - {risk} risk\n"
                elif vuln_type == 'word_plus_number':
                    output += f"  Word+number pattern: {vuln.get('word')}{vuln.get('number')} - {risk} risk\n"
                elif vuln_type == 'common_suffix':
                    output += f"  Common number suffix: '{vuln.get('suffix')}' - {risk} risk\n"
                else:
                    output += f"  {vuln_type}: {vuln}\n"
        
        return output


def main():
    """Command line interface for the enhanced password checker"""
    parser = argparse.ArgumentParser(
        description="Enhanced Password Tool - Generate and analyze secure passwords"
    )
    
    # Create subparsers for different modes
    subparsers = parser.add_subparsers(dest='mode', help='Tool mode')
    subparsers.required = True
    
    # Common arguments for resource files
    resource_args = argparse.ArgumentParser(add_help=False)
    resource_args.add_argument(
        "-c", "--common-passwords",
        help="Path to a file containing common passwords (one per line)"
    )
    resource_args.add_argument(
        "-w", "--word-list",
        help="Path to a word list for passphrase generation"
    )
    resource_args.add_argument(
        "-d", "--dict-dir",
        help="Directory containing dictionary files for advanced analysis"
    )
    
    # Generate password mode
    gen_parser = subparsers.add_parser(
        'generate', 
        help='Generate secure passwords',
        parents=[resource_args]
    )
    gen_parser.add_argument(
        "--type",
        choices=["password", "passphrase"],
        default="password",
        help="Type of password to generate"
    )
    gen_parser.add_argument(
        "--length", 
        type=int, 
        default=16,
        help="Length for random passwords"
    )
    gen_parser.add_argument(
        "--words", 
        type=int, 
        default=4,
        help="Number of words for passphrases"
    )
    gen_parser.add_argument(
        "--count", 
        type=int, 
        default=1,
        help="Number of passwords to generate"
    )
    gen_parser.add_argument(
        "--no-check", 
        action="store_true",
        help="Skip strength checking for generated passwords"
    )
    
    # Check password mode
    check_parser = subparsers.add_parser(
        'check', 
        help='Check password strength',
        parents=[resource_args]
    )
    check_parser.add_argument(
        "-p", "--password",
        help="Password to check (warning: may be visible in command history)"
    )
    check_parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Interactive mode - prompt for passwords"
    )
    check_parser.add_argument(
        "-f", "--file",
        help="Read passwords from file (one per line)"
    )
    check_parser.add_argument(
        "-o", "--output",
        choices=["text", "json"],
        default="text",
        help="Output format"
    )
    check_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed analysis"
    )
    check_parser.add_argument(
        "--advanced",
        action="store_true",
        help="Perform advanced pattern analysis"
    )
    
    args = parser.parse_args()
    
    # Initialize the enhanced checker
    enhanced_checker = EnhancedPasswordChecker(
        args.common_passwords,
        args.word_list,
        args.dict_dir
    )
    
    # Handle generate mode
    if args.mode == 'generate':
        for i in range(args.count):
            if args.type == 'password':
                password = enhanced_checker.generate_password(length=args.length)
            else:  # passphrase
                try:
                    password = enhanced_checker.generate_passphrase(words=args.words)
                except ValueError as e:
                    print(f"Error: {e}")
                    print("A word list file is required for passphrase generation.")
                    return 1
            
            # Print the generated password
            print(f"Generated {'password' if args.type=='password' else 'passphrase'} {i+1}: {password}")
            
            # Check the strength if requested
            if not args.no_check:
                print("\nStrength analysis:")
                if args.dict_dir and args.advanced:
                    # Use advanced checking
                    results = enhanced_checker.advanced_check(password)
                    print(enhanced_checker.format_enhanced_results(password, results))
                else:
                    # Use basic checking
                    results = PasswordAnalyzer.evaluate_strength(password)
                    formatter = ReportFormatter()
                    print(formatter.format_text(password, results))
                
                print("\n" + "-" * 60 + "\n")
    
    # Handle check mode
    elif args.mode == 'check':
        import getpass
        
        # Function to check a single password
        def check_password(pwd):
            if args.advanced and args.dict_dir:
                # Use advanced checking
                results = enhanced_checker.advanced_check(pwd)
                return enhanced_checker.format_enhanced_results(
                    pwd, results, args.output, args.verbose
                )
            else:
                # Use basic checking
                results = PasswordAnalyzer.evaluate_strength(pwd)
                formatter = ReportFormatter()
                if args.output == "json":
                    return formatter.format_json(pwd, results)
                else:
                    return formatter.format_text(pwd, results, args.verbose)
        
        # Process based on input method
        if args.password:
            result = check_password(args.password)
            print(result)
        
        elif args.file:
            try:
                with open(args.file, 'r') as f:
                    for line in f:
                        password = line.strip()
                        if password:  # Skip empty lines
                            result = check_password(password)
                            print(result)
                            if args.output == "text":
                                print("\n" + "-" * 60 + "\n")
            except Exception as e:
                print(f"Error processing file: {str(e)}")
        
        elif args.interactive:
            print("Password Strength Checker - Interactive Mode")
            print("Enter passwords to check (empty line to exit)")
            print("-" * 60)
            
            try:
                while True:
                    password = getpass.getpass("Password: ")
                    if not password:
                        break
                    
                    result = check_password(password)
                    print("\n" + result + "\n")
                    print("-" * 60)
            except (KeyboardInterrupt, EOFError):
                print("\nExiting...")
        
        else:
            check_parser.print_help()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())