#!/usr/bin/env python3
"""
Password Strength Checker - A security tool for analyzing password strength

This tool analyzes passwords from various input sources and provides a detailed
strength assessment including entropy calculation, character composition analysis,
and common password detection.
"""

import argparse
import sys
import os
import math
import json
import re
import getpass
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple

# Optional: If zxcvbn is installed, use it for additional checks
try:
    import zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False

# Optional: If colorama is installed, use it for terminal colors
try:
    from colorama import init, Fore, Style
    init()  # Initialize colorama
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False

class StrengthLevel(Enum):
    """Enum representing password strength levels"""
    VERY_WEAK = 1
    WEAK = 2
    MODERATE = 3
    STRONG = 4
    VERY_STRONG = 5

class PasswordAnalyzer:
    """Core password analysis engine"""
    
    # Common passwords will be loaded from file only
    COMMON_PASSWORDS = set()
    
    @classmethod
    def load_common_passwords(cls, filepath=None):
        """Load common passwords from a file (one password per line)"""
        # Start with an empty set
        cls.COMMON_PASSWORDS = set()
        
        # If no file specified, use an empty set
        if not filepath:
            return 0
        
        # Try to load from the specified file
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    password = line.strip()
                    if password and not password.startswith('#'):  # Skip empty lines and comments
                        cls.COMMON_PASSWORDS.add(password.lower())
            return len(cls.COMMON_PASSWORDS)
        except Exception as e:
            print(f"Warning: Could not load common passwords from {filepath}: {str(e)}")
            # Use empty set if file can't be loaded
            return 0
    
    @staticmethod
    def has_lowercase(password: str) -> bool:
        """Check if password contains lowercase letters"""
        return any(c.islower() for c in password)
    
    @staticmethod
    def has_uppercase(password: str) -> bool:
        """Check if password contains uppercase letters"""
        return any(c.isupper() for c in password)
    
    @staticmethod
    def has_numbers(password: str) -> bool:
        """Check if password contains digits"""
        return any(c.isdigit() for c in password)
    
    @staticmethod
    def has_symbols(password: str) -> bool:
        """Check if password contains special characters"""
        return any(not c.isalnum() for c in password)
    
    @staticmethod
    def calculate_entropy(password: str) -> float:
        """Calculate password entropy"""
        charset_size = 0
        if PasswordAnalyzer.has_lowercase(password):
            charset_size += 26
        if PasswordAnalyzer.has_uppercase(password):
            charset_size += 26
        if PasswordAnalyzer.has_numbers(password):
            charset_size += 10
        if PasswordAnalyzer.has_symbols(password):
            charset_size += 33  # Approximation for common symbols
        
        if charset_size == 0:
            return 0
        
        return len(password) * math.log2(charset_size)
    
    # Passphrase analysis method removed
    
    @staticmethod
    def is_common_password(password: str) -> bool:
        """Check if password is in list of common passwords"""
        return password.lower() in PasswordAnalyzer.COMMON_PASSWORDS
    
    @staticmethod
    def evaluate_strength(password: str) -> Dict[str, Any]:
        """Comprehensive password strength evaluation"""
        result = {}
        
        # Basic properties
        result["length"] = len(password)
        result["has_lowercase"] = PasswordAnalyzer.has_lowercase(password)
        result["has_uppercase"] = PasswordAnalyzer.has_uppercase(password)
        result["has_numbers"] = PasswordAnalyzer.has_numbers(password)
        result["has_symbols"] = PasswordAnalyzer.has_symbols(password)
        
        # Count different character types used
        char_types = sum([
            result["has_lowercase"],
            result["has_uppercase"],
            result["has_numbers"],
            result["has_symbols"]
        ])
        result["character_variety"] = char_types
        
        # Check if it's a common password
        result["is_common"] = PasswordAnalyzer.is_common_password(password)
        
        # Calculate entropy
        result["entropy"] = PasswordAnalyzer.calculate_entropy(password)
        
        # Passphrase detection removed
        
        # Use zxcvbn if available
        if ZXCVBN_AVAILABLE:
            zxcvbn_result = zxcvbn.zxcvbn(password)
            result["zxcvbn_score"] = zxcvbn_result["score"]  # 0-4
            result["crack_time_seconds"] = zxcvbn_result["crack_times_seconds"]["offline_fast_hashing_1e10_per_second"]
            result["feedback"] = zxcvbn_result["feedback"]
        
        # Calculate strength score (0-100)
        strength = 0
        
        # Length factor (max 40 points)
        length = result["length"]
        strength += min(40, length * 2)
        
        # Variety factor (max 40 points)
        strength += char_types * 10
        
        # Entropy bonus (max 20 points)
        entropy = result["entropy"]
        strength += min(20, int(entropy / 4))
        
        # Penalty for common password
        if result["is_common"]:
            strength = 0
        
        # Cap at 100
        strength = min(100, strength)
        result["strength_score"] = strength
        
        # Determine strength level
        if strength < 20:
            result["strength_level"] = StrengthLevel.VERY_WEAK
        elif strength < 40:
            result["strength_level"] = StrengthLevel.WEAK
        elif strength < 60:
            result["strength_level"] = StrengthLevel.MODERATE
        elif strength < 80:
            result["strength_level"] = StrengthLevel.STRONG
        else:
            result["strength_level"] = StrengthLevel.VERY_STRONG
        
        # Suggestions
        suggestions = []
        if length < 12:
            suggestions.append("Increase length to at least 12 characters")
        if not result["has_lowercase"]:
            suggestions.append("Add lowercase letters")
        if not result["has_uppercase"]:
            suggestions.append("Add uppercase letters")
        if not result["has_numbers"]:
            suggestions.append("Add numbers")
        if not result["has_symbols"]:
            suggestions.append("Add special characters")
        if char_types < 3:
            suggestions.append("Use more character types (upper, lower, numbers, symbols)")
        
        result["suggestions"] = suggestions
        
        return result


class ReportFormatter:
    """Formats analysis results for different output types"""
    
    @staticmethod
    def strength_to_color(strength_level: StrengthLevel) -> str:
        """Convert strength level to color code"""
        if not COLORS_AVAILABLE:
            return ""
        
        colors = {
            StrengthLevel.VERY_WEAK: Fore.RED,
            StrengthLevel.WEAK: Fore.RED,
            StrengthLevel.MODERATE: Fore.YELLOW,
            StrengthLevel.STRONG: Fore.GREEN,
            StrengthLevel.VERY_STRONG: Fore.GREEN
        }
        return colors.get(strength_level, "")
    
    @staticmethod
    def strength_to_label(strength_level: StrengthLevel) -> str:
        """Convert strength level to human-readable label"""
        labels = {
            StrengthLevel.VERY_WEAK: "VERY WEAK",
            StrengthLevel.WEAK: "WEAK",
            StrengthLevel.MODERATE: "MODERATE",
            StrengthLevel.STRONG: "STRONG",
            StrengthLevel.VERY_STRONG: "VERY STRONG"
        }
        return labels.get(strength_level, "UNKNOWN")
    
    @staticmethod
    def format_text(password: str, analysis: Dict[str, Any], verbose: bool = False) -> str:
        """Format analysis as text"""
        strength_level = analysis["strength_level"]
        color = ReportFormatter.strength_to_color(strength_level)
        reset = Style.RESET_ALL if COLORS_AVAILABLE else ""
        
        # Basic output
        lines = [
            f"Password: {'*' * len(password)}",
            f"Length: {analysis['length']} characters",
            f"Strength: {color}{ReportFormatter.strength_to_label(strength_level)}{reset} ({analysis['strength_score']}/100)"
        ]
        
        # Common password warning
        if analysis["is_common"]:
            warning = f"{Fore.RED if COLORS_AVAILABLE else ''}WARNING: This is a common password!{reset}"
            lines.append(warning)
        
        # Verbose output
        if verbose:
            lines.extend([
                "",
                "Character Composition:",
                f"  Lowercase letters: {'Yes' if analysis['has_lowercase'] else 'No'}",
                f"  Uppercase letters: {'Yes' if analysis['has_uppercase'] else 'No'}",
                f"  Numbers: {'Yes' if analysis['has_numbers'] else 'No'}",
                f"  Special symbols: {'Yes' if analysis['has_symbols'] else 'No'}",
                f"  Character variety: {analysis['character_variety']} of 4 possible types",
                "",
                f"Entropy: {analysis['entropy']:.2f} bits"
            ])
            
            # Passphrase analysis section removed
            
            # Add zxcvbn results if available
            if "zxcvbn_score" in analysis:
                seconds = analysis["crack_time_seconds"]
                time_display = "centuries" if seconds > 3.154e10 else \
                               "decades" if seconds > 3.154e9 else \
                               "years" if seconds > 3.154e7 else \
                               "months" if seconds > 2.628e6 else \
                               "weeks" if seconds > 6.048e5 else \
                               "days" if seconds > 8.64e4 else \
                               "hours" if seconds > 3.6e3 else \
                               "minutes" if seconds > 60 else \
                               "seconds"
                
                lines.extend([
                    "",
                    "Advanced Analysis:",
                    f"  Time to crack: {time_display}",
                    f"  zxcvbn score: {analysis['zxcvbn_score']} / 4"
                ])
                
                if analysis["feedback"]["warning"]:
                    lines.append(f"  Warning: {analysis['feedback']['warning']}")
                
                if analysis["feedback"]["suggestions"]:
                    lines.append("  Suggestions:")
                    for suggestion in analysis["feedback"]["suggestions"]:
                        lines.append(f"   - {suggestion}")
        
        # Always show suggestions
        if analysis["suggestions"]:
            lines.append("")
            lines.append("Suggestions for improvement:")
            for suggestion in analysis["suggestions"]:
                lines.append(f"  - {suggestion}")
        
        return "\n".join(lines)
    
    @staticmethod
    def format_json(password: str, analysis: Dict[str, Any]) -> str:
        """Format analysis as JSON"""
        # Convert Enum to string for JSON serialization
        result = {**analysis}
        result["strength_level"] = ReportFormatter.strength_to_label(analysis["strength_level"])
        return json.dumps(result, indent=2)
    
    @staticmethod
    def format_csv(password: str, analysis: Dict[str, Any]) -> str:
        """Format analysis as CSV"""
        # Very basic CSV implementation - could be expanded
        fields = [
            "****",  # Password masked
            str(analysis["length"]),
            str(analysis["strength_score"]),
            ReportFormatter.strength_to_label(analysis["strength_level"]),
            str(analysis["entropy"]),
            "Yes" if analysis["has_lowercase"] else "No",
            "Yes" if analysis["has_uppercase"] else "No",
            "Yes" if analysis["has_numbers"] else "No",
            "Yes" if analysis["has_symbols"] else "No",
            "Yes" if analysis["is_common"] else "No"
        ]
        return ",".join(fields)


class PasswordChecker:
    """Main application class"""
    
    def __init__(self, common_passwords_file=None):
        self.analyzer = PasswordAnalyzer()
        self.formatter = ReportFormatter()
        
        # Load common passwords
        num_passwords = PasswordAnalyzer.load_common_passwords(common_passwords_file)
        if common_passwords_file:
            print(f"Loaded {num_passwords} common passwords from '{common_passwords_file}'")
        else:
            print("No common password file provided. Common password detection disabled.")
    
    def check_password(self, password: str, output_format: str = "text", verbose: bool = False) -> str:
        """Check a single password and return formatted results"""
        analysis = self.analyzer.evaluate_strength(password)
        
        if output_format == "json":
            return self.formatter.format_json(password, analysis)
        elif output_format == "csv":
            return self.formatter.format_csv(password, analysis)
        else:  # Default to text
            return self.formatter.format_text(password, analysis, verbose)
    
    def process_input_file(self, file_path: str, output_format: str, verbose: bool) -> List[str]:
        """Process passwords from a file"""
        results = []
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    password = line.strip()
                    if password:  # Skip empty lines
                        result = self.check_password(password, output_format, verbose)
                        results.append(result)
        except Exception as e:
            results.append(f"Error processing file: {str(e)}")
        
        # Option to securely wipe the file
        return results
    
    def secure_wipe_file(self, file_path: str) -> bool:
        """Securely wipe a file containing passwords"""
        try:
            # Get file size
            file_size = os.path.getsize(file_path)
            
            # Overwrite with random data
            with open(file_path, 'wb') as f:
                f.write(os.urandom(file_size))
            
            # Overwrite with zeros
            with open(file_path, 'wb') as f:
                f.write(b'\x00' * file_size)
            
            # Delete the file
            os.remove(file_path)
            return True
        except Exception:
            return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Password Strength Checker - Analyze the security of passwords"
    )
    
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument(
        "-p", "--password",
        help="Password to check (warning: may be visible in command history)"
    )
    input_group.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Interactive mode - prompt for passwords"
    )
    input_group.add_argument(
        "-f", "--file",
        help="Read passwords from file (one per line)"
    )
    
    parser.add_argument(
        "-o", "--output",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed analysis"
    )
    parser.add_argument(
        "-w", "--wipe",
        action="store_true",
        help="Securely wipe input file after processing (use with caution!)"
    )
    parser.add_argument(
        "-c", "--common-passwords",
        help="Path to a file containing common passwords (one per line)",
        required=True
    )
    
    args = parser.parse_args()
    checker = PasswordChecker(args.common_passwords)
    
    # Process based on input method
    if args.password:
        result = checker.check_password(args.password, args.output, args.verbose)
        print(result)
    
    elif args.file:
        results = checker.process_input_file(args.file, args.output, args.verbose)
        
        # Handle different output formats
        if args.output == "csv" and len(results) > 0:
            # Add header for CSV
            headers = "Password,Length,Score,Level,Entropy,Lowercase,Uppercase,Numbers,Symbols,Common"
            print(headers)
            
        # Print all results
        for result in results:
            print(result)
            # Separate multiple text results
            if args.output == "text" and len(results) > 1:
                print("\n" + "-" * 50 + "\n")
        
        # Securely wipe if requested
        if args.wipe:
            if checker.secure_wipe_file(args.file):
                print(f"\nFile '{args.file}' has been securely wiped.")
            else:
                print(f"\nWarning: Could not securely wipe file '{args.file}'.")
    
    elif args.interactive:
        print("Password Strength Checker - Interactive Mode")
        print("Enter passwords to check (Ctrl+D or empty line to exit)")
        print("-" * 50)
        
        try:
            while True:
                password = getpass.getpass("Password: ")
                if not password:
                    break
                
                result = checker.check_password(password, args.output, args.verbose)
                print("\n" + result + "\n")
                print("-" * 50)
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()