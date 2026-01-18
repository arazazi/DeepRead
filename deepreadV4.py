#!/usr/bin/env python3
"""
ULTIMATE Universal Encoding Detector and Decoder - V4.2 (by Azazi)
Implements 50+ encoding methods (Base, classical ciphers, ROT, keyboard, morse, steganography, esoteric)
Added --multi-layers (-m) for chained decoding and --gemini for AI analysis.
* New in V4.2: AI-Powered Detection/Decoding Mode (Triggered by -a -g).
"""

import re
import base64
import binascii
import urllib.parse
import string
import html
import math
import itertools
import collections
import json
import argparse
import hashlib
import uuid
import datetime
import os 
from typing import Dict, List, Tuple, Optional, Any

# --- Gemini API Imports (using google-genai as the expected library) ---
try:
    from google import genai as gemini_client
    from google.genai.errors import APIError as GeminiAPIError
except ImportError:
    gemini_client = None
    GeminiAPIError = Exception 
# ----------------------------------------------------------------------

# --- Standard Imports ---
try:
    import chardet
except ImportError:
    chardet = None

class UltimateEncodingDetector:
    def __init__(self):
        self.encoders = {
            'base16': self.detect_base16, 'base32': self.detect_base32, 'base45': self.detect_base45,
            'base58': self.detect_base58, 'base64': self.detect_base64, 'base85': self.detect_base85,
            'base91': self.detect_base91, 'base92': self.detect_base92, 'ascii_hex': self.detect_ascii_hex,
            'binary': self.detect_binary, 'octal': self.detect_octal, 'decimal': self.detect_decimal,
            'hex': self.detect_hex, 'url': self.detect_url_encoding, 'double_url': self.detect_double_url,
            'html_entities': self.detect_html_entities, 'html_decimal': self.detect_html_decimal,
            'html_hex': self.detect_html_hex, 'xml_entities': self.detect_xml_entities,
            'caesar': self.detect_caesar, 'rot13': self.detect_rot13, 'rot47': self.detect_rot47,
            'rot5': self.detect_rot5, 'rot18': self.detect_rot18, 'rot8000': self.detect_rot8000,
            'atbash': self.detect_atbash, 'affine': self.detect_affine, 'vigenere': self.detect_vigenere,
            'playfair': self.detect_playfair, 'bacon': self.detect_bacon, 'polybius': self.detect_polybius,
            'adfgx': self.detect_adfgx, 'rail_fence': self.detect_rail_fence,
            'columnar_transposition': self.detect_columnar, 'reverse': self.detect_reverse,
            'keyboard_qwerty': self.detect_keyboard_qwerty, 'keyboard_dvorak': self.detect_keyboard_dvorak,
            'keyboard_azerty': self.detect_keyboard_azerty, 'morse': self.detect_morse,
            'tap_code': self.detect_tap_code, 'semaphore': self.detect_semaphore,
            'md5': self.detect_md5, 'sha1': self.detect_sha1, 'sha256': self.detect_sha256,
            'sha512': self.detect_sha512, 'whitespace': self.detect_whitespace,
            'zero_width': self.detect_zero_width, 'uuencode': self.detect_uuencode,
            'xxencode': self.detect_xxencode, 'quoted_printable': self.detect_quoted_printable,
            'brainfuck': self.detect_brainfuck, 'ook': self.detect_ook, 'malbolge': self.detect_malbolge,
            'a1z26': self.detect_a1z26, 'leet_speak': self.detect_leet_speak,
            'pigpen': self.detect_pigpen, 'skip_cipher': self.detect_skip_cipher,
            'grille_cipher': self.detect_grille_cipher,
            'uuid': self.detect_uuid,
            'xor': self.detect_xor, 
        }
        # Dynamically create decoders if a decode_method exists
        self.decoders = {name: getattr(self, f'decode_{name}', None) for name in self.encoders.keys() if hasattr(self, f'decode_{name}')}
        self.non_decodable_types = ('md5', 'sha1', 'sha256', 'sha512', 'semaphore', 'brainfuck', 'ook', 'malbolge', 'pigpen', 'grille_cipher')
        self.gemini_client = self._initialize_gemini_client()


    def _initialize_gemini_client(self):
        if not gemini_client:
            return None
        
        # 1. Check Environment Variable
        api_key = os.getenv("GEMINI_API_KEY")
        
        # 2. Check local file (.gemini_key)
        if not api_key:
            try:
                with open(".gemini_key", "r") as f:
                    api_key = f.read().strip()
            except FileNotFoundError:
                pass 
            except Exception as e:
                print(f"⚠️ Warning: Error reading .gemini_key file: {e}")
                
        if api_key:
            try:
                # Use the client initialization that accepts the key
                return gemini_client.Client(api_key=api_key)
            except Exception:
                # This could be an API key format error or network issue
                return None
        
        return None


    # Helper for English word scoring
    def score_english(self, text: str) -> float:
        # --- ROBUSTNESS FIX: Ensure input is a string ---
        if not isinstance(text, str) or len(text) < 2:
            return -1.0 
        # -----------------------------------------------
        
        common_words = ['the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'a', 'an', 'is', 'are', 'was', 'were', 'be',    'been', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'this', 'that', 'i', 'you', 'he', 'she', 'it', 'we', 'they']
        common_digrams = ['th', 'he', 'in', 'er', 'an', 're', 'ed', 'on', 'es', 'st', 'en', 'at', 'to', 'nt', 'ha', 'nd', 'ou', 'de', 'ne', 'ea', 'io', 'ro', 'li', 'ra', 'te', 'co', 'mu', 'ti', 'as', 'hi', 'al', 'ma', 'is']
        score = 0
        text_lower = text.lower()
        
        for word in common_words:
            score += text_lower.count(word) * 2
        for digram in common_digrams:
            score += text_lower.count(digram)

        score -= sum(1 for char in text if not char.isalpha() and not char.isspace() and not char.isdigit()) * 0.8
        
        if len(text) < 10:
            score -= 5
        
        return score

    def has_english_words(self, text: str) -> bool:
        return self.score_english(text) > 5

    def detect_all(self, text: str) -> Dict[str, bool]:
        results = {}
        for name, detector_func in self.encoders.items():
            try:
                # Special handling for hashes to include extended info in the detected dictionary
                if name.startswith('sha') or name.startswith('md5'):
                    is_detected, hash_info = detector_func(text, extended=True)
                    results[name] = is_detected
                    if is_detected:
                        results[f'{name}_info'] = hash_info
                else:
                    results[name] = detector_func(text)
            except Exception: # Catch any errors during detection to avoid crashing
                results[name] = False
        return results

    def get_all_decodes_for_string(self, text: str) -> Dict[str, str]:
        """Core decoding function. Returns a dictionary of successful decodes."""
        results = {}
        for name, decoder_func in self.decoders.items():
            if name in self.non_decodable_types:
                continue

            if decoder_func:
                try:
                    # UUID uses decoding functionality but is not a typical cipher, so we decode if it's detected
                    if name == 'uuid' and self.detect_uuid(text):
                        results[name] = decoder_func(text)
                    # Check if text is detected as this encoding before attempting to decode
                    elif name != 'uuid' and self.encoders[name](text):
                        decoded_text = decoder_func(text)
                        # Filter out errors, the original text, and known failure messages
                        if decoded_text and decoded_text != text and not str(decoded_text).startswith("Error") and not "failed to find a plausible decryption" in str(decoded_text): 
                            results[name] = decoded_text
                except Exception as e:
                    # Only report error if detection passed
                    if self.encoders[name](text):
                        results[name] = f"Error during decoding: {e}"
        return results
    
    # =========================================================
    # --- CIPHER/ENCODING HELPER FUNCTIONS (DEFINED FIRST) ---
    # =========================================================
    
    def caesar_shift(self, text: str, shift: int) -> str:
        result = []
        for char in text:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - ascii_offset + shift) % 26
                result.append(chr(shifted + ascii_offset))
            else:
                result.append(char)
        return ''.join(result)

    def rot47_cipher(self, text: str) -> str:
        result = []
        for char in text:
            char_ord = ord(char)
            if 33 <= char_ord <= 126:
                result.append(chr(33 + (char_ord - 33 + 47) % 94))
            else:
                result.append(char)
        return ''.join(result)

    def rot5_cipher(self, text: str) -> str:
        result = []
        for char in text:
            if char.isdigit():
                result.append(str((int(char) + 5) % 10))
            else:
                result.append(char)
        return ''.join(result)

    def rot18_cipher(self, text: str) -> str:
        temp_text = self.rot5_cipher(text)
        return self.caesar_shift(temp_text, 13)

    def rot8000_cipher(self, text: str) -> str:
        result = []
        for char in text:
            char_ord = ord(char)
            if 0x4e00 <= char_ord <= 0x9fa5:
                result.append(chr(0x4e00 + (char_ord - 0x4e00 + 8000) % (0x9fa5 - 0x4e00 + 1)))
            else:
                result.append(char)
        return ''.join(result)

    def atbash_cipher(self, text: str) -> str:
        result = []
        for char in text:
            if char.isalpha():
                if char.isupper():
                    result.append(chr(ord('A') + (ord('Z') - ord(char))))
                else:
                    result.append(chr(ord('a') + (ord('z') - ord(char))))
            else:
                result.append(char)
        return ''.join(result)

    def affine_decrypt(self, text: str, a: int, b: int) -> str:
        def mod_inverse(a_val: int, m: int) -> int:
            for x in range(1, m):
                if (a_val * x) % m == 1:
                    return x
            raise ValueError(f"No modular inverse for {a_val} mod {m}")
    
        a_inv = mod_inverse(a, 26)
        result = []
        for char in text:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                y = ord(char) - ascii_offset
                x = (a_inv * (y - b)) % 26
                result.append(chr(x + ascii_offset))
            else:
                result.append(char)
        return ''.join(result)

    def vigenere_decrypt(self, text: str, key: str) -> str:
        result = []
        key = key.upper()
        key_index = 0
        for char in text:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('A')
                if char.isupper():
                    result.append(chr(ord('A') + (ord(char) - ord('A') - shift) % 26))
                else:
                    result.append(chr(ord('a') + (ord(char) - ord('a') - shift) % 26))
                key_index += 1
            else:
                result.append(char)
        return ''.join(result)

    def playfair_decrypt(self, text: str, key: str) -> str:
        return f"Playfair cipher detected. Requires key and square generation for full decryption."

    def rail_fence_decrypt(self, text: str, rails: int) -> str:
        if rails <= 1 or len(text) == 0:
            return text
        
        fence = [['\n'] * len(text) for _ in range(rails)]
        
        dir_down = False
        row, col = 0, 0
        for _ in range(len(text)):
            if (row == 0) or (row == rails - 1):
                dir_down = not dir_down
            fence[row][col] = '*'
            col += 1
            if dir_down:
                row += 1
            else:
                row -= 1
        
        index = 0
        for r in range(rails):
            for c in range(len(text)):
                if fence[r][c] == '*':
                    fence[r][c] = text[index]
                    index += 1
        
        result = []
        row, col = 0, 0
        dir_down = False
        for _ in range(len(text)):
            if (row == 0) or (row == rails - 1):
                dir_down = not dir_down
            result.append(fence[row][col])
            if dir_down:
                row += 1
            else:
                row -= 1
            col += 1
        return ''.join(result)

    def columnar_decrypt(self, text: str, key_length: int, order: Optional[List[int]] = None) -> str:
        if key_length <= 1 or len(text) == 0:
            return text

        num_cols = key_length
        num_rows = math.ceil(len(text) / num_cols)
        
        col_lengths = [num_rows] * num_cols
        remainder = len(text) % num_cols
        if remainder != 0:
            for i in range(remainder, num_cols):
                col_lengths[i] -= 1

        cols = [[] for _ in range(num_cols)]
        current_idx = 0
        for i in range(num_cols):
            cols[i] = list(text[current_idx : current_idx + col_lengths[i]])
            current_idx += col_lengths[i]
        
        plaintext = []
        for r in range(num_rows):
            for c in range(num_cols):
                if r < len(cols[c]):
                    plaintext.append(cols[c][r])
        return ''.join(plaintext)

    def keyboard_shift(self, text: str, layout_name: str) -> str:
        layouts = {
            'qwerty': {
                'q': 'w', 'w': 'e', 'e': 'r', 'r': 't', 't': 'y', 'y': 'u', 'u': 'i', 'i': 'o', 'o': 'p', 'p': '[',
                'a': 's', 's': 'd', 'd': 'f', 'f': 'g', 'g': 'h', 'h': 'j', 'j': 'k', 'k': 'l', 'l': ';', ';': "'",
                'z': 'x', 'x': 'c', 'c': 'v', 'v': 'b', 'b': 'n', 'n': 'm', 'm': ',', ',': '.', '.': '/'
            },
            'dvorak': {
                'p': 'y', 'y': 'f', 'f': 'g', 'g': 'c', 'c': 'r', 'r': 'l', 'l': 'a', 'a': 'o', 'o': 'e', 'e': 'u',
                'u': 'i', 'i': 'd', 'd': 'h', 'h': 't', 't': 'n', 'n': 's', 's': 'q', 'q': 'j', 'j': 'k', 'k': 'x',
                'x': 'b', 'b': 'm', 'm': 'w', 'w': 'v', 'v': 'z', 'z': ','
            },
            'azerty': {
                'a': 'z', 'z': 'e', 'e': 'r', 'r': 't', 't': 'y', 'y': 'u', 'u': 'i', 'i': 'o', 'o': 'p', 'p': '^',
                'q': 's', 's': 'd', 'd': 'f', 'f': 'g', 'g': 'h', 'h': 'j', 'j': 'k', 'k': 'l', 'l': 'm', 'm': 'ù',
                'w': 'x', 'x': 'c', 'c': 'v', 'v': 'b', 'b': 'n', 'n': ',', ',': ';', ';': ':'
            }
        }
        
        shift_map = layouts.get(layout_name, {})
        reverse_shift_map = {v: k for k, v in shift_map.items()}

        result = []
        for char in text.lower():
            result.append(reverse_shift_map.get(char, char))
        return ''.join(result)

    def xor_data(self, data: str, key: int) -> str:
        """Applies a single-byte XOR key to the string data."""
        return "".join([chr(ord(c) ^ key) for c in data])

    # Generic decoding helper with English scoring (Used by Caesar, Vigenere, etc.)
    def decode_with_english_scoring(self, text: str, decoder_func, param_range: Any) -> str:
        best_decoded = text
        best_score = self.score_english(text)
        
        for param in param_range:
            try:
                decoded = decoder_func(text, param)
                score = self.score_english(decoded)
                if score > best_score:
                    best_score = score
                    best_decoded = decoded
            except Exception:
                continue
        
        # --- FIX: Ensure a string is returned on failure (defaulting to input) ---
        if best_score > self.score_english(text) + 2.0:
             return best_decoded
        elif best_decoded != text and best_score > 5.0:
             return best_decoded
        else:
             return text # Always return a string
    # --- END HELPER FUNCTIONS ---


    # =========================================================
    # --- DETECTION METHODS ---
    # =========================================================
    
    # --- UUID/HASH Detection Overrides (V2.7) ---
    def identify_hash_mode(self, text: str, name: str) -> str:
        text_lower = text.lower()
        
        # Salted/Peppered Hashes
        if '$1$' in text: return 'MD5crypt / Apache MD5 (Hashcat Mode 500)'
        if '$5$' in text: return 'SHA256crypt (Hashcat Mode 7400)'
        if '$6$' in text: return 'SHA512crypt (Hashcat Mode 1800)'
        if '$a$' in text_lower or '$b$' in text_lower: return 'Blowfish (e.g., bcrypt/Joomla) (Hashcat Mode 3200)'
        if '$2a$' in text_lower or '$2b$' in text_lower: return 'Blowfish (e.g., bcrypt/Joomla) (Hashcat Mode 3200)'
        if text.startswith('pbkdf2'): return 'PBKDF2-HMAC (Various Modes)'
        if text.startswith('scrypt'): return 'Scrypt (Hashcat Mode 8900)'
        
        # Unsalted Hashes
        if name == 'md5' and len(text) == 32: return 'MD5 (Hashcat Mode 0)'
        if name == 'sha1' and len(text) == 40: return 'SHA1 (Hashcat Mode 100)'
        if name == 'sha256' and len(text) == 64: return 'SHA256 (Hashcat Mode 1400)'
        if name == 'sha512' and len(text) == 128: return 'SHA512 (Hashcat Mode 1700)'
        
        return 'Unknown or custom format'


    def detect_md5(self, text: str, extended: bool = False) -> Tuple[bool, Optional[str]]:
        is_md5 = bool(re.match(r'^[a-f0-9]{32}$', text.lower()))
        is_salted = '$1$' in text or '$a$' in text.lower() or '$b$' in text.lower()
        if extended and (is_md5 or is_salted):
            mode = self.identify_hash_mode(text, 'md5')
            return is_md5 or is_salted, mode
        return is_md5, None

    def detect_sha1(self, text: str, extended: bool = False) -> Tuple[bool, Optional[str]]:
        is_sha1 = bool(re.match(r'^[a-f0-9]{40}$', text.lower()))
        if extended and is_sha1:
            mode = self.identify_hash_mode(text, 'sha1')
            return is_sha1, mode
        return is_sha1, None

    def detect_sha256(self, text: str, extended: bool = False) -> Tuple[bool, Optional[str]]:
        is_sha256 = bool(re.match(r'^[a-f0-9]{64}$', text.lower()))
        is_salted = '$5$' in text
        if extended and (is_sha256 or is_salted):
            mode = self.identify_hash_mode(text, 'sha256')
            return is_sha256 or is_salted, mode
        return is_sha256, None
    
    def detect_sha512(self, text: str, extended: bool = False) -> Tuple[bool, Optional[str]]:
        is_sha512 = bool(re.match(r'^[a-f0-9]{128}$', text.lower()) or '$6$' in text)
        is_salted = '$6$' in text
        if extended and (is_sha512 or is_salted):
            mode = self.identify_hash_mode(text, 'sha512')
            return is_sha512 or is_salted, mode
        return is_sha512, None

    def detect_uuid(self, text: str) -> bool:
        text = text.strip().lower()
        # Standard UUID format: 8-4-4-4-12 hex chars
        uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
        return bool(uuid_pattern.match(text))
    # --- END UUID/HASH Detection Overrides ---

    def detect_base16(self, text: str) -> bool:
        text = text.strip().replace(' ', '')
        return len(text) >= 2 and len(text) % 2 == 0 and bool(re.match(r'^[0-9A-Fa-f]+$', text))

    def detect_base32(self, text: str) -> bool:
        text = text.strip().replace(' ', '').upper()
        if len(text) < 8 or len(text) % 8 != 0:
            return False
        return bool(re.match(r'^[A-Z2-7]+=*$', text))

    def detect_base45(self, text: str) -> bool:
        text = text.strip().replace(' ', '')
        return len(text) >= 2 and bool(re.match(r'^[0-9A-Z $%*+\-./:]+$', text))

    def detect_base58(self, text: str) -> bool:
        text = text.strip()
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        return len(text) >= 4 and all(c in alphabet for c in text)

    def detect_base64(self, text: str) -> bool:
        text = text.strip()
        if len(text) < 4 or len(text) % 4 != 0:
            return False
        pattern = r'^[A-Za-z0-9+/]*={0,2}$'
        if not re.match(pattern, text):
            return False
        try:
            base64.b64decode(text, validate=True) 
            return True
        except (binascii.Error, ValueError):
            return False

    def detect_base85(self, text: str) -> bool:
        text = text.strip().replace(' ', '')
        return len(text) >= 5 and bool(re.match(r'^[!"#$%&\'()*+,\-./0-9:;<=>?@A-Z[\\\]^_`a-z{|}~]+$', text))

    def detect_base91(self, text: str) -> bool:
        text = text.strip()
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
        return len(text) >= 2 and all(c in alphabet for c in text)

    def detect_base92(self, text: str) -> bool:
        text = text.strip()
        alphabet = '!#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~'
        return len(text) >= 2 and all(c in alphabet for c in text)

    def detect_ascii_hex(self, text: str) -> bool:
        return bool(re.search(r'\\x[0-9A-Fa-f]{2}', text))

    def detect_binary(self, text: str) -> bool:
        text = text.strip().replace(' ', '')
        return len(text) >= 8 and len(text) % 8 == 0 and bool(re.match(r'^[01]+$', text))

    def detect_octal(self, text: str) -> bool:
        text = text.strip().replace(' ', '')
        return len(text) >= 3 and len(text) % 3 == 0 and bool(re.match(r'^[0-7]+$', text))

    def detect_decimal(self, text: str) -> bool:
        parts = text.strip().split()
        if len(parts) < 2:
            return False
        try:
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except ValueError:
            return False

    def detect_hex(self, text: str) -> bool:
        text = text.strip().replace(' ', '').replace('-', '').replace('0x', '')
        if len(text) < 2 or len(text) % 2 != 0:
            return False
        return bool(re.match(r'^[0-9A-Fa-f]+$', text))

    def detect_url_encoding(self, text: str) -> bool:
        return '%' in text and bool(re.search(r'%[0-9A-Fa-f]{2}', text))

    def detect_double_url(self, text: str) -> bool:
        return self.detect_url_encoding(text) and '%25' in text

    def detect_html_entities(self, text: str) -> bool:
        return bool(re.search(r'&[a-zA-Z]{2,10};', text))

    def detect_html_decimal(self, text: str) -> bool:
        return bool(re.search(r'&#[0-9]{2,5};', text))

    def detect_html_hex(self, text: str) -> bool:
        return bool(re.search(r'&#x[0-9A-Fa-f]{2,4};', text))

    def detect_xml_entities(self, text: str) -> bool:
        return bool(re.search(r'&(amp|lt|gt|quot|apos);', text))

    def detect_caesar(self, text: str) -> bool:
        clean_text = ''.join(filter(str.isalpha, text))
        if len(clean_text) < 10: return False
        for shift in range(1, 26):
            decoded = self.caesar_shift(text, shift)
            if self.has_english_words(decoded):
                return True
        return False

    def detect_rot13(self, text: str) -> bool:
        clean_text = ''.join(filter(str.isalpha, text))
        if len(clean_text) < 5: return False
        decoded = self.caesar_shift(text, 13)
        return self.has_english_words(decoded)

    def detect_rot47(self, text: str) -> bool:
        clean_text = ''.join(filter(lambda c: 33 <= ord(c) <= 126, text))
        if len(clean_text) < 5: return False
        decoded = self.rot47_cipher(text)
        return self.has_english_words(decoded)

    def detect_rot5(self, text: str) -> bool:
        if not any(c.isdigit() for c in text): return False
        decoded = self.rot5_cipher(text)
        return decoded != text and any(c.isdigit() for c in decoded)

    def detect_rot18(self, text: str) -> bool:
        if not any(c.isdigit() for c in text) and not any(c.isalpha() for c in text): return False
        decoded = self.rot18_cipher(text)
        return decoded != text and self.has_english_words(decoded)

    def detect_rot8000(self, text: str) -> bool:
        if not any(0x4e00 <= ord(c) <= 0x9fa5 for c in text): return False
        decoded = self.rot8000_cipher(text)
        return decoded != text

    def detect_atbash(self, text: str) -> bool:
        clean_text = ''.join(filter(str.isalpha, text))
        if len(clean_text) < 5: return False
        decoded = self.atbash_cipher(text)
        return self.has_english_words(decoded)

    def detect_affine(self, text: str) -> bool:
        clean_text = ''.join(filter(str.isalpha, text)).upper()
        if len(clean_text) < 10: return False
        for a in [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]:
            for b in range(26):
                try:
                    decoded = self.affine_decrypt(text, a, b)
                    if self.has_english_words(decoded):
                        return True
                except Exception:
                    continue
        return False

    def detect_vigenere(self, text: str) -> bool:
        clean_text = re.sub(r'[^A-Za-z]', '', text)
        return len(clean_text) >= 20 and len(set(clean_text.lower())) > 15

    def detect_playfair(self, text: str) -> bool:
        clean_text = re.sub(r'[^A-Za-z]', '', text)
        return len(clean_text) >= 6 and len(clean_text) % 2 == 0 and 'X' in clean_text.upper()

    def detect_bacon(self, text: str) -> bool:
        clean = re.sub(r'[^A-Za-z]', '', text).upper()
        if len(clean) < 10: return False
        unique_chars = sorted(list(set(clean)))
        if len(unique_chars) == 2:
            return True
        elif len(unique_chars) > 2:
            if all(c in 'AB' for c in unique_chars) or \
               all(c.lower() in 'ab' for c in unique_chars):
               return True
        return False

    def detect_polybius(self, text: str) -> bool:
        clean = re.sub(r'[^1-5]', '', text)
        return len(clean) >= 4 and len(clean) % 2 == 0 and bool(re.match(r'^[1-5]+$', clean))

    def detect_adfgx(self, text: str) -> bool:
        clean = re.sub(r'[^ADFGX]', '', text, flags=re.IGNORECASE)
        return len(clean) >= 4 and len(clean) % 2 == 0 and bool(re.match(r'^[ADFGX]+$', clean.upper()))

    def detect_rail_fence(self, text: str) -> bool:
        clean = re.sub(r'[^A-Za-z]', '', text)
        return len(clean) >= 10

    def detect_columnar(self, text: str) -> bool:
        clean = re.sub(r'[^A-Za-z]', '', text)
        return len(clean) >= 15

    def detect_reverse(self, text: str) -> bool:
        if len(text) < 3: return False
        return self.has_english_words(text[::-1])

    def detect_keyboard_qwerty(self, text: str) -> bool:
        decoded = self.keyboard_shift(text, 'qwerty')
        return decoded != text and self.has_english_words(decoded)

    def detect_keyboard_dvorak(self, text: str) -> bool:
        decoded = self.keyboard_shift(text, 'dvorak')
        return decoded != text and self.has_english_words(decoded)

    def detect_keyboard_azerty(self, text: str) -> bool:
        decoded = self.keyboard_shift(text, 'azerty')
        return decoded != text and self.has_english_words(decoded)

    def detect_morse(self, text: str) -> bool:
        clean = re.sub(r'[^.\-/\s]', '', text)
        return len(clean) >= 3 and (clean.count('.') + clean.count('-')) > 0 and \
               bool(re.search(r'([.\-]+|\s)+', clean))

    def detect_tap_code(self, text: str) -> bool:
        clean = re.sub(r'[^.\s]', '', text)
        return len(clean) >= 4 and bool(re.match(r'^(\.+ +)+\.+$', clean.strip()))

    def detect_semaphore(self, text: str) -> bool:
        semaphore_chars = set('⛿🚩⚐⚑🔰🇦🇧🇨🇩🇪🇫🇬🇭🇮🇯🇰🇱🇲🇳🇴🇵🇶🇷🇸🇹🇺🇻🇼🇽🇾🇿')
        return any(c in text for c in semaphore_chars) or \
               bool(re.search(r'\b(flag|arm|position)\b', text, re.IGNORECASE))

    def detect_whitespace(self, text: str) -> bool:
        return text != text.strip() and ('\t' in text or '  ' in text or '\u00A0' in text)

    def detect_zero_width(self, text: str) -> bool:
        zero_width = ['\u200b', '\u200c', '\u200d', '\ufeff']
        return any(c in text for c in zero_width)

    def detect_uuencode(self, text: str) -> bool:
        lines = text.strip().split('\n')
        return len(lines) >= 2 and lines[0].startswith('begin ') and lines[-1] == 'end'

    def detect_xxencode(self, text: str) -> bool:
        lines = text.strip().split('\n')
        return len(lines) >= 2 and lines[0].startswith('begin ') and lines[-1] == 'end' and \
               any(bool(re.search(r'^[+0-9A-Za-z]{61}', line[1:])) for line in lines[1:-1] if line)

    def detect_quoted_printable(self, text: str) -> bool:
        return '=' in text and (bool(re.search(r'=[0-9A-Fa-f]{2}', text)) or '=\n' in text)

    def detect_brainfuck(self, text: str) -> bool:
        clean = re.sub(r'[^><+\-.,[\]]', '', text)
        return len(clean) >= 10 and len(clean) / len(text) > 0.75

    def detect_ook(self, text: str) -> bool:
        clean = re.sub(r'[^Ook\.!\?]', '', text)
        return len(clean) >= 9 and 'Ook' in text and (clean.count('Ook.') + clean.count('Ook?') + clean.count('Ook!')) > 3

    def detect_malbolge(self, text: str) -> bool:
        # Correcting escaped characters: \[ becomes [ and \\| becomes \|
        valid_malbolge_chars = set('ji*<v>/^%+)(}{&[$\'#@!`~_?\\|')
        clean = ''.join(c for c in text if c in valid_malbolge_chars)
        return len(clean) >= 10 and len(clean) / len(text) > 0.8

    def detect_a1z26(self, text: str) -> bool:
        parts = re.split(r'[ \-]', text.strip())
        if len(parts) < 2: return False
        try:
            numbers = [int(p) for p in parts if p.isdigit()]
            if not numbers: return False
            valid_nums = sum(1 for n in numbers if 1 <= n <= 26)
            return len(numbers) > 0 and (valid_nums / len(numbers) > 0.7)
        except ValueError:
            return False

    def detect_leet_speak(self, text: str) -> bool:
        leet_chars = {'4', '@', '3', '8', '1', '!', '7', '+', '5', '$', '0', '(', '|'}
        return any(c in text for c in leet_chars) and \
               sum(1 for char in text.lower() if char in 'aeiou') < sum(1 for char in text if char in leet_chars)

    def detect_pigpen(self, text: str) -> bool:
        return bool(re.search(r'[☗☖☗☖☗☖]', text))

    def detect_skip_cipher(self, text: str) -> bool:
        clean_text = re.sub(r'[^A-Za-z]', '', text)
        return len(clean_text) >= 15

    def detect_grille_cipher(self, text: str) -> bool:
        return bool(re.search(r'\b(grille|mask|template)\b', text, re.IGNORECASE)) and len(text) > 20

    def detect_xor(self, text: str) -> bool:
        if len(text) < 10: return False
        
        # Check raw input
        for key in range(256):
            decoded = self.xor_data(text, key)
            if self.has_english_words(decoded):
                return True
        
        # Check if hex-encoded and needs two steps (e.g., Hex -> ASCII/Binary -> XOR)
        if self.detect_hex(text):
            try:
                # Use decode_hex result for scoring check
                decoded_hex = self.decode_hex(text) 
                for key in range(256):
                    decoded = self.xor_data(decoded_hex, key)
                    if self.has_english_words(decoded):
                        return True
            except:
                pass

        return False
    
    # =========================================================
    # --- DECODING METHODS (The original one's) ---
    # =========================================================

    def decode_base16(self, text: str) -> str:
        text = text.strip().replace(' ', '')
        return base64.b16decode(text.upper()).decode('utf-8', errors='ignore')
    def decode_base32(self, text: str) -> str:
        text = text.strip().replace(' ', '').upper()
        missing_padding = len(text) % 8
        if missing_padding != 0:
            text += '=' * (8 - missing_padding)
        return base64.b32decode(text).decode('utf-8', errors='ignore')
    def decode_base45(self, text: str) -> str:
        return "Base45 decoding requires a dedicated library or full custom implementation."
    def decode_base58(self, text: str) -> str:
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        base_count = len(alphabet)
        decoded_int = 0
        for char in text:
            decoded_int = decoded_int * base_count + alphabet.index(char)
        
        result_bytes = bytearray()
        while decoded_int > 0:
            result_bytes.append(decoded_int % 256)
            decoded_int //= 256
        result_bytes.reverse()

        for char in text:
            if char == '1':
                result_bytes.insert(0, 0)
            else:
                break
        
        return result_bytes.decode('utf-8', errors='ignore')
    def decode_base64(self, text: str) -> str:
        text = text.strip()
        missing_padding = len(text) % 4
        if missing_padding != 0:
            text += '=' * (4 - missing_padding)
        return base64.b64decode(text).decode('utf-8', errors='ignore')
    def decode_base85(self, text: str) -> str:
        try:
            if text.startswith('<~') and text.endswith('~>'):
                return base64.a85decode(text.encode('ascii')).decode('utf-8', errors='ignore')
            else:
                return base64.a85decode(text.encode('ascii'), adobe=False).decode('utf-8', errors='ignore')
        except binascii.Error:
            return "Base85 decoding failed. Ensure correct format (e.g., <~ ~> for Adobe variant)."
    def decode_base91(self, text: str) -> str:
        return "Base91 decoding requires custom implementation."
    def decode_base92(self, text: str) -> str:
        return "Base92 decoding requires custom implementation."
    def decode_ascii_hex(self, text: str) -> str:
        def hex_to_char(match):
            return chr(int(match.group(0)[2:], 16))
        return re.sub(r'\\x[0-9A-Fa-f]{2}', hex_to_char, text)
    def decode_binary(self, text: str) -> str:
        text = text.strip().replace(' ', '')
        if not text: return ""
        try:
            return ''.join(chr(int(text[i:i+8], 2)) for i in range(0, len(text), 8))
        except ValueError:
            return "Invalid binary sequence for ASCII decoding."
    def decode_octal(self, text: str) -> str:
        text = text.strip().replace(' ', '')
        if not text: return ""
        try:
            return ''.join(chr(int(text[i:i+3], 8)) for i in range(0, len(text), 3))
        except ValueError:
            return "Invalid octal sequence for ASCII decoding."
    def decode_decimal(self, text: str) -> str:
        if not text.strip(): return ""
        try:
            return ''.join(chr(int(part)) for part in text.strip().split())
        except ValueError:
            return "Invalid decimal sequence for ASCII decoding."
    def decode_hex(self, text: str) -> str:
        text = text.strip().replace(' ', '').replace('-', '').replace('0x', '')
        if not text: return ""
        try:
            # Use latin-1 to avoid errors with potential binary data
            return binascii.unhexlify(text).decode('latin-1', errors='ignore') 
        except binascii.Error:
            return "Invalid hexadecimal string."
    def decode_url_encoding(self, text: str) -> str:
        return urllib.parse.unquote(text)
    def decode_double_url(self, text: str) -> str:
        return urllib.parse.unquote(urllib.parse.unquote(text))
    def decode_html_entities(self, text: str) -> str:
        return html.unescape(text)
    def decode_html_decimal(self, text: str) -> str:
        return html.unescape(text)
    def decode_html_hex(self, text: str) -> str:
        return html.unescape(text)
    def decode_xml_entities(self, text: str) -> str:
        return html.unescape(text)
    def decode_caesar(self, text: str) -> str:
        # --- FIX: Ensure a string is returned on failure ---
        decoded = self.decode_with_english_scoring(text, self.caesar_shift, range(1, 26))
        return decoded if decoded != text else text # Force string return
    def decode_rot13(self, text: str) -> str:
        return self.caesar_shift(text, 13)
    def decode_rot47(self, text: str) -> str:
        return self.rot47_cipher(text)
    def decode_rot5(self, text: str) -> str:
        return self.rot5_cipher(text)
    def decode_rot18(self, text: str) -> str:
        return self.rot18_cipher(text)
    def decode_rot8000(self, text: str) -> str:
        return self.rot8000_cipher(text)
    def decode_atbash(self, text: str) -> str:
        # --- FIX: Ensure a string is returned on failure ---
        decoded = self.atbash_cipher(text)
        return decoded if self.has_english_words(decoded) else text
    def decode_affine(self, text: str) -> str:
        best_decoded = ""
        best_score = -1.0
        for a_val in [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]:
            for b_val in range(26):
                try:
                    decoded = self.affine_decrypt(text, a_val, b_val)
                    score = self.score_english(decoded)
                    if score > best_score:
                        best_score = score
                        best_decoded = decoded
                except ValueError:
                    continue
        # --- FIX: Ensure a string is returned on failure ---
        if best_decoded and self.score_english(best_decoded) > 5.0:
            return best_decoded
        return text
    def decode_vigenere(self, text: str) -> str:
        # --- FIX: Ensure a string is returned on failure ---
        decoded = self.decode_with_english_scoring(text, self.vigenere_decrypt, ['key', 'password', 'secret', 'flag', 'ctf', 'the', 'and', 'cipher', 'cryptography'])
        return decoded if decoded != text else text
    def decode_playfair(self, text: str) -> str:
        return "Playfair decoding is complex and requires a key and matrix. Manual decryption recommended."
    def decode_bacon(self, text: str) -> str:
        clean = re.sub(r'[^A-Za-z]', '', text).upper()
        
        char_counts = collections.Counter(clean)
        if len(char_counts) < 2:
            return "Baconian requires at least two distinct characters."
        
        most_common_chars = [char for char, _ in char_counts.most_common(2)]
        
        if len(most_common_chars) < 2:
            return "Baconian requires at least two distinct characters."

        char_a = most_common_chars[0]
        char_b = most_common_chars[1]

        bacon_map = {
            'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D', 'AABAA': 'E',
            'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H', 'ABAAA': 'I', 'ABAAB': 'J',
            'ABABA': 'K', 'ABABB': 'L', 'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O',
            'ABBBB': 'P', 'BAAAA': 'Q', 'BAAAB': 'R', 'BAABA': 'S', 'BAABB': 'T',
            'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X', 'BBAAA': 'Y',
            'BBAAB': 'Z'
        }
        
        translation_table = str.maketrans(char_a + char_b, 'AB')
        translated_clean = clean.translate(translation_table)

        binary = translated_clean # It's already 'A'/'B', which is effectively binary

        result = []
        for i in range(0, len(binary), 5):
            byte = binary[i:i+5]
            if len(byte) == 5:
                key = byte.replace('B', 'B').replace('A', 'A') 
                result.append(bacon_map.get(key, '?'))
            else:
                result.append('?')
        
        return ''.join(result)
    def decode_polybius(self, text: str) -> str:
        clean = re.sub(r'[^1-5]', '', text)
        polybius_square = [
            ['A', 'B', 'C', 'D', 'E'],
            ['F', 'G', 'H', 'I', 'K'],
            ['L', 'M', 'N', 'O', 'P'],
            ['Q', 'R', 'S', 'T', 'U'],
            ['V', 'W', 'X', 'Y', 'Z']
        ]
        result = []
        for i in range(0, len(clean), 2):
            if i + 1 < len(clean):
                try:
                    row = int(clean[i]) - 1
                    col = int(clean[i+1]) - 1
                    if 0 <= row < 5 and 0 <= col < 5:
                        result.append(polybius_square[row][col])
                    else:
                        result.append('?')
                except ValueError:
                    result.append('?')
            else:
                result.append('?')
        return ''.join(result)
    def decode_adfgx(self, text: str) -> str:
        return "ADFGX decoding requires a key and specific matrix. Manual decryption recommended."
    def decode_rail_fence(self, text: str) -> str:
        # --- FIX: Ensure a string is returned on failure ---
        best_decoded = ""
        best_score = -1.0
        max_rails = min(10, len(text))
        for rails in range(2, max_rails + 1):
            decoded = self.rail_fence_decrypt(text, rails)
            score = self.score_english(decoded)
            if score > best_score:
                best_score = score
                best_decoded = decoded
        return best_decoded if best_decoded and self.score_english(best_decoded) > 5.0 else text
    def decode_columnar(self, text: str) -> str:
        # --- FIX: Ensure a string is returned on failure ---
        best_decoded = ""
        best_score = -1.0
        max_key_length = min(8, len(text) // 2)
        for key_length in range(2, max_key_length + 1):
            decoded = self.columnar_decrypt(text, key_length)
            score = self.score_english(decoded)
            if score > best_score:
                best_score = score
                best_decoded = decoded
        return best_decoded if best_decoded and self.score_english(best_decoded) > 5.0 else text
    def decode_reverse(self, text: str) -> str:
        return text[::-1]
    def decode_keyboard_qwerty(self, text: str) -> str:
        decoded = self.keyboard_shift(text, 'qwerty')
        return decoded if self.score_english(decoded) > 5.0 else text
    def decode_keyboard_dvorak(self, text: str) -> str:
        decoded = self.keyboard_shift(text, 'dvorak')
        return decoded if self.score_english(decoded) > 5.0 else text
    def decode_keyboard_azerty(self, text: str) -> str:
        decoded = self.keyboard_shift(text, 'azerty')
        return decoded if self.score_english(decoded) > 5.0 else text
    def decode_morse(self, text: str) -> str:
        morse_code_map = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G',
            '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N',
            '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U',
            '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y', '--ez': 'Z',
            '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
            '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
            '.-.-.-': '.', '--..--': ',', '..--..': '?', '---...': ':', '-.-.--': '!',
            '-....-': '-', '.-..-.': '"', '.----.': "'", '-.-.-.': ';', '.-.-.': '+'
        }
        
        words = text.strip().split('   ')
        decoded_words = []
        for word in words:
            letters = word.strip().split(' ')
            decoded_word = ''.join(morse_code_map.get(letter, '') for letter in letters)
            decoded_words.append(decoded_word)
        return ' '.join(decoded_words)
    def decode_tap_code(self, text: str) -> str:
        tap_square = [
            ['A', 'B', 'C', 'D', 'E'],
            ['F', 'G', 'H', 'I', 'J'],
            ['L', 'M', 'N', 'O', 'P'],
            ['Q', 'R', 'S', 'T', 'U'],
            ['V', 'W', 'X', 'Y', 'Z']
        ]
        
        clean = re.sub(r'[^.\s]', '', text)
        groups = clean.strip().split(' ')
        
        result = []
        for group in groups:
            sub_groups = [s for s in group.split('.') if s] # Split by dots, remove empty strings
            if len(sub_groups) == 2:
                row_taps = len(sub_groups[0])
                col_taps = len(sub_groups[1])
            else:
                row_taps = 0
                col_taps = 0

            if row_taps > 0 and col_taps > 0:
                row_idx = row_taps - 1
                col_idx = col_taps - 1
                
                if 0 <= row_idx < 5 and 0 <= col_idx < 5:
                    result.append(tap_square[row_idx][col_idx])
                else:
                    result.append('?')
            else:
                result.append('?')
        return ''.join(result)
    def decode_semaphore(self, text: str) -> str:
        return "Semaphore decoding requires visual interpretation of flag positions or specific symbol sets not easily decoded from plain text."
    def decode_uuencode(self, text: str) -> str:
        lines = text.strip().split('\n')
        if not lines or not lines[0].startswith('begin') or not lines[-1] == 'end':
            return "Invalid UUencode format."
        
        decoded_data_parts = []
        for line in lines[1:-1]:
            if not line:
                continue
            try:
                length_char = line[0]
                num_bytes_encoded = (ord(length_char) - 32) & 0x3f
                encoded_chunk_chars = line[1:]
                decoded_bytes_chunk = bytearray()
                for i in range(0, len(encoded_chunk_chars), 4):
                    chars = [(ord(c) - 32) for c in encoded_chunk_chars[i:i+4]]
                    if len(chars) >= 2:
                        decoded_bytes_chunk.append((chars[0] << 2) | ((chars[1] & 0x30) >> 4))
                    if len(chars) >= 3:
                        decoded_bytes_chunk.append(((chars[1] & 0x0f) << 4) | ((chars[2] & 0x3c) >> 2))
                    if len(chars) >= 4:
                        decoded_bytes_chunk.append(((chars[2] & 0x03) << 6) | chars[3])
                decoded_data_parts.append(bytes(decoded_bytes_chunk[:num_bytes_encoded]).decode('utf-8', errors='ignore'))
            except (ValueError, IndexError, binascii.Error) as e:
                return f"Error during UUencode decoding: {e}"
        return ''.join(decoded_data_parts)
    def decode_xxencode(self, text: str) -> str:
        lines = text.strip().split('\n')
        if not lines or not lines[0].startswith('begin') or not lines[-1] == 'end':
            return "Invalid XXencode format."
        
        decoded_data_parts = []
        for line in lines[1:-1]:
            if not line:
                continue
            
            try:
                length_char = line[0]
                num_bytes_encoded = ord(length_char) - 32 
                
                encoded_chunk_chars = line[1:]
                
                decoded_bytes_chunk = bytearray()
                for i in range(0, len(encoded_chunk_chars), 4):
                    chars_raw = encoded_chunk_chars[i:i+4]
                    if len(chars_raw) < 2: continue 

                    chars_values = [(ord(c) - 32) & 0x3f for c in chars_raw] 

                    if len(chars_values) >= 2:
                        decoded_bytes_chunk.append((chars_values[0] << 2) | ((chars_values[1] & 0x30) >> 4))
                    if len(chars_values) >= 3:
                        decoded_bytes_chunk.append(((chars_values[1] & 0x0f) << 4) | ((chars_values[2] & 0x3c) >> 2))
                    if len(chars_values) >= 4:
                        decoded_bytes_chunk.append(((chars_values[2] & 0x03) << 6) | chars_values[3])
                
                decoded_data_parts.append(bytes(decoded_bytes_chunk[:num_bytes_encoded]).decode('utf-8', errors='ignore'))
            except (ValueError, IndexError) as e:
                return f"Error during XXencode decoding: {e}"
        
        return ''.join(decoded_data_parts)
    def decode_quoted_printable(self, text: str) -> str:
        decoded_text = text.replace('=\n', '')
        
        pattern = r'=[0-9A-Fa-f]{2}'
        def replace_match(match):
            return chr(int(match.group()[1:], 16))
        
        return re.sub(pattern, replace_match, decoded_text)
    def decode_brainfuck(self, text: str) -> str:
        return "Brainfuck code detected. It's an executable esoteric language, not a simple encoding. Requires an interpreter."
    def decode_ook(self, text: str) -> str:
        ook_to_bf_map = {
            'Ook. Ook?': '>', 'Ook? Ook.': '<', 'Ook. Ook.': '+', 'Ook! Ook!': '-',
            'Ook! Ook.': '.', 'Ook. Ook!': ',', 'Ook? Ook!': '[', 'Ook! Ook?': ']',
        }
        
        bf_code = text
        for ook_pattern, bf_char in ook_to_bf_map.items():
            bf_code = bf_code.replace(ook_pattern, bf_char)
        
        return f"Ook! code translated to Brainfuck: {bf_code[:100]}{'...' if len(bf_code) > 100 else ''}. Requires an interpreter."
    def decode_malbolge(self, text: str) -> str:
        return "Malbolge is an extremely complex esoteric language. Decoding requires a very specialized interpreter and understanding of its self-modifying nature."
    def decode_a1z26(self, text: str) -> str:
        parts = re.split(r'[ \-]', text.strip())
        result = []
        for part in parts:
            if part.isdigit():
                num = int(part)
                if 1 <= num <= 26:
                    result.append(chr(ord('A') + num - 1))
                else:
                    result.append('?')
            else:
                result.append(part)
        return ''.join(result)
    def decode_leet_speak(self, text: str) -> str:
        leet_to_normal_map = {
            '4': 'a', '@': 'a', '3': 'e', '8': 'b', '1': 'l', '!': 'i', '7': 't', '+': 't', '5': 's', '$': 's',
            '0': 'o', '(': 'c', '|': 'i', '\\/': 'v', '/\\': 'a', '/_\\\\': 'n', '|\\|': 'n', '/v': 'v',
            '|_|': 'u', '(-)': 'h', '[-]': 'h', 'ph': 'f', 'gh': 'f', 'j00': 'you', 'w00t': 'what', 'hax0r': 'hacker'
        }
        
        decoded_text = text.lower()
        for leet_char, normal_char in sorted(leet_to_normal_map.items(), key=lambda item: len(item[0]), reverse=True):
            decoded_text = decoded_text.replace(leet_char, normal_char)
        
        return decoded_text.capitalize()
    def decode_pigpen(self, text: str) -> str:
        return "Pigpen cipher uses symbols. Decoding requires visual comparison with a Pigpen key chart."
    def decode_skip_cipher(self, text: str) -> str:
        # --- FIX: Ensure a string is returned on failure ---
        best_decoded = ""
        best_score = -1.0
        clean_text = re.sub(r'[^A-Za-z]', '', text)
        if not clean_text: return text

        for skip in range(2, min(len(clean_text) // 2 + 1, 10)):
            num_groups = skip
            groups = [[] for _ in range(num_groups)]
            
            for i, char in enumerate(clean_text):
                groups[i % num_groups].append(char)
            
            reconstructed = list(itertools.chain.from_iterable(groups))
            decoded = ''.join(reconstructed)
            
            score = self.score_english(decoded)
            if score > best_score:
                best_score = score
                best_decoded = decoded
                
        return best_decoded if best_decoded and self.score_english(best_decoded) > 5.0 else text
    def decode_grille_cipher(self, text: str) -> str:
        return "Grille cipher decryption requires the physical or digital grille (template) to reveal the message."
    
    # --- UUID Decoding Method (Final Robust Version) ---
    def decode_uuid(self, text: str) -> str:
        try:
            u = uuid.UUID(text.strip())
            
            # --- ROBUST VARIANT DETECTION (Based on UUID Version for stability) ---
            # Assume for all V1, V3, V4, V5, V6 that the variant is RFC 4122 (Variant 2)
            if u.version in [1, 3, 4, 5, 6]:
                variant_name = "RFC 4122 / DCE 1.1, ISO/IEC 11578:1996"
            elif hasattr(u.variant, 'name'):
                 variant_name = u.variant.name.replace('_', ' ').title()
            else:
                 # Last resort fallback, using the integer value as a name
                 variant_name = f"Unknown Variant ({str(u.variant)})"


            info = []
            info.append(f"  Version: {u.version} | Variant: {variant_name}")
            
            if u.version == 1:
                # UUIDv1 includes node (MAC address) and timestamp
                timestamp = u.time
                # Convert 100-nanosecond intervals since 00:00:00.00, 15 October 1582
                seconds_since_epoch = (timestamp - 0x01b21dd213814000) // 10000000
                dt_object = datetime.datetime.fromtimestamp(seconds_since_epoch, datetime.timezone.utc)
                info.append(f"  Node (MAC): {u.node:012x}")
                info.append(f"  Timestamp: {dt_object.isoformat()}")
            elif u.version in [3, 5]:
                info.append(f"  Generation: Based on Namespace/Name Hashing")
            elif u.version == 4:
                info.append(f"  Generation: Randomly Generated")
            elif u.version == 6:
                info.append(f"  Generation: Reordered Time-based (RFC 4122bis)")
            
            return "\n".join(info)

        except ValueError:
            return "Invalid UUID format or value."

    def decode_xor(self, text: str) -> str:
        best_decoded = ""
        best_score = -1.0
        best_key = -1
        
        # Determine the data to be XORed: either raw or hex-decoded
        data_to_xor = text
        is_hex_input = self.detect_hex(text) and len(text) % 2 == 0 and len(text) > 10
        
        if is_hex_input:
            try:
                # Use decode_hex result for the actual XOR operation
                data_to_xor = binascii.unhexlify(text).decode('latin-1', errors='ignore')
            except:
                pass

        for key in range(256):
            decoded = self.xor_data(data_to_xor, key)
            score = self.score_english(decoded)

            if score > best_score:
                best_score = score
                best_decoded = decoded
                best_key = key
        
        # Set a clear threshold for plausibility
        if best_score > self.score_english(data_to_xor) + 5.0 and self.has_english_words(best_decoded): 
            return f"{best_decoded} (Key: 0x{best_key:02x})"
        
        return "XOR decoding failed to find a plausible plaintext."


    def decode_with_english_scoring(self, text: str, decoder_func, param_range: Any) -> str:
        best_decoded = text
        best_score = self.score_english(text)
        
        for param in param_range:
            try:
                decoded = decoder_func(text, param)
                score = self.score_english(decoded)
                if score > best_score:
                    best_score = score
                    best_decoded = decoded
            except Exception:
                continue
        
        if best_score > self.score_english(text) + 2.0:
             return best_decoded
        elif best_decoded != text and best_score > 5.0:
             return best_decoded
        else:
             return text
    
def decode_recursive_chain(detector: 'UltimateEncodingDetector', text: str, max_depth: int = 5, current_chain: Optional[List[Dict]] = None) -> Tuple[str, List[Dict]]:
    """
    Recursively decodes a string.
    The recursion stops if:
    1. max_depth is reached.
    2. No new encoding method is detected in the decoded result.
    """
    if current_chain is None:
        current_chain = []

    if len(current_chain) >= max_depth:
        return text, current_chain

    # 1. Get all valid decodes for the current text
    decoded_results = detector.get_all_decodes_for_string(text)
    
    # Filter for the single best, most plausible decode based on English score
    best_decode = None
    best_score = -1.0
    
    for name, result in decoded_results.items():
        score = 0.0
        
        # --- NEW PRIORITY LOGIC ---
        if name in ['hex', 'base64'] and result != text and not str(result).startswith('Invalid'):
            # Give priority to clean low-level encodings if they decode without error
            # This prioritizes intermediate layers over gibberish-English
            score = 100.0 
        elif name == 'uuid':
            score = 90.0
        elif name == 'xor' and ' (Key:' in result:
            plaintext_part = result.split(' (Key:')[0]
            score = detector.score_english(plaintext_part)
        else:
            score = detector.score_english(result)
        # --- END NEW PRIORITY LOGIC ---
            
        if score > best_score:
            best_score = score
            best_decode = (name, result)

    # Base Case: No meaningful decode found in this step
    if not best_decode or best_score < 5.0: 
        return text, current_chain

    best_name, best_result = best_decode
    
    # Secondary check: Is the best result a candidate for further decoding?
    # We strip XOR key info for the next detection step
    result_for_next_detection = best_result.split(' (Key:')[0] if best_name == 'xor' else best_result
    
    next_detections = detector.detect_all(result_for_next_detection)
    is_next_layer_detected = False
    
    for name, is_detected in next_detections.items():
        # UUID is a terminal decode, it doesn't lead to another encoding, so we skip it here.
        if name == 'uuid': continue 
        
        # Only check a new method (not the one we just used, and not a non-decodable type)
        if is_detected and name != best_name and name not in detector.non_decodable_types:
            is_next_layer_detected = True
            break
            
    # Add the current step to the chain
    current_chain.append({"method": best_name, "text": best_result})

    # Recursive Step: If a new layer is detected, continue the chain.
    if is_next_layer_detected and best_name != 'uuid':
        return decode_recursive_chain(detector, result_for_next_detection, max_depth, current_chain)
    
    # Final Base Case: No new layer detected, so the current result is the final plaintext.
    return best_result, current_chain

def decode_json_recursive(data: Any, detector: 'UltimateEncodingDetector') -> Any:
    """Recursively traverses a JSON structure and attempts to decode all string values (Single Pass for JSON mode)."""
    if isinstance(data, dict):
        new_data = {}
        for key, value in data.items():
            new_data[key] = decode_json_recursive(value, detector)
        return new_data
    elif isinstance(data, list):
        return [decode_json_recursive(item, detector) for item in data]
    elif isinstance(data, str):
        # Skip strings that are too short to be meaningful encodings
        if len(data.strip()) < 4:
            return data

        decoded_results = detector.get_all_decodes_for_string(data)
        
        valid_results = {k: v for k, v in decoded_results.items() if not str(v).startswith("Error") and v != data}
        
        if valid_results:
            # Find the best decoding using English scoring
            best_result = None
            best_score = -1.0
            
            for name, result in valid_results.items():
                if name == 'uuid':
                    score = 100.0
                elif name == 'xor' and ' (Key:' in result:
                    plaintext_part = result.split(' (Key:')[0]
                    score = detector.score_english(plaintext_part)
                else:
                    score = detector.score_english(result)
                    
                if score > best_score:
                    best_score = score
                    best_result = (name, result)

            # Return a structured object for the decoded string if score is above a threshold
            if best_result and best_score > 5.0: 
                return {
                    "original_string_deepread_input": data,
                    "is_decoded_by_deepread": True,
                    "best_decoding_deepread": {
                        "method": best_result[0],
                        "text": best_result[1]
                    },
                    "all_valid_decodings_deepread": valid_results
                }
            else:
                return data # No good decode found, return original string
        else:
            return data # Not a detected encoding, return original string
    else:
        # Other types (int, bool, float, None)
        return data

def process_json_file(filepath: str, detector: 'UltimateEncodingDetector'):
    print(f"📁 Reading JSON file: {filepath}")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"❌ Error: File not found at {filepath}")
        return
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON format in {filepath}: {e}")
        return

    print("🔬 Recursively decoding all string values. This may take a moment...")
    decoded_data = decode_json_recursive(data, detector)

    # Create output filename with an emoji
    if '.' in filepath:
        base, ext = filepath.rsplit('.', 1)
        output_filepath = f"{base}_✨decoded.{ext}"
    else:
        output_filepath = f"{filepath}_✨decoded.json" # Default to .json if no extension

    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            # Use ensure_ascii=False to save the emoji properly
            json.dump(decoded_data, f, indent=2, ensure_ascii=False) 
        print(f"\n✅ Decoding complete. Results saved to: {output_filepath}")
        print("Note: Decoded strings are replaced by a structured object containing 'original_string_deepread_input' and decoding results.")
    except Exception as e:
        print(f"❌ Error saving output file: {e}")

def process_file(filepath: str) -> str:
    with open(filepath, 'rb') as f:
        raw_data = f.read()
    
    if chardet:
        result = chardet.detect(raw_data)
        encoding = result['encoding'] if result['confidence'] > 0.5 else 'utf-8'
        print(f"Chardet detected encoding: {encoding} (confidence: {result['confidence']:.2f})")
    else:
        encoding = 'utf-8'
        print("Chardet not installed. Defaulting to UTF-8 for file processing.")

    try:
        return raw_data.decode(encoding)
    except UnicodeDecodeError:
        print(f"UnicodeDecodeError with {encoding}, trying 'latin-1'")
        return raw_data.decode('latin-1', errors='ignore')

def process_ai_detection(client, text: str) -> str:
    """Sends the raw input to Gemini for encoding identification and decoding."""
    
    prompt = (
        "Analyze the following input string. Your task is to act as a universal decoding engine. "
        "1. Identify the *most probable* single encoding or cipher (e.g., Base64, Hex, Vigenere, Caesar ,etc). "
        "2. Decode/decrypt the string fully. If it is multi-layered, continue decoding until you reach clear plaintext or the final JSON/XML object. "
        "3. Provide the result in a clean, structured JSON format with the following keys:\n"
        '{"identified_encoding": "NAME_OF_ENCODING", "is_multi_layered": true/false, "decoded_plaintext": "YOUR_FINAL_PLAINTEXT"}'
    )

    full_prompt = f"{prompt}\n\n--- Input Data ---\n{text}"
    
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=full_prompt
        )
        return response.text
    
    except GeminiAPIError as e:
        return f"🚨 GEMINI API ERROR: Check your API Key, network connection, or usage limits. Error details: {e}"
    except Exception as e:
        return f"🚨 UNEXPECTED ERROR during AI process: {e}"


def main():
    parser = argparse.ArgumentParser(description="ULTIMATE Universal Encoding Detector and Decoder - V4.0(by Azazi)")
    
    # --- ARGUMENT GROUPING ---
    input_group = parser.add_argument_group('Input Options', 'Define the source data for analysis.')
    input_group.add_argument('-t', '--text', type=str, help="Input text to detect and decode")
    input_group.add_argument('-f', '--file', type=str, help="Input file to detect and decode (plain text)")
    input_group.add_argument('-j', '--json', type=str, help="Input JSON file to recursively decode all string values and save output.")

    mode_group = parser.add_argument_group('Mode & Analysis', 'Select primary mode of operation.')
    mode_group.add_argument('-d', '--decode', action='store_true', help="Attempt to decode detected encodings (automatically enabled for -m)")
    mode_group.add_argument('-m', '--multi-layers', action='store_true', help="Enable multi-layer/stacked decoding (e.g., Hex -> Base64 -> Plaintext)")
    mode_group.add_argument('-u', '--uid', action='store_true', help="Force UUID-only detection and decoding for clean analysis.")
    mode_group.add_argument('-g', '--gemini', action='store_true', help="Use Gemini AI for advanced plausible output filtering and extraction.") # <--- NEW GEMINI PARAMETER

    output_group = parser.add_argument_group('Output & Formatting', 'Control how results are displayed.')
    output_group.add_argument('-a', '--all', action='store_true', help="Show all detection results, not just detected ones")
    output_group.add_argument('-c', '--confidence', action='store_true', help="Show confidence scores for detected encodings (experimental)")
    output_group.add_argument('--top', type=int, default=0, help="Show only the top N most confident detections (implies --confidence)")
    output_group.add_argument('-l', '--long', action='store_true', help="Show full, untruncated output for decoded strings.")
    output_group.add_argument('-o', '--output', type=str, help="Output results to a JSON file (only applicable for -t/-f mode)")
    # --- END ARGUMENT GROUPING ---

    args = parser.parse_args()

    # Define truncation length based on the new argument
    MAX_OUTPUT_CHARS = 10000 if args.long else 200

    # Need 'datetime' for UUIDv1 decoding
    import datetime

    if args.json:
        detector = UltimateEncodingDetector()
        process_json_file(args.json, detector)
        return

    if not args.text and not args.file:
        print("❌ Please provide either --text, --file, --json, or --uid with text")
        return

    detector = UltimateEncodingDetector()
    if args.file:
        text = process_file(args.file)
        print(f"📁 File content: {text[:100]}{'...' if len(text) > 100 else ''}")
    else:
        text = args.text

    # --- AI-POWERED DETECTION MODE (-a and -g together) ---
    if args.all and args.gemini:
        print(f"\n🧠 AI-Powered Detection Mode Initiated: Analyzing raw input with Gemini...")
        if not detector.gemini_client:
            print("❌ GEMINI ERROR: Client failed to initialize. Check `pip install google-genai` and `.gemini_key` file or `GEMINI_API_KEY`.")
            return

        ai_analysis_text = process_ai_detection(detector.gemini_client, text)
        
        print("\n🤖 AI-Powered Decoding (Gemini Model):")
        print("-" * 60)
        print(ai_analysis_text)
        print("-" * 60)
        return


    # --- DEDICATED UUID PARAMETER LOGIC ---
    if args.uid:
        print(f"\n🎯 Analyzing UUID: {text}")
        if detector.detect_uuid(text):
            print("-" * 60)
            print("✅ UUID Detected.")
            decoded_info = detector.decode_uuid(text)
            print("\n📝 UUID METADATA:")
            print(f"{decoded_info}")
        else:
            print(f"❌ Input is not a valid UUID: {text}")
        return


    print(f"\n🔍 Analyzing: {text[:50]}{'...' if len(text) > 50 else ''}")
    print("-" * 60)

    # --- MULTI-LAYER DECODING LOGIC ---
    if args.multi_layers:
        print("🔄 Initiating Multi-Layer Decoding (Max 5 steps)...")
        final_text, chain = decode_recursive_chain(detector, text)

        # --- GEMINI AI POST-PROCESSING (for -m mode) ---
        if args.gemini and detector.gemini_client:
            print("\n🧠 Sending results to Gemini AI for Plausibility Check...")
            
            # Combine the chain results into one large string
            ai_input = f"Original Input: {text}\n"
            ai_input += "--- Decoding Chain ---\n"
            for step in chain:
                ai_input += f"[{step['method'].upper()}]: {step['text'][:500]}{'...' if len(step['text']) > 500 else ''}\n"
            ai_input += f"--- Final Algorithmic Result ---\n{final_text}"

            ai_analysis = process_with_ai_post_process(detector.gemini_client, ai_input, 'multi-layer')

            print("\n🤖 AI Post-Analysis (Gemini Model):")
            print("-" * 60)
            print(ai_analysis)
            print("-" * 60)
            return
        # --- END GEMINI AI POST-PROCESSING ---
        
        if chain:
            print(f"\n🎉 Multi-Layer Decoding Chain Found ({len(chain)} steps):")
            for i, step in enumerate(chain):
                method = step.get('method', 'Unknown')
                decoded_output = step.get('text', 'Error')
                # Use MAX_OUTPUT_CHARS for truncation
                truncated_output = decoded_output[:MAX_OUTPUT_CHARS]
                dots = '...' if len(decoded_output) > MAX_OUTPUT_CHARS else ''
                print(f"  [{i+1}] {method.upper()} -> {truncated_output}{dots}")
            print("\n  FINAL PLAINTEXT:")
            print(f"  {final_text}")
        else:
            print("❓ No multi-layer encoding found. Performing single-pass detection.")
        
        # If a chain was found, we stop here to avoid confusing single-pass output
        if chain:
             return 

    # --- SINGLE-PASS DECODING LOGIC (or fallback from multi-layers) ---
    detected = detector.detect_all(text)
    confidence_scores = {}
    
    # Calculate confidence scores for all detections
    for encoding, is_detected in detected.items():
        if is_detected:
            # We use the English scoring system to generate a simple confidence score
            score = detector.score_english(text)
            confidence = min(100, max(0, int(score * 5))) 
            confidence_scores[encoding] = confidence
        else:
            confidence_scores[encoding] = 0 

    # Sort detections by confidence, showing non-detected last
    sorted_detections = sorted(detected.items(), key=lambda item: confidence_scores.get(item[0], 0), reverse=True)

    if args.all:
        print("🎯 Detection results (Single Pass):")
        for encoding, is_detected in sorted_detections:
            # Check for extended hash info
            hash_info = detected.get(f'{encoding}_info', None)
            
            status = "✅ Detected" if is_detected else "❌ Not detected"
            conf = f" (confidence: {confidence_scores.get(encoding, 0)}%)" if args.confidence or args.top > 0 else ""
            info = f" ({hash_info})" if hash_info else ""
            print(f"  {encoding}: {status}{conf}{info}")
        print()

    found_encodings = [(name, confidence_scores.get(name, 0)) for name, is_detected in detected.items() if is_detected]
    found_encodings.sort(key=lambda x: x[1], reverse=True)

    if args.top > 0:
        found_encodings = found_encodings[:args.top]


    if found_encodings:
        print(f"🎉 Detected encodings: {', '.join([name for name, _ in found_encodings])}")
        
        # --- GEMINI AI POST-PROCESSING (for single-pass mode) ---
        if args.gemini and args.decode and detector.gemini_client:
            print("\n🧠 Sending top decodes to Gemini AI for Plausibility Check...")
            decoded_results = detector.get_all_decodes_for_string(text)
            
            ai_input = f"Original Input: {text}\n"
            ai_input += "--- Top Decoded Results ---\n"
            
            top_decodes_list = []
            for encoding, conf in found_encodings:
                 if encoding in decoded_results:
                     top_decodes_list.append(f"[{encoding.upper()}]: {decoded_results[encoding][:500]}{'...' if len(decoded_results[encoding]) > 500 else ''}")

            if not top_decodes_list:
                print("⚠️ No successfully decoded results to send to AI.")
                return

            ai_input += "\n".join(top_decodes_list)
            
            ai_analysis = process_with_ai_post_process(detector.gemini_client, ai_input, 'single-pass')

            print("\n🤖 AI Post-Analysis (Gemini Model):")
            print("-" * 60)
            print(ai_analysis)
            print("-" * 60)
            return # Exit after AI output
        # --- END GEMINI AI POST-PROCESSING ---


        # Standard Decode Output (if no AI or -d used)
        if args.decode:
            print("\n🔓 Decoding results:")
            decoded_results = detector.get_all_decodes_for_string(text)
            for encoding, conf in found_encodings:
                hash_info = detected.get(f'{encoding}_info', None)
                if encoding in decoded_results:
                    info_str = f" ({hash_info})" if hash_info else ""
                    print(f"\n📝 {encoding.upper()} (Confidence: {conf}%){info_str}:")
                    result = decoded_results[encoding]
                    # Use MAX_OUTPUT_CHARS for truncation
                    truncated_result = result[:MAX_OUTPUT_CHARS]
                    dots = '...' if len(result) > MAX_OUTPUT_CHARS else ''
                    
                    # Print UUID output neatly
                    if encoding == 'uuid':
                        print(f"{result}")
                    else:
                        print(f"  Decoded: {truncated_result}{dots}")
                elif hash_info:
                    print(f"\n📝 {encoding.upper()} (HASH - NOT DECODABLE):")
                    print(f"  Info: {hash_info}")
    else:
        print("❓ No known encodings detected")

    if args.output:
        results = {
            'input': text[:100] + ('...' if len(text) > 100 else ''),
            'detected_encodings': [{'name': name, 'confidence': conf, 'info': detected.get(f'{name}_info')} for name, conf in found_encodings],
            'decodings': detector.get_all_decodes_for_string(text) if args.decode else {}
        }
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n💾 Results saved to {args.output}")

def process_with_ai_post_process(client, input_data: str, mode: str) -> str:
    """Sends the algorithmic results to Gemini for plausible plaintext extraction."""
    
    if mode == 'multi-layer':
        prompt = (
            "Analyze the following multi-step decoding chain. Your task is to identify the most plausible and clear plaintext result. "
            "Also, explicitly check the output of each step for any obvious indicators of *another* layer of encoding (like a Base64 string, Hex string, URL encoding, etc.) that the algorithmic decoder might have missed. "
            "Respond in a concise, structured markdown format with the final clear message and any suggested next steps or missed layers."
        )
    else: # single-pass
        prompt = (
            "Analyze the following original input and the various algorithmic decoding results. Your task is to find the MOST PLAUSIBLE PLAINTEXT result. "
            "Ignore gibberish and focus on clear, natural language, or valid JSON/XML. "
            "Respond in a concise, structured markdown format, including the source encoding if found, the plaintext, and a brief justification."
        )

    full_prompt = f"{prompt}\n\n--- Input Data ---\n{input_data}"
    
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=full_prompt
        )
        return response.text
    
    except GeminiAPIError as e:
        return f"🚨 GEMINI API ERROR: Check your API Key, network connection, or usage limits. Error details: {e}"
    except Exception as e:
        return f"🚨 UNEXPECTED ERROR during AI process: {e}"

if __name__ == "__main__":
    print(r"""
                                                                                
@@@@@@@   @@@@@@@@  @@@@@@@@  @@@@@@@   @@@@@@@   @@@@@@@@   @@@@@@   @@@@@@@   
@@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  
@@!  @@@  @@!       @@!       @@!  @@@  @@!  @@@  @@!       @@!  @@@  @@!  @@@  
!@!  @!@  !@!       !@!       !@!  @!@  !@!  @!@  !@!       !@!  @!@  !@!  @!@  
@!@  !@!  @!!!:!    @!!!:!    @!@@!@!   @!@!!@!   @!!!:!    @!@!@!@!  @!@  !@!  
!@!  !!!  !!!!!:    !!!!!:    !!@!!!    !!@!@!    !!!!!:    !!!@!!!!  !@!  !!!  
!!:  !!!  !!:       !!:       !!:       !!: :!!   !!:       !!:  !!!  !!:  !!!  
:!:  !:!  :!:       :!:       :!:       :!:  !:!  :!:       :!:  !:!  :!:  !:!  
 :::: ::   :: ::::   :: ::::   ::       ::   :::   :: ::::  ::   :::   :::: ::  
:: :  :   : :: ::   : :: ::    :         :   : :  : :: ::    :   : :  :: :  :   
                                                                                

   DEEPREAD: The Infinite Decoder          VERSION 4.0 (by Azazi)
    """)
    main()