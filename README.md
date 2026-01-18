# DeepRead
Since you are a Master's student in Cybersecurity and have been actively focusing on Cyber Threat Intelligence, this README is designed to highlight the technical sophistication and forensic utility of **DeepRead V4.0**.

                                                                                
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
                                                                                


---

# 📖 DEEPREAD: The Infinite Decoder (V4.0)

**DeepRead** is an ultimate universal encoding detector and decoder designed for security researchers, CTF players, and forensic analysts. It automates the identification and decryption of over 50+ encoding methods, ranging from standard Base encodings to complex classical ciphers and esoteric programming languages.

## 🚀 Key Features

* **Multi-Layered Decoding (`-m`):** Automatically detects and unwinds nested encodings (e.g., Hex → Base64 → Plaintext) up to 5 layers deep.
* **AI-Powered Analysis (`-g`):** Integrates with Gemini AI to perform plausibility checks, filtering gibberish to find the most likely plaintext.
* **Massive Library:** Supports 50+ methods including:
* **Bases:** Base16, 32, 45, 58, 64, 85, 91, 92.
* **Ciphers:** Caesar, Vigenere, Atbash, Affine, Rail Fence, Columnar Transposition.
* **Forensics:** UUID metadata extraction (Version/Timestamp/MAC), Hash identification (MD5, SHA1/256/512).
* **Esoteric:** Brainfuck, Ook!, Malbolge.


* **Recursive JSON Decoding:** Processes entire JSON files and decodes every string value found within the structure.

## 🛠️ Installation

1. **Clone the repository:**
```bash
git clone https://github.com/arazazi/DeepRead.git
cd DeepRead

```


2. **Install dependencies:**
```bash
pip install google-genai chardet

```


3. **Setup AI (Optional):**
To use the `--gemini` analysis, place your API key in a file named `.gemini_key` or set the `GEMINI_API_KEY` environment variable.

## 💻 Usage

### Basic String Analysis

```bash
python3 deepread.py -t "SGVsbG8gV29ybGQ=" -d

```

### Multi-Layer Decoding with AI Post-Processing

```bash
python3 deepread.py -t "NGU1NDU0NTQzZDMz" -m -g

```

### Forensic UUID Extraction

```bash
python3 deepread.py -u "550e8400-e29b-41d4-a716-446655440000"

```

### Recursive JSON File Decoding

```bash
python3 deepread.py -j data_dump.json

```

## 📊 Technical Specs

| Feature | Description |
| --- | --- |
| **Detection Engine** | Regex-based pattern matching combined with English frequency scoring. |
| **UUID Support** | Decodes Versions 1, 3, 4, 5, and 6, including MAC address and timestamp extraction. |
| **Hash Analysis** | Identifies specific Hashcat modes (e.g., Mode 0 for MD5, Mode 1700 for SHA512). |
| **Language** | Python 3.x |

## ⚖️ Disclaimer

This tool is intended for educational purposes, Capture The Flag (CTF) challenges, and authorized security audits. Always ensure you have permission before analyzing data.

---

**Author:** Azazi
**Focus:** Cybersecurity & Cyber Threat Intelligence

