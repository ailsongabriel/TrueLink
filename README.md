# 🔗 TrueLink

## 📖 About
TrueLink is a command-line tool designed to analyze the security of shortened URLs. It expands shortened links, retrieves the original URL, and scans it using the VirusTotal API to detect potential threats.

## 🚀 Features
- Expands shortened URLs to reveal the original link.
- Analyzes the URL using the VirusTotal API.
- Displays security analysis statistics.
- (Optional) Shows detailed results from each antivirus engine.

## 📌 Prerequisites
- Python 3.7+
- A [VirusTotal](https://www.virustotal.com/) API key.
- `requests` library installed.

## 📥 Installation
Clone the repository and install dependencies:

```sh
# Clone the repository
git clone https://github.com/ailsongabriel/TrueLink.git
cd truelink

# Install required dependencies
pip install -r requirements.txt
```

## ⚙️ Usage
### 🔹 Basic Usage
To analyze a shortened URL, run:
```sh
python truelink.py <SHORTENED_URL> --api-key-path api_key.txt
```

### 🔹 Arguments
| Parameter            | Description                                           |
|----------------------|-------------------------------------------------------|
| `<SHORTENED_URL>`    | The shortened URL to analyze.                         |
| `--api-key-path`     | Path to the file containing the VirusTotal API key.   |
| `--show-engines`     | (Optional) Show results from individual security engines. |

### 🔹 Example Usage
Analyze a shortened URL:
```sh
python truelink.py https://bit.ly/example --api-key-path api_key.txt
```

Show detailed antivirus engine results:
```sh
python truelink.py https://bit.ly/example --api-key-path api_key.txt --show-engines
```

## 🤝 Contribution
Feel free to open issues and submit pull requests to improve TrueLink!

## 📝 License
This project is licensed under the MIT License. See the `LICENSE` file for more details.

---
Created by [Noslia](https://github.com/ailsongabriel).
