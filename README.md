````markdown
# 🛡️ Shastra

**Shastra** is a powerful and flexible SQL Injection (SQLi) scanner and static analyzer built using [Playwright](https://playwright.dev/), with support for dynamic form fuzzing, header injection, parameter tampering, and optional static code analysis via Bandit.  


<img width="1396" height="973" alt="Screenshot 2025-07-31 095120" src="https://github.com/user-attachments/assets/231815e9-b02c-487c-852e-7198a0a22e9a" />

## ⚙️ Features

- 🔎 Dynamic SQL Injection detection using full browser emulation (Playwright)
- 🧪 Automatic fuzzing of:
  - Query parameters
  - Form inputs
  - HTTP headers
  - URL path
- 🐛 Optional static analysis using Bandit
- 🧰 Customizable payloads and error signature detection
- 🖥️ Debug mode to dump raw HTTP requests/responses
- 📦 JSON output for easy reporting or integration
- 🎨 Colorful terminal output with [Rich](https://github.com/Textualize/rich)

---

## 🛠 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/shastra.git
cd shastra
````

### 2. Install Python Requirements

```bash
pip install -r requirements.txt
```

### 3. Install Playwright Browsers

```bash
playwright install
```

---

## 🚀 Usage

### Scan a single URL

```bash
python shastra.py -u https://example.com/page.php?id=1
```

### Scan multiple URLs from a file

```bash
python shastra.py -l urls.txt
```

### Output results to JSON

```bash
python shastra.py -u https://example.com -o results.json
```

### Fuzz additional headers

```bash
python shastra.py -u https://target.com -H Referer -H X-Forwarded-For
```

### Increase concurrency and reduce delay

```bash
python shastra.py -l urls.txt --threads 5 --delay 0.5
```

### Show raw HTTP requests and responses (debug mode)

```bash
python shastra.py -u https://example.com --debug
```

---

## 🧪 Sample Output

```json
{
  "dynamic": [
    {
      "https://example.com/page.php?id=1": [
        [
          "https://example.com/page.php?id='",
          "param id",
          "'",
          ["error signature"]
        ]
      ]
    }
  ],
  "static": [
    {
      "filename": "somefile.py",
      "line_number": 23,
      "issue_text": "Possible SQL injection via string-based query construction",
      ...
    }
  ]
}
```

---

## ⚡ Advanced

### Customize Payloads

Edit the `SQL_PAYLOADS` list in `shastra.py`:

```python
SQL_PAYLOADS = ["'", "''", "--", "-- OR 1=1", "--1=1"]
```

### Customize Error Matchers

Edit the `ERROR_SIGNS` list:

```python
ERROR_SIGNS = ["sql syntax", "mysql", "ora-", "syntax error", "unclosed quotation"]
```

---

## 🔒 Disclaimer

**Shastra is intended for ethical and legal use only.**
Do not use it on websites or systems you do not own or have explicit permission to test. Unauthorized usage may be illegal.

---

## 🧑‍💻 Author

**Shastra** is developed by [mrgreyhat07](https://github.com/mrgreyhat07)
Contributions, ideas, and pull requests are welcome!

---

