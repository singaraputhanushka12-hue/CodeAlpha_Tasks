# 🔒 Secure Coding Review

## 📌 Project Overview

This project demonstrates a **secure coding review** by analyzing a deliberately vulnerable Flask-based user management application. It highlights common security flaws and explains how they can be identified and mitigated.

> **Note:** This application is intentionally insecure and is designed **only for educational purposes**. Do not deploy it in a production environment.

---

## 🎯 Objectives

- Identify common web application vulnerabilities
- Understand secure coding practices
- Learn how insecure code can be exploited
- Recommend mitigation techniques

---

## 🚨 Vulnerabilities Identified

- SQL Injection
- Cross-Site Scripting (XSS)
- OS Command Injection
- Path Traversal
- Hardcoded Secret Key
- Hardcoded Credentials
- Weak Password Hashing (MD5)
- Broken Access Control
- Verbose Error Disclosure
- Debug Mode Enabled

---

## 🛠 Technologies Used

- Python 3
- Flask
- SQLite

---

## 📂 Project Structure

```
Secure_Coding_Review/
│── images/
│── secure_coding_review.py
│── README.md
│── requirements.txt
```

---

## 📥 Installation

Install the required dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Run the Application

```bash
python secure_coding_review.py
```

The application starts on:

```
http://127.0.0.1:5000
```

---

## 📸 Screenshots

Save screenshots inside the `images` folder.

Example:

```
images/output.png
```

Display them in the README like this:

```markdown
![Output](images/output.png)
```

---

## ⚠ Disclaimer

This application intentionally contains security vulnerabilities for learning and demonstration purposes only. It should **never** be deployed to a production environment.

---

## 👨‍💻 Author

**Singarapu Thanushka**