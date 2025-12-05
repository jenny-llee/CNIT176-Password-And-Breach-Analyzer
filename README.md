# CNIT176-Password-Strength-Analyzer-And-Breach-Checker-

My objective was to create a C++ command-line tool that analyzes the strength of **test passwords** and checks whether they appear in public data breaches. The program runs on a Raspberry Pi (or any Linux system with C++17, OpenSSL, and libcurl), scores each password based on length and character variety, looks for weak patterns (like password, 1234, keyboard walks, and years), and then uses a privacy-preserving SHA-1 prefix query to the Pwned Passwords API. It prints a clear report with a rating, numeric score, reasons, and suggestions so I can see how different test passwords behave. This tool is for testing and learning only — never for real passwords.

When I run, for example:

./pw_checker "Password123"

the tool calls analyze_password to measure the password’s length, count how many character types it uses (lowercase, uppercase, digits, symbols), and compute a numeric score. It then assigns a rating from Weak, Fair, Good, to Strong and prints the rating, score, length, and character variety, along with breach information.

During the same run, the analyzer checks for common weak patterns inside the password. It flags:
- common words like password, letmein, qwerty, or iloveyou
- repeated characters such as aaa
- digit sequences like 1234 or 4321
- keyboard walks along QWERTY rows
- years between 1990 and 2030

Each issue becomes a human-readable entry under the reasons, and matching tips (like “Use 14+ characters” or “Avoid years or dates”) are added under the suggestions so users know exactly how to improve the test password.

At the same time, the breach module (pwned_count) hashes the test password locally in C++ using OpenSSL’s SHA-1 implementation. It converts the digest to a 40-character uppercase hex string, splits it into a 5-character prefix and a 35-character suffix, and sends only the prefix to [https://api.pwnedpasswords.com/range/](https://haveibeenpwned.com/Passwords)<prefix> using libcurl. It then searches the returned suffix list on my machine. If it finds a match, it reports that the password was found in breaches and shows the number of times that hash has appeared; if the network request fails, the program catches the exception and still shows the local strength analysis.

To make the tool easier to use, I added a shell alias called pwcheck in my .bashrc that points to the compiled binary. After reloading the shell configuration, I can type commands like: (pwcheck "Password123") from any directory instead of having to type the full path to pw_checker.
