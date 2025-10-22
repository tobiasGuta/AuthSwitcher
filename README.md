### **Description**

**IDOR Hunter** is a Burp Suite extension designed to automate the detection of **Insecure Direct Object Reference (IDOR)** vulnerabilities by replaying captured requests with different authentication contexts.\
It captures a baseline request (e.g. from *User A*), then automatically duplicates it using cookies, tokens, or credentials from other configured profiles (e.g. *User B*).\
If the duplicate response exposes the same user-specific data (such as names, emails, or account IDs), the extension flags it as a potential IDOR.

It's basically a smart "Repeater + auth swapper" -> a lightweight automation layer to catch access control flaws that normal fuzzers miss.

* * * * *

### **Key features**

-   Auto-duplicates requests across multiple user sessions or credential sets.

-   Detects response similarities that indicate unauthorized access.

-   Marks and organizes possible IDORs directly inside Burp.

-   Side-by-side diff view for manual confirmation.

-   Compatible with cookie-based, token-based, and header-based auth.
