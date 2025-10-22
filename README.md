### **Description**

**IDOR Hunter** is a Burp Suite extension designed to automate the detection of **Insecure Direct Object Reference (IDOR)** vulnerabilities by replaying captured requests with different authentication contexts.\
It captures a baseline request (e.g. from *User A*) alice example: /profile/1 = alice profile, then automatically duplicates it using cookies, tokens, or credentials from other configured profiles (e.g. *User B*) bob.\
If the duplicate response exposes the same user-specific data (such as names, emails, or account IDs), the extension flags it as a potential IDOR.

It's basically a smart "Repeater + auth swapper" -> a lightweight automation layer to catch access control flaws that normal fuzzers miss.

* * * * *

### **Key features**

-   Auto-duplicates requests across multiple user sessions or credential sets.

-   Detects response similarities that indicate unauthorized access.

-   Marks and organizes possible IDORs directly inside Burp.

-   Side-by-side diff view for manual confirmation.

-   Compatible with cookie-based, token-based, and header-based auth.

# Example

## Request:

<img width="1916" height="972" alt="image" src="https://github.com/user-attachments/assets/7145d0e5-0b85-40d9-885c-09d64a158b0a" />

## Response:

<img width="1919" height="971" alt="image" src="https://github.com/user-attachments/assets/4d669b8f-3f0c-4b16-bbfd-cba1846fb424" />


## Comparer

<img width="1916" height="158" alt="image" src="https://github.com/user-attachments/assets/bfc617fb-83da-4e63-ae1f-8f720035c747" />

## Maches:

<img width="1916" height="478" alt="image" src="https://github.com/user-attachments/assets/ecfc052c-34fe-49da-8386-c65f29a0358d" />


# Support
If my tool helped you land a bug bounty, consider buying me a coffee ☕️ as a small thank-you! Everything I build is free, but a little support helps me keep improving and creating more cool stuff ❤️
---

<div align="center">
  <h3>☕ Support My Journey</h3>
</div>


<div align="center">
  <a href="https://www.buymeacoffee.com/tobiasguta">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" width="200" />
  </a>
</div>

---

