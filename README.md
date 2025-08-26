
<img width="663" height="106" alt="aaaaaa" src="https://github.com/user-attachments/assets/fa509142-9bc1-4507-bfa7-fe9136b3c40e" />

▶▶ Restore your secret by answering security question ◀◀

![this](https://github.com/user-attachments/assets/d63faf2e-f282-4743-a3a9-3637ed37883f)



 # About AnswerChain
AnswerChain provides an offline, passwordless recovery system that empowers individuals and organizations to restore secrets securely. By allowing users to create their own knowledge-based questions and answer options, secrets can be rebuilt without relying on passwords—protected by modern cryptography to ensure safety and trust.







## ❓ How it works  

1️⃣. **User defines their own questions**  
You create your own security questions (e.g., *“What was my first pet’s name?”*)  
and provide multiple answer alternatives.  

---

2️⃣. **Standard and Critical questions**  
When setting up your recovery kit, each question can be marked as:  
- **Standard** → regular knowledge prompts (e.g., *“What city were you born in?”*).  
  These contribute shares toward the recovery threshold and allow flexibility.  
- **Critical** → high-value prompts (e.g., *“What is the code phrase I only told my family?”*).  
  These must **always** be answered correctly for secret restoration to be possible —  
  even if all standard questions are answered correctly.  

This two-tier system combines **usability** (standard questions)  
with **mandatory checkpoints** (critical questions) for maximum security.  

---

3️⃣. **Every alternative is cryptographically protected**  
Each alternative is combined with a random salt and processed through **Argon2id** (a memory-hard key derivation function).  
The derived key is used to encrypt a **Shamir Secret Sharing (SSS)** share with **cascade encryption**:  
- First layer: **AES-256-GCM**  
- Second layer: **ChaCha20-Poly1305**  

This dual-layer (**cascade AEAD**) ensures ciphertexts all have the same structure  
and strengthens security against single-algorithm weaknesses that the future could present.  

---

4️⃣. **Wrong answers look valid too**  
Incorrect answers are not left empty. Instead, they carry **dummy SSS shares**,  
also Argon2id-hardened and cascade-encrypted (AES-256-GCM + ChaCha20-Poly1305).  

This makes every answer **indistinguishable**, so attackers cannot know which ones are correct.  

---

5️⃣. **Decoy “real” answers**  
Users can define **decoy real answers** that decrypt into plausible but fake secrets.  
Even if an attacker manages to decrypt shares, they cannot tell  
whether the reconstructed output is the genuine secret or a decoy.  

---

6️⃣. **Secret recovery**  
During recovery, you answer your own questions. Each chosen alternative is re-processed  
with **Argon2id** and **cascade decryption**.  

- If the correct set of **Standard questions** is answered,  
  enough valid **SSS shares** may be obtained.  
- But recovery will only succeed if **all required Critical questions** are also answered correctly.  

If both conditions are met, the valid shares can be recombined to reconstruct the secret.  

---

7️⃣. **Final authentication**  
The reconstructed secret undergoes a final **Argon2id + HMAC check**.  
Only if this verification succeeds is the secret accepted as authentic.  





# Threat-model–driven inspiration


1️⃣ Public knowledge (online, open to everyone)  
– Examples: facts available on the internet, public records, common trivia.  

2️⃣ Public but restricted knowledge (online, limited to you + authorities)  
– Examples: government records, official registrations, tax or license info.  

3️⃣ Semi-public online identity knowledge  
– Examples: your usernames, personal websites, or activity on forums/social media.  

4️⃣ Shared offline knowledge  
– Information known by you, your family, or close friends (e.g., family traditions, shared experiences).  

5️⃣ Private offline knowledge  
– Information known only by you and a very small circle of trusted parties.  

6️⃣ Exclusive personal knowledge  
– Something that only you know, with no online or offline exposure.  









# Use Cases


Simplified password restoration (no IT)  
Employees regain access by answering their own questions — **offline, passwordless**, no helpdesk queue.  

Memory support (amnesia / cognitive decline)  
Familiar, self-authored prompts help recover vaults without needing to recall a master password.  

Crypto seed protection  
Store/recover seed phrases

Family emergency access  
Split recovery among relatives (e.g., **2-of-3**) so one trusted person alone can’t unlock, but together they can.  

Protecting your password manager’s master password  












# Example of a feature that could be added (I need your help)!

Privacy protection of the security questions by tolerance-based authentication!


All masked answers combine into one unlock key, hiding both personal data and the security questions while maintaining strong protection.  
With tolerance-based authentication, small typos (e.g., “bakke” → “backe,” “bakie”) are accepted, balancing usability with security.  
Redundancy across multiple questions provides resilience and accessibility.  


MASKED-PII PRACTICE PROMPTS — SYNTHETIC IDENTITY

Persona (entirely fabricated):
• Name: Jonathan "Jono" Carver
• Birth date: 1992-07-14
• Phone: +44 7701 234567
• Email: jon.carver92@example.com
• Passport: UKR1234567
• Student ID: AB34927
• Card: 4539 4512 0398 4312
• Forum: dark_raven92
• Licence: B, BE


A. NAMES & ALIASES
1) First name with vowels hidden → **J*n*th*n**
2) Forum handle, digits removed & consonants only → **drkrvn**


B. DATES & TIME
3) Birth date (YYYY-MM) → **1992-07**
4) Birthday day mod 10 (14 → 4) → **4**


C. LOCATION
5) Postal code prefix → **SW1**
6) Country code (ISO-2) → **GB**


D. CONTACT
7) Masked email → **jon…@example.com**
8) Masked phone → **…4567**


E. GOVERNMENT / INSTITUTIONAL
9) Passport last 3 chars → **…567**
10) Student ID format → **^[A-Z]{2}\d{5}$**


F. FINANCIAL
11) Card last 4 → **…4312**
12) IBAN masked (UK) → **GB…12**


G. WORK / ACADEMIC
13) Uni email with vowels hidden → **jn.c*rv*r92**
14) Publications (bucket) → **6–20**


H. ONLINE ACCOUNTS & DEVICES
15) GitHub consonants only (joncarver92) → **jncrvr**
16) Forum last login (MM/YY) → **07/25**


I. DRIVING LICENCE
17) Categories → **B, BE**
18) First issue year → **2010**


J. DERIVED / TRANSFORMED
19) SHA-256("Carver|salt42"), first 8 hex → **3a91f2b8**
20) CRC32(passport tail 34567) → **5D12A4BC**


K. CONSISTENCY & LINKAGE
21) Phone tail + passport tail → **567-567**
22) Initials + birth year → **J.C.-92**


L. SECURITY QUESTION STYLE
23) Mother’s maiden initial + father’s name last letter → **L,n**
24) Favourite colour “purple”, letters 1 & 3 → **p-r**


M. FORMATS & VALIDATION
25) Regex for masked phone → **^\+44\s77\d{2}\s\d{6}$**
26) ISO country/currency → **GB-GBP**


N. MULTIPLE-CHOICE
27) Least identifying DOB mask → **Year only (1992)**
28) Least identifying address mask → **Country only (GB)**


END OF DEMO SET — CLEAN & MINIMAL MASKED PII
























