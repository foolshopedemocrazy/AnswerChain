
<img width="663" height="106" alt="aaaaaa" src="https://github.com/user-attachments/assets/fa509142-9bc1-4507-bfa7-fe9136b3c40e" />

▶▶ Restore your secret by answering security question ◀◀

![this](https://github.com/user-attachments/assets/d63faf2e-f282-4743-a3a9-3637ed37883f)



 # About AnswerChain
AnswerChain provides an offline, passwordless recovery system that empowers individuals and organizations to restore secrets securely. By allowing users to create their own knowledge-based questions and answer options, secrets can be rebuilt without relying on passwords—protected by modern cryptography to ensure safety and trust.



&nbsp;  
&nbsp;  
&nbsp;







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


&nbsp;  
&nbsp;  
&nbsp;




# 🔒 Why the Security Questions File is Secure  

---

## 1. Key Derivation  
Every answer is combined with a random salt and processed through **Argon2id**  
with enforced high memory cost (≥1 GiB, parallelism pinned to 1).  
This makes brute-force attacks prohibitively expensive,  
even for attackers using modern GPUs or ASICs.  

---

## 2. Cascade Encryption  
Each derived key is used in **cascade encryption**, first with **AES-256-GCM**  
and then with **ChaCha20-Poly1305**.  
This guarantees ciphertexts are uniform in structure and provides long-term resilience:  
even if one cipher is broken in the future, the other still protects the data.  

---

## 3. Secret Splitting (SSS)  
The protected secret is never stored directly but split into shares using  
**Shamir’s Secret Sharing (SSS)**.  
A defined threshold of correct answers must be provided to recombine the secret,  
while any subset below the threshold reveals absolutely nothing.  

---

## 4. Standard vs. Critical Questions  
Questions can be **standard** or **critical**.  
- Standard questions → contribute shares toward the threshold.  
- Critical questions → must always be answered correctly.  

Secret restoration is **impossible** if even one critical question is wrong,  
regardless of how many standard answers are correct.  

---

## 5. Wrong Answers and Decoys  
Wrong answers are indistinguishable from correct ones because they also decrypt into  
**dummy shares** hardened with Argon2id and cascade AEAD.  

Users can also configure **decoy real answers**, which produce plausible but fake secrets.  
These protections ensure attackers can never know whether a recovered result is genuine or a decoy.  

---

## 6. Final Verification  
Once enough shares are collected, the reconstructed secret must pass a  
**final Argon2id + HMAC verification step**.  
This prevents tampering and guarantees that only the genuine secret is accepted.  

---

## 7. Offline and Passwordless  
The entire system is **offline and passwordless**, eliminating risks associated with  
servers, cloud storage, or a single vulnerable master password.  
Everything needed for recovery is self-contained.  

---

## 8. Leak Resilience  
The system is deliberately designed to remain secure **even if the complete file,  
all ciphertexts, salts, and parameters leak online**.  

Attackers gain no useful advantage because:  
- Argon2id makes brute-force infeasible.  
- Cascade AEAD ensures dual-layer protection.  
- Dummy shares and decoys make answers indistinguishable.  
- Shamir’s Secret Sharing prevents partial leakage.  
- Critical questions block recovery without mandatory checkpoints.  
- The HMAC gate validates authenticity.  

---

## 9. Brute-Force Cost Analysis  
After setup, the program presents a **brute-force cost analysis**,  
showing the estimated difficulty of cracking the configuration with modern hardware.  

Users can then adjust Argon2id parameters, thresholds, or question sets  
if they want even stronger security.  

## 10. Uses trusted encryption libraries

🔒 Cryptography Library Audits

## [pyca/cryptography](https://github.com/pyca/cryptography)
- **Software audit:** ❓ Unclear  
- **Algorithm audit:** ✅ Yes  

---

## [argon2-cffi](https://github.com/hynek/argon2-cffi)
- **Software audit:** ❓ Unclear (but trusted). Based on [PHC winner Argon2](https://github.com/P-H-C/phc-winner-argon2), which **has been audited**.  
- **Algorithm audit:** ✅ Yes  

---

## [Shamir Secret Sharing (privy-io)](https://github.com/privy-io/shamir-secret-sharing)
- **Software audit:** ✅ Yes (audited twice)  
- **Algorithm audit:** ✅ Yes  



---


Even in a **total leak scenario**, the true secret remains secure  
without the exact knowledge answers.  








&nbsp;  
&nbsp;  
&nbsp;






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





&nbsp;  
&nbsp;  
&nbsp;



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

<details>
  <summary># 🔒 Privacy Protection via Tolerance-Based Authentication for the security questions</summary>

# 🔒 Privacy Protection via Tolerance-Based Authentication for the security questions

### Example Feature Idea
**Privacy protection of security questions using tolerance-based authentication.**

- All masked answers combine into a single unlock key → hiding both personal data *and* the questions.  
- With **tolerance-based authentication**, small typos are accepted (e.g., `bakke` → `backe`, `bakie`), balancing **usability and security**.  
- Redundancy across multiple questions provides **resilience and accessibility**.  

---

## 🧪 Masked-PII Practice Prompts (Synthetic Identity)

> ⚠️ *All data below is entirely fabricated, for demonstration only.*

**Persona**  
- Name: *Jonathan "Jono" Carver*  
- Birth date: `1992-07-14`  
- Phone: `+44 7701 234567`  
- Email: `jon.carver92@example.com`  
- Passport: `UKR1234567`  
- Student ID: `AB34927`  
- Card: `4539 4512 0398 4312`  
- Forum: `dark_raven92`  
- Licence: `B, BE`  

---

### A. Names & Aliases
- First name with vowels hidden → `J*n*th*n`  
- Forum handle (digits removed, consonants only) → `drkrvn`  

### B. Dates & Time
- Birth date (YYYY-MM) → `1992-07`  
- Day of month mod 10 (14 → 4) → `4`  

### C. Location
- Postal prefix → `SW1`  
- Country code → `GB`  

### D. Contact
- Masked email → `jon…@example.com`  
- Masked phone → `…4567`  

### E. Government / Institutional
- Passport last 3 → `…567`  
- Student ID format → `^[A-Z]{2}\d{5}$`  

### F. Financial
- Card last 4 → `…4312`  
- IBAN masked (UK) → `GB…12`  

### G. Work / Academic
- Uni email with vowels hidden → `jn.c*rv*r92`  
- Publications bucket → `6–20`  

### H. Online Accounts & Devices
- GitHub consonants only (joncarver92) → `jncrvr`  
- Forum last login → `07/25`  

### I. Driving Licence
- Categories → `B, BE`  
- First issue year → `2010`  

### J. Derived / Transformed
- SHA-256("Carver|salt42"), first 8 hex → `3a91f2b8`  
- CRC32(passport tail 34567) → `5D12A4BC`  

### K. Consistency & Linkage
- Phone tail + passport tail → `567-567`  
- Initials + birth year → `J.C.-92`  

### L. Security Question Style
- Mother’s maiden initial + father’s name last letter → `L,n`  
- Favourite colour "purple", letters 1 & 3 → `p-r`  

### M. Formats & Validation
- Regex for masked phone → `^\+44\s77\d{2}\s\d{6}$`  
- ISO country/currency → `GB-GBP`  

### N. Multiple Choice
- Least identifying DOB mask → `Year only (1992)`  
- Least identifying address mask → `Country only (GB)`  

---

✅ **End of Demo Set — clean, minimal, and privacy-preserving.**  

</details>
