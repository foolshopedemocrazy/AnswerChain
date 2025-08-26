
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
- **Software audit:** ❓ Unclear  (but trusted)
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
























<details>
  <summary># 🔒 Server side Authentication</summary>

Features:

Automated Triggers:
If you fail to respond to a recurring prompt (e.g., an email sent at fixed intervals) within a specified time frame, a predefined action will be triggered. For example, a physical letter could be dispatched with instructions on how to proceed.

Server-Side Security:
The system can leverage server-side hardware (e.g., HSM modules) to enhance overall security and safeguard cryptographic processes.

Customizable User Conditions:
It can be programmed with detailed specifications, such as:

Denying authentication if you are under duress (e.g., held against your will).

Allowing decryption only at specific times or intervals.

Triggering auto-destruction of sensitive data if user-defined conditions are met.

Human and AI-Assisted Support:
Flexible integration of human support teams and/or AI-based assistance tailored to your specific use case.

Controlled Information Flow:
The system can hold encrypted questions or instructions and release them only after successful authentication. You decide exactly what information is stored server-side.

Contingency Features:
Optional safeguards include contacting trusted relatives or designated parties if you fail to respond within set time limits.





  


</details>






<details>
  <summary># 🔒 Unified framework of human-centric authentication factors combining biometrics, cognition, perception, behavior, and psychometric patterns</summary>






---

## 1. Biometric Authentication (Physical & physiological)  
- Fingerprints (ridge patterns)  
- Facial recognition (geometry, landmarks)  
- Iris scans (iris texture)  
- Retina scans (blood vessel pattern)  
- Voice recognition (tone, cadence, pitch)  
- Gait analysis (walking style)  
- DNA snippet profiling (SNPs encoded to bits)  
- Multisensory biometrics (fingerprint + iris + face combo)  

---

## 2. Cognitive Authentication (Knowledge, recall, logic)  
- Classic security questions  
- Custom user-authored questions  
- Memory recall tasks (facts, personal info, shared knowledge)  
- Number sequence recall (max working memory length)  
- Word/phrase recall  
- Challenge-response puzzles (math, riddles, logic)  
- Logic games (short chess puzzles, sequence completion)  
- Pattern completion challenges  
- Story/narrative memory recall  

---

## 3. Perceptual / Vision-Based  
- Color perception tests (e.g., “the dress” illusion)  
- Visual illusions (duck/rabbit, vase/faces, young woman/old woman)  
- Ambiguous 3D illusions (Necker cube, spinning dancer)  
- Gestalt grouping (continuity, similarity, proximity)  
- Pattern recognition tasks (shapes, geometry)  
- Hotspot clicks in busy images  
- Multi-object recognition in clutter  

---

## 4. Multi-Stable Perception Tests  
- Ambiguous image interpretation (Rubin’s vase, duck/rabbit)  
- Bistable motion illusions (spinning dancer clockwise/counterclockwise)  
- Multi-interpretation figure perception (e.g., young woman vs old woman)  

---

## 5. Graphical & Spatial Memory  
- PassPoints (click-points on image)  
- Grid sketch (Draw-A-Secret)  
- Pattern locks (Android-style)  
- Spatial sequence recall (navigating nodes or map)  

---

## 6. Sequences & Timing  
- Number sequence repetition  
- Word sequence repetition  
- Rhythm passwords (tap/knock patterns)  
- Morse-like cadence (short/long tap codes)  
- N-back recall challenges  
- Reaction time-based sequences  

---

## 7. Keyboard Behavior  
- Typing speed (chars/sec)  
- Keystroke dynamics (hold & gap times)  
- Misspelling/error patterns  
- Correction habits (backspace, delete, autocorrect)  
- Preferred words/phrases typing rhythm  
- Consistent keyboard quirks (capslock use, shift preference)  

---

## 8. Mouse, Touch, Motion  
- Mouse/trackpad signature curves  
- Cursor velocity, jitter, navigation habits  
- Touch gestures (swipes, pressure, angle, acceleration)  
- Phone IMU gestures (figure-8, tilt, shake)  
- Device unlocking style (swipe vs tap patterns)  

---

## 9. Semantic & Association Tasks  
- Ranking tasks (colors, shapes, preferences)  
- Odd-one-out triads (select odd from group)  
- Story path choices (consistent narrative choices)  
- Preference-based questions (favorite activity, season, movie, food, etc.)  

---

## 10. Psychometric & Emotional Responses  
- Personality test responses (Big Five style)  
- Reaction speed/accuracy to cues  
- Empathy reactions (images, phrases)  
- Emotional scaling (rate feelings 1–10 when X happens)  
- Cringe/dislike responses  
- Distractor tests (what distracts you most)  
- Mistake type profiling (errors you repeat)  
- Preferred hand for tasks  
- Comfort with surveillance/authority  
- Information disclosure vs withholding  

---

## 11. Task-Based Authentication  
- Handwriting samples  
- Reading speed tests  
- Eating & describing food taste (tomato, strong flavor, scale 1–10)  
- Describing sensory perception (smell, touch, texture)  
- Maximum sequence recall test (avg length across attempts)  
- Motor task performance (draw, trace, tap path)  

---

## 12. Temporal Patterns  
- Circadian rhythm & chronotype (morning/night person)  
- Time perception under different conditions  
- Routine adherence vs variability  
- Anticipation vs reflection behavior  
- Response to time pressure / waiting  

---

## 13. Motivational Drivers  
- Risk vs reward orientation  
- Intrinsic vs extrinsic motivators  
- Goal initiation vs follow-through style  
- Response to incentives  
- Habit formation tendencies  

---

## 14. Social Cognition & Relational Style  
- Empathy processing style  
- Affiliation vs autonomy preference  
- Conflict response (avoid, confront, adapt)  
- Theory of mind ability (inferring others’ perspectives)  
- Preference for group vs one-on-one settings  

---

## 15. Privacy & Control Dynamics  
- Comfort with disclosure vs secrecy  
- Desire for observation or anonymity  
- Tolerance for monitoring/surveillance  
- Reaction to regulation or authority  

---

## 16. Moral / Ethical Orientation  
- Deontological vs utilitarian tendencies  
- Justice vs mercy preference  
- Sensitivity to hypocrisy  
- Moral licensing patterns  
- Individual vs collective responsibility view  

---

## 17. Biological / Physiological Rhythms  
- Stress response type (fight/flight, cortisol pattern)  
- Sleep quality, REM density  
- Nutritional responsiveness  
- Sensitivity to sensory stimuli (light, sound, temperature)  
- Hormonal/metabolic baseline variation  

---

## 18. Creative Expression Profile  
- Symbolic vs narrative creativity  
- Structured vs improvisational style  
- Preferred medium (tactile, digital, verbal, visual)  
- Creative risk-taking vs repetition  
- Peak creative time periods  

---

## 19. Consistency vs Variability Preference  
- Routine adherence vs novelty seeking  
- Tolerance for unpredictability  
- Environmental adaptability  
- Attention to variance in others  
- Pattern-breaking behaviors  

---

## 20. Problem-Solving & Strategy Style  
- Trial-and-error vs plan-first  
- Big-picture vs detail-oriented focus  
- Logic-driven vs intuitive inference  
- Persistence vs pivot on failure  
- Strategic vs impulsive problem solving  

---

 

</details>























































