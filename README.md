
<img width="663" height="106" alt="aaaaaa" src="https://github.com/user-attachments/assets/fa509142-9bc1-4507-bfa7-fe9136b3c40e" />


# AnswerChain
Restore your secret by answering security question

![this](https://github.com/user-attachments/assets/d63faf2e-f282-4743-a3a9-3637ed37883f)



# About AnswerChain
AnswerChain provides an offline, passwordless recovery system that empowers individuals and organizations to restore secrets securely. By allowing users to create their own knowledge-based questions and answer options, secrets can be rebuilt without relying on passwords—protected by modern cryptography to ensure safety and trust.

## ❓ How it works  

1️⃣. **User defines their own questions**  
   - You create your own security questions (e.g., *“What was my first pet’s name?”*) and provide multiple answer alternatives.  

2️⃣. **Every alternative is cryptographically protected**  
   - Each alternative is combined with a random salt and processed through **Argon2id** (a memory-hard key derivation function).  
   - The derived key is used to encrypt a **Shamir Secret Sharing (SSS)** share with **cascade encryption**:  
     - First layer: **AES-256-GCM**  
     - Second layer: **ChaCha20-Poly1305**  
   - This dual-layer (cascade) AEAD ensures ciphertexts all have the same structure and strengthens security against single-algorithm weaknesses that the future could present.  

3️⃣. **Wrong answers look valid too**  
   - Incorrect answers are not left empty. Instead, they carry **dummy SSS shares**, also Argon2id-hardened and cascade-encrypted (AES-256-GCM + ChaCha20-Poly1305).  
   - This makes every answer indistinguishable, so attackers cannot know which ones are correct.  

4️⃣. **Decoy “real” answers**  
   - Users can define **decoy real answers** that decrypt into plausible but fake secrets.  
   - Even if an attacker manages to decrypt shares, they cannot tell whether the reconstructed output is the genuine secret or a decoy.  

5️⃣. **Secret recovery**  
   - During recovery, you answer your own questions. Each chosen alternative is re-processed with Argon2id and cascade decryption.  
   - If the correct set is chosen, enough valid SSS shares are obtained to recombine and reconstruct the secret.  

6️⃣. **Final authentication**  
   - The reconstructed secret undergoes a final **Argon2id + HMAC check**.  
   - Only if this verification succeeds is the secret accepted as authentic.  




<p align="left">
    <a href="https://yourprojectsite.com" target="_blank">
        <img src="https://yourprojectsite.com/logo.png" alt="AnswerChain" />
    </a>
</p>


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


