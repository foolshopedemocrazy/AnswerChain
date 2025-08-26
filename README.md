# AnswerChain
Restore your secret by answering security question
<img width="1024" height="1536" alt="b9de21d5-0163-45e5-ad1d-cbdbbdae5295" src="https://github.com/user-attachments/assets/821efd23-6c3e-42b8-ba97-06efbcca1b1c" />


About Bitwarden

An offline, passwordless recovery system where users create their own security questions and answer alternatives to restore secrets securely


█████████████████████████████████████████████████████████████████████████████
## 🔑 How it works  

1. **User defines their own questions**  
   - You create your own security questions (e.g., *“What was my first pet’s name?”*) and provide multiple answer alternatives.  

2. **Every alternative is cryptographically protected**  
   - Each alternative is combined with a random salt and processed through **Argon2id** (a memory-hard key derivation function).  
   - The derived key is used to encrypt a **Shamir Secret Sharing (SSS)** share with **cascade encryption**:  
     - First layer: **AES-256-GCM**  
     - Second layer: **ChaCha20-Poly1305**  
   - This dual-layer (cascade) AEAD ensures ciphertexts all have the same structure and strengthens security against single-algorithm weaknesses that the future could present.  

3. **Wrong answers look valid too**  
   - Incorrect answers are not left empty. Instead, they carry **dummy SSS shares**, also Argon2id-hardened and cascade-encrypted (AES-256-GCM + ChaCha20-Poly1305).  
   - This makes every answer indistinguishable, so attackers cannot know which ones are correct.  

4. **Decoy “real” answers**  
   - Users can define **decoy real answers** that decrypt into plausible but fake secrets.  
   - Even if an attacker manages to decrypt shares, they cannot tell whether the reconstructed output is the genuine secret or a decoy.  

5. **Secret recovery**  
   - During recovery, you answer your own questions. Each chosen alternative is re-processed with Argon2id and cascade decryption.  
   - If the correct set is chosen, enough valid SSS shares are obtained to recombine and reconstruct the secret.  

6. **Final authentication**  
   - The reconstructed secret undergoes a final **Argon2id + HMAC check**.  
   - Only if this verification succeeds is the secret accepted as authentic.  

                                   **ABOUT BITWARDEN**
