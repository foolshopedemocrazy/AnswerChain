# AnswerChain
Restore your secret by answering security question
<img width="1024" height="1536" alt="b9de21d5-0163-45e5-ad1d-cbdbbdae5295" src="https://github.com/user-attachments/assets/821efd23-6c3e-42b8-ba97-06efbcca1b1c" />


# About AnswerChain
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




<p align="left">
    <a href="https://yourprojectsite.com" target="_blank">
        <img src="https://yourprojectsite.com/logo.png" alt="AnswerChain" />
    </a>
</p>

# About AnswerChain

<a href="https://yourprojectsite.com" target="_blank">AnswerChain</a> envisions a world where secrets are restored safely without passwords. We empower individuals and organizations with an **offline, passwordless recovery system** that rebuilds secrets through **knowledge-based questions** protected by modern cryptography.

#### Here, you can
<ul>
    <li>Review code + release info/feature development
    <li>Propose PRs
    <li>Fork AnswerChain
</ul>

For documentation and support, please visit [AnswerChain Docs](https://yourprojectsite.com/docs).

# About AnswerChain Repos

## AnswerChain Core

AnswerChain Core enables secure restoration of secrets through **user-defined security questions**. Each answer alternative is protected by:
<ul>
    <li><b>Argon2id</b> memory-hard key derivation</li>
    <li><b>Cascade AEAD encryption</b> with AES-256-GCM and ChaCha20-Poly1305</li>
    <li><b>Shamir’s Secret Sharing (SSS)</b> to split and recombine secrets</li>
    <li><b>Optional decoy answers</b> producing convincing but fake secrets</li>
</ul>

### Security-first principles
<ul>
    <li>Offline operation</li>
    <li>Passwordless recovery</li>
    <li>Argon2id + cascade encryption (AES + ChaCha)</li>
    <li>Shamir’s Secret Sharing for threshold-based recovery</li>
    <li>Indistinguishable decoy answers</li>
</ul>

#### Popular related repos
<ul>
    <li><a href="https://github.com/yourorg/answerchain-core">answerchain-core</a> – Core cryptographic engine (Argon2id, SSS, cascade AEAD)</li>
    <li><a href="https://github.com/yourorg/answerchain-ui">answerchain-ui</a> – User interface for writing questions, managing alternatives, and restoring secrets</li>
    <li><a href="https://github.com/yourorg/answerchain-cli">answerchain-cli</a> – Command-line toolkit for power users</li>
</ul>
Learn more about AnswerChain by reading the [AnswerChain Whitepaper](https://yourprojectsite.com/whitepaper).

## AnswerChain Kits

AnswerChain Kits enable packaging of encrypted question sets, share distributions, and recovery instructions for safe offline storage. With Kits, users can:
<ul>
    <li>Define custom security questions</li>
    <li>Protect each answer alternative with Argon2id + cascade AEAD</li>
    <li>Include decoy “real” answers to confuse attackers</li>
    <li>Distribute threshold-based recovery shares via SSS</li>
</ul>

#### Popular related repos
<ul>
    <li><a href="https://github.com/yourorg/answerchain-kit-tools">answerchain-kit-tools</a> – Tools for creating and verifying recovery kits</li>
    <li><a href="https://github.com/yourorg/answerchain-validator">answerchain-validator</a> – Independent validator to test kit integrity and security</li>
</ul>
Learn more by visiting the [AnswerChain Kit Documentation](https://yourprojectsite.com/docs/kits).

## AnswerChain Passwordless.dev

AnswerChain also integrates **passwordless principles** into recovery flows:
<ul>
    <li><b>Offline-first</b>: All operations run without internet connectivity</li>
    <li><b>Passwordless by design</b>: Knowledge-based answers replace static master passwords</li>
    <li><b>Indistinguishable answers</b>: Correct and wrong answers both decrypt into shares, but only the right threshold rebuilds the true secret</li>
</ul>

#### Popular related repos
<ul>
    <li><a href="https://github.com/yourorg/answerchain-passwordless-server">answerchain-passwordless-server</a> – Backend API for optional integrations</li>
    <li><a href="https://github.com/yourorg/answerchain-passwordless-example">answerchain-passwordless-example</a> – Example integrations for developers</li>
</ul>
Learn more by visiting the [Passwordless Recovery Documentation](https://yourprojectsite.com/docs/passwordless).
</p>

# We're Hiring!

Interested in contributing in a big way? Consider joining AnswerChain! We're hiring for many positions. Please take a look at the [Careers page](https://yourprojectsite.com/careers) to see what opportunities are currently open as well as what it's like to work with us.

# Contribute

Code contributions are welcome! Please commit any pull requests against the `main` branch. Learn more about how to contribute by reading the [Contributing Guidelines](https://yourprojectsite.com/contributing).  

Security audits and feedback are welcome. Please open an issue or email us privately if the report is sensitive in nature. You can read our security policy in the [`SECURITY.md`](/SECURITY.md) file.
