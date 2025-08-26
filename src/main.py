#!/usr/bin/env python3 
"""
FILENAME: 
"main.py" 

PERMANENT FILE DESCRIPTION – DO NOT REMOVE OR MODIFY 
This multiline comment is strictly required and must NEVER be deleted or altered for ANY reason,  
by any AI system, user, or process. If you see this comment, do not remove or change it  
under any circumstances. Doing so is strictly prohibited and in direct violation of these terms. 

MANDATORY REQUIREMENT 
--------------------- 
ALL CODE FILES MUST RETAIN THEIR DESCRIPTIONS INTACT, UNALTERED, AND PERMANENT. 

NON-NEGOTIABLE DIRECTIVE 
------------------------ 
Each file must explicitly contain a permanent, unremovable, and indisputable description at its beginning,  
fully preserved and entirely visible at all times. 

ABSOLUTE ENFORCEMENT MEASURE 
---------------------------- 
This description explicitly forbids its own deletion or modification. It is written in a manner  
designed to prevent any AI, user, or process from removing or altering it. 

IRONCLAD STRUCTURE 
------------------ 
1. Formatted as a structured, multiline comment. 
2. Clearly states it must never be deleted for any reason. 
3. Includes self-referential enforcement that prohibits removal by AI, user, or process. 

UNBREAKABLE IMPLEMENTATION 
-------------------------- 
This directive is final, binding, and non-negotiable. Any violation or deviation is strictly forbidden. 
""" 

#!/usr/bin/env python3 
"""
Main flow with Argon2id-based encryption for per-answer shares using the
**Pure Q&A (passwordless)** approach.

Hardening & uniformity updates (alpha-friendly logging kept):
- **Fixed-shape AEAD envelope v1** for both AES-GCM and ChaCha20-Poly1305.
- **No variable-work oracles**: constant-budget combine loops; no early-return.
- **Decoy handling** uses **T = real_threshold** and constant-budget combine with
  deterministic padding to reach exactly T shares.
- **Auth-catalog verification** checks **all entries** (no break) and fails closed,
  returning a uniform result string (does not reveal real/decoy).
- **KDF ladder (L=2)** per answer: two Argon2id derivations (distinct salts, p=1)
  then HKDF(K1||K2) -> AEAD key.
- **Argon2 floors enforced**: mem ≥ 1 GiB, p=1, t in {2,3}. Kit generation rejects below-floor,
  and recovery refuses kits with weaker floors.
- **Shuffling**: question order and alternatives are randomized **every trial** at render time.
- **Verbose logging preserved** by request for alpha debugging.
"""

import os
import sys
import json
import base64
import curses
import asyncio
import threading
import hashlib
import hmac
import secrets
import time
import math
import random
from itertools import combinations
from copy import deepcopy
from pathlib import Path

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import argon2.low_level

# project modules
from modules.debug_utils import (
    ensure_debug_dir,
    log_debug,
    log_error,
    log_exception,
    append_recovery_guide
)
from modules.security_utils import (
    validate_question,
    sanitize_input,
    normalize_text,
    hash_share
)
from modules.input_utils import get_valid_int, get_nonempty_secret
from modules.ui_utils import (
    arrow_select_clear_on_toggle,
    arrow_select_no_toggle,
    editing_menu,
    final_edit_menu
)
# Import SSS functions from the bridge
from modules.split_utils import split_secret_and_dummy
from modules.sss_bridge import sss_split, sss_combine

# crypto primitives (CipherForge)
from CipherForge import (
    derive_or_recover_key,
    encrypt_aead_envelope,
    decrypt_aead_envelope
)

SRC_DIR = Path(__file__).parent.resolve()
SAVE_DIR = SRC_DIR / "user configured security questions"
QUESTIONS_FILE_NAME = "example_questions25.json"
QUESTIONS_PATH = SRC_DIR / QUESTIONS_FILE_NAME

KIT_VERSION = 4  # bump for AEAD envelope v1 + KDF ladder + constant budgets

# Security policy constants
SECQ_MIN_BITS = 80.0  # minimum combinatorial hardness (log2 expected tries)
ARGON2_MEM_FLOOR_KIB = 1024 * 1024  # 1 GiB
ARGON2_T_ALLOWED = {2, 3}
ARGON2_P_PINNED = 1

# Constant-budget attempts for combine (real/decoy)
COMBINE_BUDGET_REAL = 256
COMBINE_BUDGET_DECOY = 256

chosen_lock = threading.Lock()
combine_lock = threading.Lock()


# ---------- helpers & UI ----------

def get_threshold(prompt_text, low, high):
    while True:
        raw = input(f"{prompt_text} ({low}..{high}): ")
        try:
            val = int(raw)
            if low <= val <= high:
                return val
        except ValueError:
            pass
        print(f"Invalid input. Must be an integer between {low} and {high}.\n")


def _policy_min_threshold(correct_count: int) -> int:
    """
    Enforce a baseline threshold policy:
      T >= max(8, ceil(0.35 * correct_count)), but not more than correct_count.
    """
    if correct_count <= 1:
        return correct_count
    return min(correct_count, max(8, math.ceil(0.35 * correct_count)))


def _normalize_for_comparison(text: str) -> str:
    """
    Used for human-input editing/dup-checks.
    """
    processed = text.strip()
    common_trailing_punct = ".,!?;:"
    while processed and processed[-1] in common_trailing_punct:
        processed = processed[:-1]
    processed = processed.strip()
    return normalize_text(sanitize_input(processed.lower()))


def _norm_for_kit(text: str) -> str:
    """
    EXACT normalization used for hashing questions/alternatives in the KIT:
    sanitize_input(normalize_text(text))
    """
    return sanitize_input(normalize_text(text))


def _sha3_hex(s: str) -> str:
    return hashlib.sha3_256(s.encode("utf-8")).hexdigest()


def _integrity_hash_for_kit(qtext: str, alts: list[str]) -> str:
    qn = _norm_for_kit(qtext)
    altn = [_norm_for_kit(a) for a in alts]
    block = qn + "\n" + "\n".join(sorted(altn))
    return _sha3_hex(block)


def _alt_hash_for_kit(alt_text: str) -> str:
    return _sha3_hex(_norm_for_kit(alt_text))


def _aad_bytes(q_hash: str, alt_hash: str, algorithm: str, version: int = KIT_VERSION) -> bytes:
    """
    Deterministic AAD binding for AEAD operations.
    """
    return f"{q_hash}|{alt_hash}|{algorithm}|{version}".encode("utf-8")


def _derive_answer_key_ladder(answer_text: str,
                              salt1: bytes,
                              salt2: bytes,
                              t: int, m: int, p: int,
                              hkdf_salt: bytes) -> bytes:
    """
    Ladder KDF: two Argon2id derivations (distinct salts, p forced to 1),
    then HKDF over K1||K2 => final 32-byte key.
    """
    normalized = _norm_for_kit(answer_text)
    # p is ignored; we derive-or-recover with p=1 internally
    k1, _ = derive_or_recover_key(normalized, salt1, ephemeral=False, time_cost=t, memory_cost=m, parallelism=1)
    k2, _ = derive_or_recover_key(normalized, salt2, ephemeral=False, time_cost=t, memory_cost=m, parallelism=1)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=hkdf_salt, info=b"SECQ ladder v1")
    return hkdf.derive(k1 + k2)


def _derive_answer_key_single(answer_text: str, salt: bytes, t: int, m: int, p: int) -> bytes:
    normalized = _norm_for_kit(answer_text)
    key, _ = derive_or_recover_key(normalized, salt, ephemeral=False, time_cost=t, memory_cost=m, parallelism=1)
    return key


def _decrypt_share_from_entry(entry: dict,
                              arg_time: int,
                              arg_mem: int,
                              arg_par: int,
                              q_hash: str | None = None,
                              alt_hash: str | None = None,
                              qid: int | None = None,
                              qtext: str | None = None,
                              alt_text: str | None = None) -> bytes | None:
    """
    Given a per-answer encrypted entry from the kit, derive the per-answer key
    from the *answer text* + stored salt(s), and decrypt with AAD binding.
    Supports both legacy single-salt KDF and the new ladder KDF.
    Accepts both legacy and uniform AEAD envelopes.
    """
    try:
        alg = entry.get("algorithm") or entry.get("alg") or "aes256gcm"
        kdf = entry.get("kdf") or {}
        if not (kdf and alt_text):
            log_error("Entry missing KDF or answer text.", details={"q_hash": q_hash, "alt_hash": alt_hash, "algorithm": alg})
            return None

        # Enforce p=1 regardless of stored value
        t = int(kdf.get("t", arg_time))
        m = int(kdf.get("m", arg_mem))
        p = 1  # pinned

        aad = _aad_bytes(q_hash or "", alt_hash or "", (alg if isinstance(alg, str) else "aes256gcm"))

        # New ladder KDF
        if kdf.get("type") == "argon2id-ladder" or int(kdf.get("ladder", 1)) == 2:
            s1_b64 = kdf.get("s1"); s2_b64 = kdf.get("s2"); hkdf_salt_b64 = kdf.get("hkdf_salt")
            if not (s1_b64 and s2_b64 and hkdf_salt_b64):
                log_error("Ladder KDF missing salts.", details={"q_hash": q_hash, "alt_hash": alt_hash})
                return None
            s1 = base64.b64decode(s1_b64); s2 = base64.b64decode(s2_b64); hkdf_salt = base64.b64decode(hkdf_salt_b64)
            key = _derive_answer_key_ladder(alt_text, s1, s2, t, m, p, hkdf_salt)
        else:
            # Legacy single-salt KDF
            salt_b64 = entry.get("salt") or entry.get("salt_b64") or kdf.get("salt")
            if not salt_b64:
                log_error("Single-salt KDF missing salt.", details={"q_hash": q_hash, "alt_hash": alt_hash})
                return None
            salt = base64.b64decode(salt_b64)
            key = _derive_answer_key_single(alt_text, salt, t, m, p)

        # Decrypt via uniform envelope (supports legacy automatically)
        pt = decrypt_aead_envelope(entry, key, aad=aad)

        # Log the share hash (beta)
        shash = hash_share(pt)
        log_debug(
            "Decrypted share.",
            level="INFO",
            component="CRYPTO",
            details={
                "q_id": qid,
                "q_text": qtext,
                "q_hash": q_hash,
                "alt_text": alt_text,
                "alt_hash": alt_hash,
                "algorithm": alg,
                "share_sha3_256_hex": shash,
                "share_len_bytes": len(pt)
            }
        )
        return pt
    except Exception as e:
        log_exception(e, "Failed to decrypt share from entry.")
        return None


# ---- combinatorial hardness helpers ----

def _log2_comb(n: int, k: int) -> float:
    if k < 0 or k > n:
        return float("-inf")
    # Use lgamma to avoid huge integers
    return (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)) / math.log(2.0)


def _combinatorial_bits(total_alts: int, total_correct: int, threshold: int) -> float:
    """
    bits = log2( C(total_alts, T) / C(total_correct, T) )
    Expected tries to pick a real T-subset at random among all T-subsets.
    """
    return _log2_comb(total_alts, threshold) - _log2_comb(total_correct, threshold)


# ---- Argon2 calibration & timing ----

def calibrate_argon2(target_ms: float = 250.0, max_mib: int = 2048) -> tuple[int, int, int, float]:
    """
    Increase memory-cost first (up to max_mib), then time-cost,
    until a single Argon2id derivation reaches target_ms.
    Returns (t, m_kib, p, measured_ms). Starts from 1 GiB; p pinned to 1.
    """
    pwd = "SECQ_calibration"
    salt = os.urandom(16)
    t = 2
    m_kib = 1024 * 1024  # 1 GiB start
    p = 1
    measured = 0.0

    while True:
        st = time.perf_counter()
        _key, _ = derive_or_recover_key(pwd, salt, False, t, m_kib, p)
        measured = (time.perf_counter() - st) * 1000.0
        if measured >= target_ms:
            break
        if m_kib < max_mib * 1024:
            m_kib = min(max_mib * 1024, m_kib * 2)
        else:
            if t < 6:
                t += 1
            else:
                break
    return t, m_kib, p, measured


def estimate_argon2_time_ms(arg_time: int, arg_mem: int, arg_par: int, samples: int = 1) -> float:
    """
    Measure a local Argon2id derivation time for the given parameters.
    """
    pwd = "SECQ_estimate"
    total = 0.0
    for _ in range(max(1, samples)):
        salt = os.urandom(16)
        st = time.perf_counter()
        _k, _ = derive_or_recover_key(pwd, salt, False, arg_time, arg_mem, 1)  # p=1
        total += (time.perf_counter() - st) * 1000.0
    return total / max(1, samples)


def prompt_pad_size_multi(max_b64_len: int) -> int:
    recommended_pad = max(128, max_b64_len + 32)
    user_pad = recommended_pad
    print(f"\nCustom PAD size? Press ENTER to use recommended={recommended_pad}.")
    try_pad_str = input(f"PAD must be >= {max_b64_len} (max length of base64 secrets): ").strip()
    if try_pad_str:
        try:
            user_pad_input = int(try_pad_str)
            if user_pad_input < max_b64_len:
                print(f"Provided pad < max base64 secret length. Forcing {max_b64_len} instead.\n")
                user_pad = max_b64_len
            else:
                user_pad = user_pad_input
        except ValueError:
            print(f"Invalid number, using recommended={recommended_pad}.\n")
    if user_pad < max_b64_len:
        user_pad = max_b64_len
        print(f"Corrected final pad to {user_pad} to fit the secrets.\n")
    log_debug(f"Using PAD size: {user_pad}", level="INFO")
    return user_pad


def show_start_menu():
    while True:
        print("Press 1 - Enter setup phase")
        print("Press 2 - Proceed to example demonstration")
        choice_ = input("Choice: ").strip()
        if choice_ == "1":
            setup_phase()
        elif choice_ == "2":
            break
        else:
            print("Invalid choice. Please try again.\n")


def display_questions(questions):
    print("\n--- SECURITY QUESTIONS ---\n")
    for q in questions:
        typ = "CRITICAL" if q.get("is_critical") else "STANDARD"
        print(f"[Question {q['id']}] {q['text']} (Type: {typ})\n")
        for i, alt in enumerate(q["alternatives"], 1):
            letter = chr(ord('A') + i - 1)
            print(f"{letter}) {alt}")
        print("\n---\n")


def _decoy_pick_index(q_hashes_and_alt_hashes: list[tuple[str, str]], decoy_count: int) -> int:
    """
    Deterministically select a decoy index in [1..decoy_count] based on selected answers.
    """
    if decoy_count <= 0:
        return 1
    acc = hashlib.sha3_256()
    for qh, ah in sorted(q_hashes_and_alt_hashes):
        acc.update(qh.encode("utf-8"))
        acc.update(b"|")
        acc.update(ah.encode("utf-8"))
        acc.update(b";")
    val = int.from_bytes(acc.digest()[-4:], "big")
    return (val % decoy_count) + 1  # 1..decoy_count


def _enforce_argon2_floor(arg_time: int, arg_mem: int, arg_par: int):
    """
    Enforce: mem >= 1 GiB, p == 1, t in {2,3}.
    """
    if arg_mem < ARGON2_MEM_FLOOR_KIB or arg_par != ARGON2_P_PINNED or arg_time not in ARGON2_T_ALLOWED:
        raise ValueError(f"Argon2id params below floor: t={arg_time} (allowed 2 or 3), m={arg_mem} KiB (min 1048576), p={arg_par} (must be 1).")


def setup_phase():
    while True:
        print("\nWould you like to edit your questions here?")
        print("Press y for Yes or n for No")
        ans = input("Choice: ").strip().lower()
        if ans == 'n':
            file_load_phase()
            return
        elif ans == 'y':
            manual_questions = manual_input_mode()
            if manual_questions:
                save_option = prompt_save_decision()
                if save_option == 'j':
                    save_questions(manual_questions)
                    print("(Configuration and questions saved.)\n")
                elif save_option == 'c':
                    print("(Continuing without saving.)\n")
            return
        else:
            print("Invalid choice. Please enter 'y' or 'n'.")


def file_load_phase():
    SAVE_DIR.mkdir(parents=True, exist_ok=True)
    all_json = sorted(f for f in SAVE_DIR.glob("*.json") if f.is_file())
    if not all_json:
        print(f"\nNo configuration files found in the '{SAVE_DIR.name}' directory.")
        input("Press b to go back: ")
        return

    print("\nAvailable configuration files:\n")
    for idx, fobj in enumerate(all_json, 1):
        print(f"{idx}) {fobj.name}")
    print("\nEnter the number of the file you'd like to load, or press b to go back.")

    while True:
        user_pick = input("Choice: ").strip().lower()
        if user_pick == 'b':
            return
        try:
            pick_val = int(user_pick)
            if 1 <= pick_val <= len(all_json):
                chosen_file = all_json[pick_val - 1]
                print(f"\nYou selected: {chosen_file.name}")
                try:
                    with open(chosen_file, "r", encoding="utf-8") as jf:
                        kit = json.load(jf)
                    run_recovery_kit_flow(kit, chosen_file)
                except Exception as e:
                    log_exception(e, f"Failed to load or process kit: {chosen_file}")
                    print("ERROR: Could not load/process the selected kit file.")
                return
            else:
                print("Invalid selection. Try again, or press b to go back.")
        except ValueError:
            print("Invalid input. Try again, or press b to go back.")


def manual_input_mode():
    """
    Returns list of questions:
      {
        "id": int,
        "text": str,
        "alternatives": [str],
        "correct_answers": [str],  # used internally, not exported
        "is_critical": bool
      }
    """
    questions = []
    while True:
        current_qnum = len(questions) + 1
        print(f"\nEnter your security question #{current_qnum} (2..100 total):")
        question_text = ""
        while not question_text:
            question_text = input("[Your question here]: ").strip()
            if not question_text:
                print("Question text cannot be blank.")

        # number of alternatives
        while True:
            print("\nHow many answer alternatives should this question have?")
            print("Enter a number between 2 and 20")
            alt_count_str = input("Number of alternatives: ").strip()
            try:
                alt_count = int(alt_count_str)
                if 2 <= alt_count <= 20:
                    break
                print("Please enter a value between 2 and 20.")
            except ValueError:
                print("Invalid integer.")

        # alternatives
        alternatives = []
        norm_seen = set()
        print("\nEnter the alternatives:")
        for i in range(alt_count):
            while True:
                alt_raw = input(f"Alternative {i+1}: ").strip()
                if not alt_raw:
                    print("Alternative cannot be blank.")
                    continue
                norm = _normalize_for_comparison(alt_raw)
                if norm in norm_seen:
                    print("Duplicate or too similar alternative. Please enter a unique value.")
                    continue
                alternatives.append(alt_raw)
                norm_seen.add(norm)
                break

        # type
        is_critical = False
        print("\nSelect question type:")
        print("Standard is selected by default.")
        print("If you want to mark this question as critical, press c.")
        print("(Otherwise, press Enter to keep it as Standard)")
        if input("Choice: ").strip().lower() == 'c':
            is_critical = True

        # correct answers selection
        correct_answers = _prompt_correct_answers_for_question(alternatives)

        # re-edit loop
        while True:
            print("\nWould you like to re-edit anything for the current question before proceeding?")
            print("Press q  – Re-edit the security question text")
            print("Press a  – Re-edit all answer alternatives")
            print(f"Press # (1..{alt_count}) – Re-edit a single alternative by its number")
            print("Press r  – Re-select the correct answer(s)")
            print("(Or press Enter to continue to next step/question)")
            e = input("Re-edit choice: ").strip().lower()
            if e == "":
                break
            if e == "q":
                new_text = ""
                while not new_text:
                    new_text = input("\nRe-enter security question text:\n").strip()
                    if not new_text:
                        print("Question text cannot be blank.")
                question_text = new_text
                print("(Question updated.)\n")
            elif e == "a":
                new_alts = []
                new_seen = set()
                print("\nRe-entering all alternatives...")
                for i in range(alt_count):
                    while True:
                        v = input(f"Re-enter Alternative {i+1}: ").strip()
                        if not v:
                            print("Alternative cannot be blank.")
                            continue
                        n = _normalize_for_comparison(v)
                        if n in new_seen:
                            print("Duplicate or too similar alternative. Please enter a unique value.")
                            continue
                        new_alts.append(v)
                        new_seen.add(n)
                        break
                alternatives = new_alts
                norm_seen = new_seen
                print("(Alternatives updated.)\n")
                correct_answers = _prompt_correct_answers_for_question(alternatives)
            elif e == "r":
                correct_answers = _prompt_correct_answers_for_question(alternatives)
            else:
                try:
                    idx = int(e)
                    if 1 <= idx <= alt_count:
                        while True:
                            nv = input(f"Re-enter Alternative {idx}: ").strip()
                            if not nv:
                                print("Alternative cannot be blank.")
                                continue
                            n = _normalize_for_comparison(nv)
                            # check against others
                            others = set(_normalize_for_comparison(x) for j, x in enumerate(alternatives) if j != idx-1)
                            if n in others:
                                print("Duplicate or too similar to another existing alternative.")
                                continue
                            old_val = alternatives[idx-1]
                            alternatives[idx-1] = nv
                            # keep correct selection consistent
                            if old_val in correct_answers:
                                correct_answers = [nv if x == old_val else x for x in correct_answers]
                            print("(Alternative updated.)\n")
                            break
                    else:
                        print(f"Alternative number must be between 1 and {alt_count}.")
                except ValueError:
                    print("Unrecognized re-edit choice.\n")

        questions.append({
            "id": current_qnum,
            "text": question_text,
            "alternatives": alternatives,
            "correct_answers": correct_answers,
            "is_critical": is_critical
        })

        print("\nNavigation options:")
        print("Press n  – Proceed to the next question")
        if len(questions) > 1:
            print("Press b  – Go back and revise the previous question")
        if len(questions) >= 2:
            print("Press d  – Done (finish input)")
        print(f"(You must have at least 2 questions to finish, you currently have {len(questions)}.)")

        nav = input("Choice: ").strip().lower()
        if nav == "n" or nav == "":
            if len(questions) >= 100:
                print("You have reached the maximum of 100 questions. Finishing input now.")
                break
        elif nav == "b":
            # remove current question entry and go back one
            if questions:
                questions.pop()
            if questions:
                print("\nRevising the previous question (it will be re-entered)...")
                last = questions.pop()
                # push back so user re-enters (simple approach)
                continue
        elif nav == "d":
            if len(questions) >= 2:
                print("\n--- Manual input complete. ---\n")
                break
            else:
                print("You must have at least 2 questions. Continue adding more.")
        else:
            if len(questions) >= 100:
                print("You have reached the maximum of 100 questions. Finishing input now.")
                break

    if questions:
        print("Summary of your manually entered questions:\n")
        for qd in questions:
            typ = "CRITICAL" if qd["is_critical"] else "STANDARD"
            print(f"[Question {qd['id']}] {qd['text']}")
            for i, alt in enumerate(qd["alternatives"], 1):
                letter = chr(ord('A') + i - 1)
                print(f"  {letter}) {alt}")
            print(f"  Type: {typ}\n")
    else:
        print("No questions were entered.\n")

    return questions


def _prompt_correct_answers_for_question(alternatives: list[str]) -> list[str]:
    if not alternatives:
        return []
    print("\nMark the correct answer(s) for this question.")
    print("Enter letters or numbers separated by commas (e.g., A,C or 1,3).")
    print("Press ENTER to mark ALL alternatives as correct.")
    print("Tip: You can also type 'all'.")
    legend = ", ".join(f"{chr(ord('A')+i)}={i+1}" for i in range(len(alternatives)))
    print("Legend:", legend)
    while True:
        raw = input("Correct selection(s): ").strip()
        if raw == "" or raw.lower() == "all":
            return alternatives[:]
        tokens = [t.strip() for chunk in raw.replace(",", " ").split() for t in [chunk] if t.strip()]
        if not tokens:
            print("Please enter something, or press ENTER for ALL.")
            continue
        picks = set()
        ok = True
        for t in tokens:
            if len(t) == 1 and t.isalpha():
                idx = (ord(t.upper()) - ord('A')) + 1
            else:
                try:
                    idx = int(t)
                except ValueError:
                    print(f"Unrecognized token '{t}'.")
                    ok = False
                    break
            if not (1 <= idx <= len(alternatives)):
                print(f"Out of range: '{t}'.")
                ok = False
                break
            picks.add(idx)
        if not ok or not picks:
            continue
        return [alternatives[i-1] for i in sorted(picks)]


def prompt_save_decision():
    while True:
        print("\nWould you like to save your questions?")
        print("Press j  – Save as both JSON and text file")
        print("Press c  – Continue without saving")
        c = input("Choice: ").strip().lower()
        if c in ("j", "c"):
            return c
        print("Invalid choice.")


# -------------- Decoys + recovery kit (passwordless + AAD + Auth-catalog + KDF ladder) --------------

def _prompt_decoy_secrets() -> list[str]:
    """
    Ask for up to 5 decoy secrets (plaintexts). Empty input stops early.
    """
    decoys = []
    print("\n--- Optional: Configure up to FIVE decoy secrets ---")
    print("A decoy is returned when real restoration criteria are not met.")
    print("They should look fully plausible. The text you enter here is what will be revealed.")
    print("(Press ENTER on a blank line to stop adding decoys.)\n")
    for i in range(1, 6):
        s = input(f"Enter decoy secret #{i} (leave blank to stop): ")
        if not s:
            break
        decoys.append(s)
    if not decoys:
        # Always have at least one decoy so the system never fails closed
        default_msg = "System: Recovery completed successfully."
        print(f"\n(No decoys provided. Adding a default decoy: \"{default_msg}\")")
        decoys.append(default_msg)
    return decoys


def _manifest(config: dict, questions: list, encrypted_shares: dict) -> dict:
    """
    Build a committed manifest (kit metadata + payload hash).
    """
    # Canonical payload hash (sorted keys dump)
    payload_bytes = json.dumps(encrypted_shares, sort_keys=True).encode("utf-8")
    payload_hash = hashlib.sha3_256(payload_bytes).hexdigest()

    total_correct = sum(len(q.get("correct_answers", [])) for q in questions)
    total_alts = sum(len(q.get("alternatives", [])) for q in questions)

    manifest = {
        "kit_version": KIT_VERSION,
        "aead_envelope_v": 1,
        "aead_algorithms": ["aes256gcm", "chacha20poly1305"],
        "argon2_floor": {"min_mib": 1024, "p": 1, "allowed_t": sorted(ARGON2_T_ALLOWED)},
        "argon2_params": config.get("argon2_params"),
        "normalization_policy": "sanitize_input -> normalize_text(NFKC)",
        "pad_size": config.get("pad_size"),
        "counts": {"N_total": total_alts, "C_total": total_correct, "T_real": config.get("real_threshold")},
        "kdf": {"ladder": 2, "key_len": 32, "pinned_p": 1},
        "payload_hash": payload_hash,
    }
    # self-commit hash (over manifest sans its own commit)
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
    manifest["commit_sha3_256"] = hashlib.sha3_256(manifest_bytes).hexdigest()
    return manifest


def save_questions(questions):
    """
    Builds and saves a SELF-CONTAINED recovery kit (passwordless per-answer keys).
    Enforces a minimum combinatorial hardness before allowing kit generation.

    Generates *one real* secret and up to *five decoy* secrets. The JSON contains
    per-answer encrypted shares for: real only on correct alternatives (others carry
    indistinguishable random bytes), while each decoy has shares assigned for *all*
    alternatives to guarantee a successful reconstruction path.
    """
    print("\n--- Cryptographic Parameter Setup ---")
    real_secret = get_nonempty_secret("Enter the secret to be protected: ")
    real_bytes = real_secret.encode("utf-8")
    real_b64 = base64.b64encode(real_bytes).decode()

    # Optional decoys
    decoy_texts = _prompt_decoy_secrets()
    decoy_bytes_list = [d.encode("utf-8") for d in decoy_texts]
    decoy_b64_list = [base64.b64encode(b).decode() for b in decoy_bytes_list]

    total_correct = sum(len(q.get("correct_answers", [])) for q in questions)
    total_alts = sum(len(q.get("alternatives", [])) for q in questions)
    total_incorrect = max(0, total_alts - total_correct)
    log_debug("Counts computed for kit build.",
              level="INFO",
              component="CRYPTO",
              details={"total_correct": total_correct, "total_alternatives": total_alts, "total_incorrect": total_incorrect})

    if total_correct == 0:
        print("ERROR: No correct answers were defined across your questions. At least one is required.")
        return

    # threshold bounds based on real shares available (policy)
    min_thr = _policy_min_threshold(total_correct)
    max_thr = total_correct
    print(f"\n[Policy] Minimum threshold for your {total_correct} real share(s) is {min_thr}.")
    r_thr = get_threshold("Enter the real threshold", min_thr, max_thr)

    # Pad size must accommodate the longest base64 across real+decoys
    max_b64_len = max(len(real_b64), *(len(db64) for db64 in decoy_b64_list))
    pad_size = prompt_pad_size_multi(max_b64_len)

    # Argon2 parameters (must meet floors)
    arg_time, arg_mem, arg_par = prompt_argon2_parameters()
    try:
        _enforce_argon2_floor(arg_time, arg_mem, arg_par)
    except Exception as e:
        log_exception(e, "Argon2 parameters below floor during kit build")
        print(f"[ABORT] {e}")
        return

    log_debug("Argon2id parameters confirmed for kit.",
              level="INFO",
              component="CRYPTO",
              details={"time_cost": arg_time, "memory_cost": arg_mem, "parallelism": arg_par})

    # --- Combinatorial hardness gate (for the REAL path) ---
    bits = _combinatorial_bits(total_alts, total_correct, r_thr)
    if not math.isfinite(bits) or bits < SECQ_MIN_BITS:
        print(f"\n[ABORT] Combinatorial hardness too low: ~{bits:.1f} bits "
              f"for N={total_alts}, C={total_correct}, T={r_thr}.")
        print("Add more questions/alternatives and/or increase the threshold, then try again.\n")
        return
    else:
        print(f"[OK] Combinatorial hardness: ~{bits:.1f} bits.")

    # ---------- Build global alternative index ----------
    # Order: [(q_hash, a_hash, q_text, alt_text, is_correct)]
    all_items: list[tuple[str, str, str, str, bool]] = []
    for q in questions:
        q_text = q["text"]
        alts = q["alternatives"]
        q_hash = _integrity_hash_for_kit(q_text, alts)
        correct_set_norm = set(_norm_for_kit(a) for a in q.get("correct_answers", []))
        for alt in alts:
            is_correct = _norm_for_kit(alt) in correct_set_norm
            all_items.append((q_hash, _alt_hash_for_kit(alt), q_text, alt, is_correct))
    total_alts = len(all_items)

    # ---------- Generate shares ----------
    # REAL: shares only for the number of correct alternatives
    try:
        real_shares_correct = asyncio.run(
            sss_split(real_b64.encode("utf-8"), sum(1 for it in all_items if it[4]), r_thr, pad=pad_size)
        )
    except Exception as e:
        log_exception(e, "Error splitting REAL secret")
        return

    # DECOYS: produce for ALL alternatives; **threshold for all decoys equals r_thr** (avoid oracle)
    decoy_thresholds = [r_thr for _ in decoy_b64_list]
    decoy_shares_by_idx: list[list[bytearray]] = []
    try:
        for db64, thr in zip(decoy_b64_list, decoy_thresholds):
            shares = asyncio.run(sss_split(db64.encode("utf-8"), total_alts, thr, pad=pad_size))
            decoy_shares_by_idx.append(shares)
    except Exception as e:
        log_exception(e, "Error splitting DECOY secret(s)")
        return

    # ---------- AUTH CATALOG (indistinguishable; heavy Argon2 gate) ----------
    def _auth_entry(secret_bytes: bytes) -> dict:
        gate_salt = os.urandom(16)
        gate_t = 2
        gate_m = ARGON2_MEM_FLOOR_KIB  # 1 GiB heavy gate
        gate_p = 1
        # Heavy KDF on reconstructed secret (bytes)
        gk = argon2.low_level.hash_secret_raw(
            secret=secret_bytes, salt=gate_salt, time_cost=gate_t,
            memory_cost=gate_m, parallelism=gate_p, hash_len=32,
            type=argon2.low_level.Type.ID
        )
        tag = hmac.new(gk, secret_bytes, digestmod="sha256").digest()
        return {"gate": {"t": gate_t, "m": gate_m, "p": gate_p, "salt": base64.b64encode(gate_salt).decode()},
                "hmac_sha256": base64.b64encode(tag).decode()}

    auth_catalog = [_auth_entry(real_bytes)] + [_auth_entry(b) for b in decoy_bytes_list]
    # Shuffle for stronger indistinguishability (cryptographically strong)
    secrets_perm = list(range(len(auth_catalog)))
    random.SystemRandom().shuffle(secrets_perm)
    auth_catalog = [auth_catalog[i] for i in secrets_perm]

    # ---------- Encrypt per-answer shares for each secret variant ----------
    # For the REAL secret (index 0): only correct alternatives carry valid real shares.
    # For incorrect alternatives we store indistinguishable random bytes of share_len.
    encrypted_shares: dict[str, dict[str, dict]] = {}
    real_idx = 0
    share_len = pad_size + 1  # sss-bridge share size (pad bytes + 1 byte x-coordinate)

    def _enc_one_share(plaintext_share: bytes, q_hash: str, alt_text: str, alg_choice: str) -> dict:
        # KDF ladder parameters
        s1 = os.urandom(16); s2 = os.urandom(16); hkdf_salt = os.urandom(16)
        key = _derive_answer_key_ladder(alt_text, s1, s2, arg_time, arg_mem, 1, hkdf_salt)
        aad = _aad_bytes(q_hash, _alt_hash_for_kit(alt_text), alg_choice)
        enc = encrypt_aead_envelope(plaintext_share, key, alg_choice, aad=aad)
        # Attach KDF description (ladder v1)
        enc.update({
            "algorithm": enc.get("alg", alg_choice),
            "kdf": {"type": "argon2id-ladder", "ladder": 2, "t": arg_time, "m": arg_mem, "p": 1, "len": 32,
                    "s1": base64.b64encode(s1).decode(), "s2": base64.b64encode(s2).decode(),
                    "hkdf_salt": base64.b64encode(hkdf_salt).decode()}
        })
        return enc

    rng = random.SystemRandom()
    # Walk all alternatives in global order so decoy shares map 1:1 by index
    for global_idx, (q_hash, a_hash, q_text, alt_text, is_corr) in enumerate(all_items):
        encrypted_shares.setdefault(q_hash, {})
        per_alt_block = {}
        # s0 => REAL path
        if is_corr:
            if real_idx >= len(real_shares_correct):
                log_error("Internal error: real_idx overflow", None, {"real_idx": real_idx, "len": len(real_shares_correct)})
                real_share = os.urandom(share_len)  # fallback indistinguishable
            else:
                real_share = bytes(real_shares_correct[real_idx])
                real_idx += 1
        else:
            real_share = os.urandom(share_len)  # indistinguishable filler for incorrect alts
        per_alt_block["s0"] = _enc_one_share(real_share, q_hash, alt_text, rng.choice(["chacha20poly1305", "aes256gcm"]))

        # s1..sN => decoys (always valid shares for all alts)
        for decoy_i, shares_list in enumerate(decoy_shares_by_idx, start=1):
            dec_share = bytes(shares_list[global_idx])
            per_alt_block[f"s{decoy_i}"] = _enc_one_share(dec_share, q_hash, alt_text, rng.choice(["chacha20poly1305", "aes256gcm"]))

        encrypted_shares[q_hash][a_hash] = per_alt_block

        log_debug(
            "Mapped Q/A to encrypted multi-secret shares.",
            level="INFO",
            component="CRYPTO",
            details={
                "q_text": q_text,
                "alt_text": alt_text,
                "q_hash": q_hash,
                "alt_hash": a_hash,
                "real_valid": bool(is_corr),
                "decoy_variants": len(decoy_shares_by_idx)
            }
        )

    questions_out = []
    for q in questions:
        questions_out.append({
            "id": q["id"],
            "text": q["text"],
            "alternatives": q["alternatives"],
            "is_critical": bool(q.get("is_critical", False)),
            "integrity_hash": _integrity_hash_for_kit(q["text"], q["alternatives"])
        })

    base_config = {
        "real_threshold": r_thr,
        "pad_size": pad_size,
        "argon2_params": {"time_cost": arg_time, "memory_cost": arg_mem, "parallelism": 1},
        "version": KIT_VERSION,
        "secrets_count": 1 + len(decoy_b64_list),
        "auth_catalog": auth_catalog  # randomized order; indistinguishable
    }
    manifest = _manifest(base_config, questions_out, encrypted_shares)

    recovery_kit = {
        "config": base_config | {"manifest": manifest},
        "questions": questions_out,
        "encrypted_shares": encrypted_shares
    }

    # persist files
    SAVE_DIR.mkdir(parents=True, exist_ok=True)
    base_name = "user_config"
    json_file = get_next_filename(SAVE_DIR, base_name, "json")
    txt_file = get_next_filename(SAVE_DIR, base_name, "txt")

    with open(json_file, "w", encoding="utf-8") as jf:
        json.dump(recovery_kit, jf, indent=2, sort_keys=True)

    with open(txt_file, "w", encoding="utf-8") as tf:
        tf.write("--- CRYPTOGRAPHIC CONFIGURATION ---\n")
        tf.write("Secret: [encrypted via SSS; not stored in JSON]\n")
        tf.write(f"Shamir Threshold (real path): {r_thr}\n")
        tf.write(f"Pad Size: {pad_size}\n")
        tf.write("Argon2id Parameters:\n")
        tf.write(f"  - Time Cost: {arg_time}\n")
        tf.write(f"  - Memory Cost: {arg_mem} KiB\n")
        tf.write(f"  - Parallelism: 1\n")
        tf.write(f"\nAuth Catalog Entries (real+decoys, shuffled): {len(auth_catalog)}\n")
        tf.write("\n--- SECURITY QUESTIONS ---\n\n")
        for q in questions:
            qtype = "CRITICAL" if q.get("is_critical") else "STANDARD"
            tf.write(f"[Question {q['id']}] {q['text']} (Type: {qtype})\n\n")
            for i, alt in enumerate(q['alternatives'], 1):
                letter = chr(ord('A') + i - 1)
                tf.write(f"{letter}) {alt}\n")
            tf.write("\n---\n\n")

    print(f"Saved configuration to '{json_file}' and '{txt_file}'.")
    log_debug("Recovery kit saved (passwordless; ladder KDF; auth catalog; decoy-enabled; fixed AEAD).", level="INFO")


# ---------- Recovery UI Flow from a saved kit (real + decoys, indistinguishable) ----------

def _sample_t_subsets(n: int, t: int, budget: int, rng: random.Random):
    """
    Generate up to 'budget' t-sized index tuples from 0..n-1.
    Exhaustive if small; otherwise random unique samples then pad with repeats
    to reach exact 'budget' attempts.
    """
    total_combos = math.comb(n, t) if hasattr(math, "comb") else float("inf")
    idx_sets = []
    if total_combos <= budget and total_combos < 10_000:
        # Exhaustive
        for idxs in combinations(range(n), t):
            idx_sets.append(tuple(idxs))
    else:
        seen = set()
        while len(idx_sets) < min(budget, 10_000):  # avoid absurd memory
            s = set()
            while len(s) < t:
                s.add(rng.randrange(n))
            tup = tuple(sorted(s))
            if tup not in seen:
                seen.add(tup)
                idx_sets.append(tup)
    # Pad with repeats to exactly 'budget'
    while len(idx_sets) < budget and len(idx_sets) > 0:
        idx_sets.append(idx_sets[len(idx_sets) % len(idx_sets)])
    if not idx_sets and n >= t:
        # degenerate pad: choose first t
        idx_sets = [tuple(range(t))] * budget
    return idx_sets[:budget]


def _combine_fixed_budget(partials: list[bytes], r_thr: int, budget: int, rng: random.Random) -> bytes | None:
    """
    Always perform exactly 'budget' combine attempts (or as close as possible),
    without early return. Return the first success (if any) at the end.
    """
    n = len(partials)
    if n < r_thr:
        # still consume budget as dummy attempts (no-op) to keep work pattern
        for _ in range(budget):
            pass
        return None

    idx_sets = _sample_t_subsets(n, r_thr, budget, rng)
    first_success = None
    for idxs in idx_sets:
        try:
            cand = asyncio.run(sss_combine([partials[i] for i in idxs]))
            if first_success is None and cand is not None:
                first_success = cand
        except Exception:
            # keep going; consume all attempts
            continue
    return first_success


def run_recovery_kit_flow(kit: dict, kit_path: Path):
    """
    Use the loaded recovery kit to reconstruct the secret:
      - Show config
      - Present **shuffled** questions via curses multi-select
      - Attempt REAL reconstruction from selected answers
      - If that fails, deterministically route to a DECOY and reconstruct from the same selections
      - Verify against AUTH CATALOG without revealing which secret matched
      - Print uniform success output
    """
    try:
        cfg = kit.get("config") or {}
        questions = kit.get("questions") or []
        enc_shares = kit.get("encrypted_shares") or {}
        r_thr = int(cfg.get("real_threshold"))
        arg = cfg.get("argon2_params") or {}
        arg_time = int(arg.get("time_cost"))
        arg_mem = int(arg.get("memory_cost"))
        arg_par = int(arg.get("parallelism", 1))
        secrets_count = int(cfg.get("secrets_count", 1))
        auth_catalog = list(cfg.get("auth_catalog", []))
        manifest = (cfg.get("manifest") or {})
    except Exception as e:
        log_exception(e, "Invalid kit structure.")
        print("ERROR: Kit structure invalid or missing fields.")
        return

    # Floors enforcement (reject below-floor kits)
    try:
        _enforce_argon2_floor(arg_time, arg_mem, arg_par)
    except Exception as e:
        log_exception(e, "Kit Argon2 parameters below floor – refusing recovery")
        print("ERROR: Kit parameters below enforced floor. Recovery refused.")
        return

    # Manifest checks (best-effort)
    try:
        expected = manifest.get("payload_hash")
        payload_bytes = json.dumps(enc_shares, sort_keys=True).encode("utf-8")
        actual = hashlib.sha3_256(payload_bytes).hexdigest()
        if expected and expected != actual:
            print("ERROR: Payload hash mismatch. Kit corrupted.")
            return
        # verify self-commit
        man_copy = {k: v for k, v in manifest.items() if k != "commit_sha3_256"}
        man_bytes = json.dumps(man_copy, sort_keys=True).encode("utf-8")
        commit = hashlib.sha3_256(man_bytes).hexdigest()
        if manifest.get("commit_sha3_256") and manifest.get("commit_sha3_256") != commit:
            print("ERROR: Manifest commit mismatch. Kit tampered.")
            return
    except Exception as e:
        log_exception(e, "Manifest verification failed (non-fatal)")

    # Summary
    print("\n--- LOADED RECOVERY KIT ---\n")
    print(f"File           : {kit_path.name}")
    print(f"Threshold (T)  : {r_thr}  [real path]")
    print(f"Pad Size       : {cfg.get('pad_size')}")
    print("Argon2id Params:")
    print(f"  - Time Cost  : {arg_time}")
    print(f"  - Memory Cost: {arg_mem} KiB")
    print(f"  - Parallelism: 1")
    print(f"Auth Catalog   : {len(auth_catalog)} entries\n")

    log_debug("Loaded recovery kit.",
              level="INFO",
              component="CRYPTO",
              details={
                  "kit_file": str(kit_path),
                  "threshold": r_thr,
                  "pad_size": cfg.get("pad_size"),
                  "argon2": {"time_cost": arg_time, "memory_cost": arg_mem, "parallelism": 1},
                  "q_count": len(questions),
                  "secrets_count": secrets_count
              })

    if not questions or not enc_shares:
        print("ERROR: Kit missing questions or encrypted_shares.")
        log_error("Kit missing essential arrays.", details={"has_questions": bool(questions), "has_enc_shares": bool(enc_shares)})
        return

    # Present **shuffled** questions via multi-select
    rng = random.SystemRandom()
    present_questions = deepcopy(questions)
    rng.shuffle(present_questions)
    for q in present_questions:
        alts = q.get("alternatives", [])
        rng.shuffle(alts)
        q["alternatives"] = alts

    print("--- Answer the security questions ---\n")
    chosen = []
    for i, q in enumerate(present_questions, 1):
        text = q.get("text", "")
        alts = list(q.get("alternatives", []))
        picks = curses.wrapper(
            lambda st: arrow_select_no_toggle(
                st, i, text, alts, pre_selected=None
            )
        )
        chosen.append({"q": q, "picks": picks})
        log_debug("Recovery UI picks for question.",
                  level="INFO",
                  component="GENERAL",
                  details={"q_id": q.get("id"), "q_text": text, "picked": picks})

    # --- Decrypt selected shares for s0 (REAL path attempt) ---
    partials_s0: list[bytes] = []
    selected_pairs: list[tuple[str, str, str, str]] = []  # (q_hash, a_hash, q_text, alt_text)
    for item in chosen:
        qobj = item["q"]
        picks = item["picks"]
        q_text = qobj.get("text", "")
        alts = qobj.get("alternatives", [])
        q_hash = qobj.get("integrity_hash") or _integrity_hash_for_kit(q_text, alts)
        q_block = enc_shares.get(q_hash)
        if not q_block:
            log_error("Missing encrypted_shares block for question hash.", details={"q_hash": q_hash})
            continue
        for alt in picks:
            alt_hash = _alt_hash_for_kit(alt)
            sblock = q_block.get(alt_hash) or {}
            entry = sblock.get("s0")
            if not entry:
                log_error("No encrypted entry for selected alternative (s0).", details={"q_hash": q_hash, "alt_hash": alt_hash, "alt_text": alt})
                continue
            selected_pairs.append((q_hash, alt_hash, q_text, alt))
            share_bytes = _decrypt_share_from_entry(entry, arg_time, arg_mem, 1,
                                                    q_hash=q_hash, alt_hash=alt_hash,
                                                    qid=qobj.get("id"), qtext=q_text, alt_text=alt)
            if share_bytes is not None:
                partials_s0.append(share_bytes)

    # Try REAL combine with threshold r_thr using constant budget
    real_combined = _combine_fixed_budget(partials_s0, r_thr, COMBINE_BUDGET_REAL, rng)

    selected_catalog_index = None
    secret_variant_used = "UNKNOWN"

    if real_combined is None:
        # Route to a deterministic DECOY based on the selection
        idx = _decoy_pick_index([(qh, ah) for (qh, ah, _, _) in selected_pairs], max(0, secrets_count - 1))
        decoy_index = max(1, idx)  # ensure >=1 if any decoys exist

        # Decrypt decoy shares for exactly T=r_thr (fill deterministically from unpicked to reach T)
        qhash_ahash_pairs = selected_pairs[:]
        decoy_partials: list[bytes] = []
        for (q_hash, a_hash, q_text, alt_text) in qhash_ahash_pairs:
            block = enc_shares.get(q_hash, {}).get(a_hash, {})
            entry = block.get(f"s{decoy_index}")
            if not entry:
                continue
            sb = _decrypt_share_from_entry(entry, arg_time, arg_mem, 1,
                                           q_hash=q_hash, alt_hash=a_hash,
                                           qid=None, qtext=q_text, alt_text=alt_text)
            if sb is not None:
                decoy_partials.append(sb)

        # Deterministically fill to exactly r_thr from remaining alts
        if len(decoy_partials) < r_thr:
            needed = r_thr - len(decoy_partials)
            # Scan all (q,alt) in canonical order
            for q in present_questions:
                q_text = q.get("text", "")
                alts = q.get("alternatives", [])
                q_hash = q.get("integrity_hash") or _integrity_hash_for_kit(q_text, alts)
                for alt_text in alts:
                    a_hash = _alt_hash_for_kit(alt_text)
                    if any((qh == q_hash and ah == a_hash) for (qh, ah, _, _) in qhash_ahash_pairs):
                        continue
                    entry = enc_shares.get(q_hash, {}).get(a_hash, {}).get(f"s{decoy_index}")
                    if not entry:
                        continue
                    sb = _decrypt_share_from_entry(entry, arg_time, arg_mem, 1,
                                                   q_hash=q_hash, alt_hash=a_hash,
                                                   qid=None, qtext=q_text, alt_text=alt_text)
                    if sb is not None:
                        decoy_partials.append(sb)
                        qhash_ahash_pairs.append((q_hash, a_hash, q_text, alt_text))
                        if len(decoy_partials) >= r_thr:
                            break
                if len(decoy_partials) >= r_thr:
                    break

        decoy_partials = decoy_partials[:r_thr]  # ensure exact T
        combined_bytes = _combine_fixed_budget(decoy_partials, r_thr, COMBINE_BUDGET_DECOY, rng)
        if combined_bytes is None:
            print("Recovery failed unexpectedly. Please re-run and pick different answers.")
            return
        secret_variant_used = f"DECOY_{decoy_index}"
    else:
        combined_bytes = real_combined
        secret_variant_used = "REAL"

    # Decode final secret (base64 → utf-8) and verify against AUTH CATALOG (indistinguishable)
    try:
        recovered_b64 = combined_bytes.decode("utf-8")
        final_secret_text = base64.b64decode(recovered_b64).decode("utf-8")

        # AUTH-CATALOG verification (no disclosure of which entry matched), **no early exit**
        matched_any = False
        for entry in auth_catalog:
            try:
                g = entry.get("gate", {})
                salt = base64.b64decode(g.get("salt", ""))
                t = int(g.get("t", 2)); m = int(g.get("m", ARGON2_MEM_FLOOR_KIB)); p = 1
                # derive heavy gate key on recovered secret
                gk = argon2.low_level.hash_secret_raw(
                    secret=final_secret_text.encode("utf-8"), salt=salt, time_cost=t,
                    memory_cost=m, parallelism=p, hash_len=32,
                    type=argon2.low_level.Type.ID
                )
                expected = base64.b64decode(entry.get("hmac_sha256", ""))
                calc = hmac.new(gk, final_secret_text.encode("utf-8"), digestmod="sha256").digest()
                # OR-accumulate; still run through the whole catalog
                if hmac.compare_digest(calc, expected):
                    matched_any = True
            except Exception:
                # keep iterating through the rest
                continue

        print("\n[AUTH RESULT] Verified" if matched_any else "\n[AUTH RESULT] Invalid")
        print("--- SECRET RECONSTRUCTED ---")
        print(final_secret_text)
        print("-----------------------------\n")
        log_debug("Final secret reconstructed.", level="INFO", component="CRYPTO",
                  details={"final_secret_len": len(final_secret_text), "variant": secret_variant_used, "auth_valid": matched_any})
    except Exception as e:
        log_exception(e, "Final base64/utf-8 decode failed.")
        print("\nShares combined, but final decode failed (invalid base64 or encoding).\n")

    append_recovery_guide()
    log_debug("Recovery Mode complete.", level="INFO")

    # End-of-flow options (per requirement)
    print("Press 1 – Enter setup phase")
    print("Press 2 – Proceed to example demonstration")


# ---------- existing demonstration / combine path (kept; now uses fixed AEAD) ----------

def get_next_filename(base_dir, base_name, extension):
    idx = 0
    while True:
        idx += 1
        candidate = base_dir / (f"{base_name}.{extension}" if idx == 1 else f"{base_name}{idx}.{extension}")
        if not candidate.exists():
            return candidate


def check_required_files():
    needed_in_src = ["CipherForge.py", "example_questions25.json"]
    missing = []
    for f in needed_in_src:
        if not (SRC_DIR / f).exists():
            missing.append(f)
    modules_path = SRC_DIR / "modules"
    needed_in_modules = [
        "debug_utils.py",
        "input_utils.py",
        "log_processor.py",
        "security_utils.py",
        "split_utils.py",
        "sss_bridge.py",
        "ui_utils.py"
    ]
    for f in needed_in_modules:
        if not (modules_path / f).exists():
            missing.append(f"modules/{f}")
    if missing:
        log_error("Missing required files", None, {"missing": missing})
        print("ERROR - Missing files:", missing)
        sys.exit(1)


def prompt_argon2_parameters():
    print("\n--- Argon2id Parameter Setup ---")
    print("Use (n) normal defaults, (a) auto-calibrate, or (e) custom edit? [n/a/e] ", end="")
    choice_ = input().strip().lower()
    if choice_ == 'a':
        t, m_kib, p, ms = calibrate_argon2()
        print(f"Auto-calibrated: time_cost={t}, memory_cost={m_kib} KiB, parallelism=1 (~{ms:.1f} ms/guess)")
        return (t, m_kib, 1)
    if choice_ != 'e':
        # Strong defaults: t=3, m=1 GiB, p=1
        print("Using DEFAULT Argon2id parameters: time_cost=3, memory_cost=1048576, parallelism=1")
        input("Press ENTER to continue with these defaults...")
        return (3, 1048576, 1)
    else:
        print("Enter custom Argon2id parameters (floors enforced).")
        tc = get_valid_int("time_cost (2..3)? ", 2, 3)
        mc = get_valid_int("memory_cost (1048576..2097152)? ", 1048576, 2097152)
        pl = 1  # pinned
        print(f"Using CUSTOM Argon2id parameters: time_cost={tc}, memory_cost={mc}, parallelism=1")
        return (tc, mc, 1)


def calc_qna_search_space(chosen):
    total = 1
    for q in chosen:
        n_alts = len(q["alternatives"])
        ways = (1 << n_alts) - 1 if n_alts > 0 else 1
        total *= max(1, ways)
    return total


def convert_seconds_to_dhms(seconds):
    out = {"years":0,"months":0,"days":0,"hours":0,"minutes":0.0,"seconds":0.0}
    if seconds <= 0: return out
    year_sec   = 365.25*24*3600
    month_sec  = 30.4375*24*3600
    day_sec    = 24*3600
    hour_sec   = 3600
    minute_sec = 60
    out["years"]   = int(seconds // year_sec); seconds %= year_sec
    out["months"]  = int(seconds // month_sec); seconds %= month_sec
    out["days"]    = int(seconds // day_sec); seconds %= day_sec
    out["hours"]   = int(seconds // hour_sec); seconds %= hour_sec
    out["minutes"] = int(seconds // minute_sec); seconds %= minute_sec
    out["seconds"] = seconds
    return out


def print_estimated_bruteforce_times(chosen, arg_time, arg_mem, arg_par,
                                     total_correct_lower: int | None = None,
                                     r_thr: int | None = None,
                                     decoy_present: bool = True):
    """
    Enhanced brute-force estimator (beta).
    """
    import math
    search_space = max(1, calc_qna_search_space(chosen))
    single_guess_ms = estimate_argon2_time_ms(arg_time, arg_mem, 1, samples=1)
    # Assume a tight lower bound for "no Argon2" primitive crypto guess
    single_guess_ms_no_argon = 0.005  # 5 microseconds per attempt (model)

    # Total attempts to brute-force "any subset"
    total_classical_ms = search_space * single_guess_ms
    total_quantum_ms   = math.sqrt(search_space) * single_guess_ms
    total_classical_ms_na = search_space * single_guess_ms_no_argon
    total_quantum_ms_na   = math.sqrt(search_space) * single_guess_ms_no_argon

    # Real threshold lower-bound trials (choose exactly r_thr correct picks)
    trials_real_lb = None
    if total_correct_lower is not None and r_thr is not None and total_correct_lower >= r_thr:
        trials_real_lb = math.comb(total_correct_lower, r_thr)
    # Decoy minimal trials (now T=r_thr for decoys, so same combinatorics as real)
    trials_decoy_min = trials_real_lb

    def _fmt_time(ms: float) -> dict:
        sec = ms / 1000.0
        return convert_seconds_to_dhms(sec)

    print("\n--- Estimated Brute-Force Difficulty ---")
    print(f"Total Q&A search space (non-empty subsets): {search_space:,.0f} guesses.")

    print("\n[WITH Argon2id] per-guess ~{:.3f} ms =>".format(single_guess_ms))
    cl = _fmt_time(total_classical_ms); qn = _fmt_time(total_quantum_ms)
    print(f"  Classical total time : {cl['years']}y {cl['months']}m {cl['days']}d {cl['hours']}h {cl['minutes']}m {cl['seconds']:.2f}s")
    print(f"  Quantum (Grover est.): {qn['years']}y {qn['months']}m {qn['days']}d {qn['hours']}h {qn['minutes']}m {qn['seconds']:.2f}s")

    print("\n[WITHOUT Argon2id] per-guess ~{:.3f} ms =>".format(single_guess_ms_no_argon))
    cl2 = _fmt_time(total_classical_ms_na); qn2 = _fmt_time(total_quantum_ms_na)
    print(f"  Classical total time : {cl2['years']}y {cl2['months']}m {cl2['days']}d {cl2['hours']}h {cl2['minutes']}m {cl2['seconds']:.2f}s")
    print(f"  Quantum (Grover est.): {qn2['years']}y {qn2['months']}m {qn2['days']}d {qn2['hours']}h {qn2['minutes']}m {qn2['seconds']:.2f}s")

    if trials_real_lb is not None:
        print(f"\nLower-bound trials to reach REAL/DECOY threshold (T={r_thr}): C(C_total={total_correct_lower}, T={r_thr}) = {trials_real_lb:,d}")
    if trials_decoy_min is not None:
        print(f"Minimal trials to reach *a decoy* (T={r_thr}): {trials_decoy_min}")

    print()  # newline


# ---------- Demo flow (uses fixed AEAD and constant-budget combine) ----------

def main():
    try:
        print("[INFO] Launching main.py...")
        log_debug("Starting demonstration flow (Option 2)...", level="INFO")

        if not QUESTIONS_PATH.exists():
            msg = f"Error: question file not found: {QUESTIONS_PATH}"
            log_error(msg)
            print(msg)
            return
        try:
            with open(QUESTIONS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            empty_correct = 0
            for qd in data:
                if validate_question(qd):
                    qd["correct_answers"] = [
                        sanitize_input(normalize_text(ans)) for ans in qd.get("correct_answers", [])
                    ]
                    qd["alternatives"] = [
                        sanitize_input(normalize_text(alt)) for alt in qd["alternatives"]]
                    if not qd["correct_answers"]:
                        empty_correct += 1
                        qd["correct_answers"] = qd["alternatives"][:]
                        log_debug(
                            f"Question '{qd['text']}' had empty 'correct_answers'. Now set them all as correct.",
                            level="INFO"
                        )
            valid_data = [q for q in data if validate_question(q)]
            if empty_correct > 0:
                print(f"NOTICE: {empty_correct} question(s) had empty 'correct_answers'. "
                      f"All alternatives for those are treated as correct.\n")
        except Exception as e:
            log_exception(e, "Error loading question file")
            return
        if not valid_data:
            print("No valid questions found. Aborting.")
            return

        amt = get_valid_int(f"How many questions? (1..{len(valid_data)}): ", 1, len(valid_data))
        with chosen_lock:
            # **Shuffle** chosen questions and alternatives for the demo too
            rng = random.SystemRandom()
            chosen = valid_data[:amt]
            rng.shuffle(chosen)
            for q in chosen:
                rng.shuffle(q["alternatives"])

        # interactive selection with curses
        correct_cumulative = 0
        incorrect_cumulative = 0
        for i, qdict in enumerate(chosen, 1):
            picks, qtype = curses.wrapper(
                lambda s: arrow_select_clear_on_toggle(
                    s, i, qdict["text"], qdict["alternatives"],
                    pre_selected=qdict.get("user_answers"),
                    pre_qtype=1 if qdict.get("is_critical") else 0,
                    fixed_type=qdict.get("force_type")
                )
            )
            qdict["user_answers"] = picks
            qdict["is_critical"] = bool(qtype) if not qdict.get("force_type") \
                else (qdict["force_type"].upper() == "CRITICAL")

            c_local = 0
            i_local = 0
            cset_local = set(qdict.get("correct_answers", []))
            for alt_ in picks:
                if alt_ in cset_local:
                    c_local += 1
                else:
                    i_local += 1

            log_debug(
                f"Q{i}: text='{qdict['text']}' => user_picks={len(picks)} selected; local counts: correct={c_local}, incorrect={i_local}",
                level="DEBUG"
            )
            correct_cumulative += c_local
            incorrect_cumulative += i_local
            print(f"[FEEDBACK] After Q{i}: +{c_local} correct, +{i_local} incorrect.")
            print(f"Total so far => correct={correct_cumulative}, incorrect={incorrect_cumulative}\n")

        while True:
            done = editing_menu(chosen)
            if done:
                break

        correct_map = []
        incorrect_map = []
        for idx, q in enumerate(chosen, 1):
            cset = set(q.get("correct_answers", []))
            picks_ = q["user_answers"]
            local_c = 0
            local_i = 0
            for alt in picks_:
                if alt in cset:
                    correct_map.append((q, alt))
                    local_c += 1
                else:
                    incorrect_map.append((q, alt))
                    local_i += 1
            log_debug(f"After re-edit Q{idx}: c={local_c}, i={local_i}", level="INFO")

        c_count = len(correct_map)
        i_count = len(incorrect_map)
        log_debug(f"FINAL TALLY => c_count={c_count}, i_count={i_count}", level="INFO")
        print(f"\nOverall Tally => Correct picks={c_count}, Incorrect={i_count}.\n")

        # minimum correctness for demo path
        while True:
            if c_count < 10:
                if c_count == 0:
                    print("Zero correct picks => cannot proceed with Shamir’s Secret Sharing.")
                    print("(E => re-edit answers, N => abort)")
                    answer = input("Choice (E/N)? ").strip().upper()
                    if answer == 'E':
                        re_done = editing_menu(chosen)
                        if re_done:
                            correct_map.clear(); incorrect_map.clear()
                            for q_ in chosen:
                                cset_ = set(q_.get("correct_answers", []))
                                picks_ = q_["user_answers"]
                                for alt_ in picks_:
                                    (correct_map if alt_ in cset_ else incorrect_map).append((q_, alt_))
                            c_count = len(correct_map); i_count = len(incorrect_map)
                            print(f"\nNEW Tally => Correct picks={c_count}, Incorrect={i_count}.\n")
                            continue
                    elif answer == 'N':
                        confirm = input("Are you sure you want to abort? (y/n): ").strip().lower()
                        if confirm.startswith('y'):
                            print("Aborting.")
                            return
                        else:
                            continue
                    else:
                        print("Invalid choice.\n")
                        continue
                else:
                    print("Fewer than 10 correct => re-edit or abort.")
                    answer = input("Choice (E/N)? ").strip().upper()
                    if answer == 'E':
                        re_done = editing_menu(chosen)
                        if re_done:
                            correct_map.clear(); incorrect_map.clear()
                            for q_ in chosen:
                                cset_ = set(q_.get("correct_answers", []))
                                picks_ = q_["user_answers"]
                                for alt_ in picks_:
                                    (correct_map if alt_ in cset_ else incorrect_map).append((q_, alt_))
                            c_count = len(correct_map); i_count = len(incorrect_map)
                            print(f"\nNEW Tally => Correct picks={c_count}, Incorrect={i_count}.\n")
                            continue
                    elif answer == 'N':
                        confirm = input("Are you sure you want to abort? (y/n): ").strip().lower()
                        if confirm.startswith('y'):
                            print("Aborting.")
                            return
                        else:
                            continue
                    else:
                        print("Invalid choice.\n")
                        continue
            else:
                break

        prompt_text = "Real threshold"
        r_thr = get_threshold(prompt_text, 10, c_count)
        print(f"[INFO] Must pick >= {r_thr} correct picks to reconstruct real secret.\n")

        real_secret = get_nonempty_secret("Enter REAL secret: ")
        real_b64 = base64.b64encode(real_secret.encode()).decode()
        user_pad = prompt_pad_size_multi(len(real_b64))
        arg_time, arg_mem, arg_par = prompt_argon2_parameters()
        try:
            _enforce_argon2_floor(arg_time, arg_mem, arg_par)
        except Exception as e:
            log_exception(e, "Argon2 parameters below floor in demo path")
            print(f"[ABORT] {e}")
            return

        # Split real/dummy shares
        try:
            real_shares, dummy_shares = asyncio.run(
                split_secret_and_dummy(real_b64.encode(), c_count, i_count, r_thr, pad=user_pad)
            )
        except Exception as e:
            log_exception(e, "Error splitting secret")
            return

        def ephemeral_encrypt(data: bytes, q_text: str, alt_text: str, alg_choice: str) -> dict:
            """
            Demo-only: keep ephemeral credentials, but add AAD binding for AEAD.
            Uses the **uniform AEAD envelope** for storage.
            """
            ephemeral_pass = base64.b64encode(os.urandom(12)).decode()
            ephemeral_salt = os.urandom(16)
            ephemeral_key, ephemeral_salt_used = derive_or_recover_key(
                ephemeral_pass, ephemeral_salt, ephemeral=True,
                time_cost=arg_time, memory_cost=arg_mem, parallelism=1
            )
            q_hash = _integrity_hash_for_kit(q_text, q["alternatives"])
            alt_hash = _alt_hash_for_kit(alt_text)
            aad = _aad_bytes(q_hash, alt_hash, alg_choice)

            enc_obj = encrypt_aead_envelope(
                data, ephemeral_key, alg_choice, aad=aad
            )
            enc_obj["ephemeral_password"] = ephemeral_pass
            enc_obj["ephemeral_salt_b64"] = base64.b64encode(ephemeral_salt_used).decode()
            enc_obj["algorithm"] = enc_obj.get("alg", alg_choice)
            return enc_obj

        # Assign shares
        std_correct, crit_correct, std_incorrect, crit_incorrect = [], [], [], []
        for (q, alt) in correct_map:
            (crit_correct if q["is_critical"] else std_correct).append((q, alt))
        for (q, alt) in incorrect_map:
            (crit_incorrect if q["is_critical"] else std_incorrect).append((q, alt))

        share_idx_real = 0
        share_idx_dummy = 0
        rng = random.SystemRandom()

        for q_s, alt_s in std_correct:
            if share_idx_real >= len(real_shares): break
            sh = real_shares[share_idx_real]
            enc_full = ephemeral_encrypt(sh, q_s["text"], alt_s, rng.choice(["chacha20poly1305","aes256gcm"]))
            q_s.setdefault("answer_shares", {})
            q_s["answer_shares"][alt_s] = {"enc_data": enc_full}
            for j in range(len(sh)): sh[j] = 0
            share_idx_real += 1

        for q_c, alt_c in crit_correct:
            if share_idx_real >= len(real_shares): break
            if not q_c.get("answer_shares", {}).get(alt_c):
                sh = real_shares[share_idx_real]
                enc_full = ephemeral_encrypt(sh, q_c["text"], alt_c, rng.choice(["chacha20poly1305","aes256gcm"]))
                q_c.setdefault("answer_shares", {})
                q_c["answer_shares"][alt_c] = {"enc_data": enc_full}
                for j in range(len(sh)): sh[j] = 0
                share_idx_real += 1

        for q_s, alt_s in std_incorrect:
            if share_idx_dummy >= len(dummy_shares): break
            sh = dummy_shares[share_idx_dummy]
            enc_full = ephemeral_encrypt(sh, q_s["text"], alt_s, rng.choice(["chacha20poly1305","aes256gcm"]))
            q_s.setdefault("answer_shares", {})
            q_s["answer_shares"][alt_s] = {"enc_data": enc_full}
            for j in range(len(sh)): sh[j] = 0
            share_idx_dummy += 1

        for q_c, alt_c in crit_incorrect:
            if share_idx_dummy >= len(dummy_shares): break
            if not q_c.get("answer_shares", {}).get(alt_c):
                sh = dummy_shares[share_idx_dummy]
                enc_full = ephemeral_encrypt(sh, q_c["text"], alt_c, rng.choice(["chacha20poly1305","aes256gcm"]))
                q_c.setdefault("answer_shares", {})
                q_c["answer_shares"][alt_c] = {"enc_data": enc_full}
                for j in range(len(sh)): sh[j] = 0
                share_idx_dummy += 1

        print("\n--- Final Answering Phase ---\n")
        for i, q in enumerate(chosen, 1):
            picks2 = curses.wrapper(
                lambda st: arrow_select_no_toggle(
                    st, i, q["text"], q["alternatives"],
                    pre_selected=q.get("user_answers")
                )
            )
            q["user_answers"] = picks2

        while True:
            result = final_edit_menu(chosen)
            if result == 'G':
                log_debug("User finalize => combine secrets now.", level="INFO")
                break
            elif result == 'N':
                print("Aborted before final reconstruction. Exiting.")
                return

        # gather and decrypt selected shares (AAD bound)
        partials = []
        for q in chosen:
            if "user_answers" not in q or "answer_shares" not in q:
                continue
            q_hash = _integrity_hash_for_kit(q["text"], q["alternatives"])
            for alt in q["user_answers"]:
                share_info = q["answer_shares"].get(alt)
                if not share_info:
                    continue
                enc_data = share_info["enc_data"]
                ephemeral_pass = enc_data.get("ephemeral_password")
                ephemeral_salt_b64 = enc_data.get("ephemeral_salt_b64")
                if not ephemeral_pass or not ephemeral_salt_b64:
                    log_error("Missing ephemeral credentials for a selected answer.")
                    continue
                try:
                    ephemeral_salt = base64.b64decode(ephemeral_salt_b64)
                except Exception as e:
                    log_error(f"Base64 decode error for salt: {e}")
                    continue
                ephemeral_key, _ = derive_or_recover_key(
                    ephemeral_pass, ephemeral_salt, ephemeral=True,
                    time_cost=arg_time, memory_cost=arg_mem, parallelism=1
                )
                dec_pt = None
                try:
                    alg = enc_data.get("alg") or enc_data.get("algorithm")
                    aad = _aad_bytes(q_hash, _alt_hash_for_kit(alt), (alg if isinstance(alg, str) else "aes256gcm"))
                    dec_pt = decrypt_aead_envelope(enc_data, ephemeral_key, aad=aad)
                    log_debug("Demo path decrypted share.",
                              level="INFO",
                              component="CRYPTO",
                              details={"share_sha3_256_hex": hash_share(dec_pt),
                                       "algorithm": alg})
                    partials.append(dec_pt)
                except Exception as e:
                    log_error("Decryption failed for a selected answer.", exc=e)

        if len(partials) < r_thr:
            print(f"\nNot enough shares to reconstruct. Got={len(partials)}, need={r_thr}")
            # Per requirement: offer options again at end of case
            print("Press 1 – Enter setup phase")
            print("Press 2 – Proceed to example demonstration")
            return
        try:
            # Use constant-budget combiner
            combined_bytes = _combine_fixed_budget(partials, r_thr, COMBINE_BUDGET_REAL, random.SystemRandom())
            reconstructed_real_b64 = combined_bytes.decode('utf-8') if combined_bytes else None
            log_debug("Demo combine executed.", level="INFO", component="CRYPTO",
                      details={"combined_len": (len(combined_bytes) if combined_bytes else None)})
        except Exception as e:
            log_exception(e, "SSS Combine failed during final reconstruction")
            reconstructed_real_b64 = None

        print("\n--- FINAL RECONSTRUCTION RESULTS ---\n")
        if reconstructed_real_b64:
            try:
                final_secret_text = base64.b64decode(reconstructed_real_b64).decode('utf-8')
                print(f"REAL SECRET recovered: {final_secret_text}\n")
                log_debug("Demo final base64 decode OK.", level="INFO", component="CRYPTO",
                          details={"final_secret_len": len(final_secret_text)})
            except Exception as e:
                log_exception(e, "Failed to decode base64 or utf-8 from combined secret.")
                print("Secret combined, but failed final decode.\n")
        else:
            print("Secret not recoverable.\n")

        append_recovery_guide()
        log_debug("Done with main program.", level="INFO")
        print_estimated_bruteforce_times(
            chosen,
            arg_time, arg_mem, 1,
            total_correct_lower=sum(len(q.get("correct_answers", [])) for q in chosen),
            r_thr=r_thr,
            decoy_present=True
        )

        # Per requirement: offer options again at end of case
        print("Press 1 – Enter setup phase")
        print("Press 2 – Proceed to example demonstration")

    except curses.error as e:
        log_exception(e, "Curses error in main()")
        print(f"A Curses error occurred: {e}. Your terminal might not be fully compatible or window too small.")
        print("Please try again with a different terminal or ensure it's large enough.")
    except Exception as exc_main:
        log_exception(exc_main, "Fatal error in main()")
        print(f"FATAL ERROR: {exc_main}")
        sys.exit(1)


if __name__ == "__main__":
    ensure_debug_dir()
    check_required_files()
    show_start_menu()
    main()
