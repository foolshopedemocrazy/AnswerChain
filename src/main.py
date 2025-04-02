################################################################################
# START OF FILE: "main.py"
################################################################################

"""
FILENAME:
"main.py"

PERMANENT FILE DESCRIPTION – DO NOT REMOVE OR MODIFY
...
(unmodified large multiline comment preserved)
"""

#!/usr/bin/env python3
"""
Restored CLI flow, plus ephemeral partial encryption.
If fewer than 10 correct => ask user to (E) re-edit or (N) abort.
"""

import os
import sys
import json
import base64
import curses
import asyncio
import secrets
import threading
from random import choice
from pathlib import Path

from modules.debug_utils import ensure_debug_dir, log_debug, log_error, append_recovery_guide
from modules.security_utils import validate_question, hash_share, verify_share_hash
from modules.input_utils import get_valid_int, get_nonempty_secret
from modules.ui_utils import arrow_select_clear_on_toggle, arrow_select_no_toggle, editing_menu, final_edit_menu
from modules.split_utils import split_secret_and_dummy
from modules.SSS import sss_combine

# from CipherForge
from CipherForge import (
    derive_or_recover_key,
    encrypt_aes256gcm,
    decrypt_aes256gcm,
    encrypt_chacha20poly1305,
    decrypt_chacha20poly1305
)

SRC_DIR = Path(__file__).parent.resolve()
QUESTIONS_FILE_NAME = "example_questions25.json"
QUESTIONS_PATH = SRC_DIR / QUESTIONS_FILE_NAME

chosen_lock = threading.Lock()
combine_lock = threading.Lock()


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
        "SSS.py",
        "ui_utils.py"
    ]
    for f in needed_in_modules:
        if not (modules_path / f).exists():
            missing.append(f)

    if missing:
        print("ERROR - Missing files:", missing)
        sys.exit(1)


def prompt_argon2_parameters():
    print("\n--- Argon2id Parameter Setup ---")
    choice_ = input("Use (n) for normal defaults or (e) for custom edit? [n/e] ").strip().lower()
    if choice_ != 'e':
        print("Using DEFAULT Argon2id parameters: time_cost=3, memory_cost=65536, parallelism=4")
        return (3, 65536, 4)
    else:
        print("Enter custom Argon2id parameters:")
        tc = get_valid_int("time_cost (1..10)? ", 1, 10)
        mc = get_valid_int("memory_cost (8192..1048576)? ", 8192, 1048576)
        pl = get_valid_int("parallelism (1..32)? ", 1, 32)
        print(f"Using CUSTOM Argon2id parameters: time_cost={tc}, memory_cost={mc}, parallelism={pl}")
        return (tc, mc, pl)


def main():
    print("[INFO] Launching main.py...")

    ensure_debug_dir()
    check_required_files()
    log_debug("Starting program...", level="INFO")

    # 1) Load question data
    if not QUESTIONS_PATH.exists():
        print(f"Error: question file not found: {QUESTIONS_PATH}")
        return
    try:
        with open(QUESTIONS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        valid_data = [q for q in data if validate_question(q)]
    except Exception as e:
        log_error("Error loading question file", e)
        return
    if not valid_data:
        print("No valid questions found. Aborting.")
        return

    amt = get_valid_int(f"How many questions? (1..{len(valid_data)}): ", 1, len(valid_data))
    with chosen_lock:
        chosen = valid_data[:amt]

    # 2) arrow-select each question
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
        qdict["is_critical"] = bool(qtype)

    # 3) editing menu
    while True:
        done = editing_menu(chosen)
        if done:
            break

    # Tally correct vs incorrect
    correct_map = []
    incorrect_map = []
    for q in chosen:
        cset = set(q.get("correct_answers", []))
        for alt in q["user_answers"]:
            if alt in cset:
                correct_map.append((q, alt))
            else:
                incorrect_map.append((q, alt))

    c_count = len(correct_map)
    i_count = len(incorrect_map)
    print(f"\nOverall Tally => Correct picks={c_count}, Incorrect={i_count}.\n")

    # If fewer than 10 correct => re-edit or abort
    while True:
        if c_count < 10:
            print("Fewer than 10 correct => re-edit or abort.")
            answer = input("Choice (E/N)? ").strip().upper()
            if answer == 'E':
                # go back to editing
                re_done = editing_menu(chosen)
                if re_done:
                    # re-check picks
                    correct_map = []
                    incorrect_map = []
                    for q in chosen:
                        cset = set(q.get("correct_answers", []))
                        for alt in q["user_answers"]:
                            if alt in cset:
                                correct_map.append((q, alt))
                            else:
                                incorrect_map.append((q, alt))
                    c_count = len(correct_map)
                    i_count = len(incorrect_map)
                    print(f"\nNEW Tally => Correct picks={c_count}, Incorrect={i_count}.\n")
                    continue
                else:
                    # user may have re-edited multiple times
                    continue
            elif answer == 'N':
                print("Aborting.")
                return
            else:
                print("Invalid choice. Type E or N.\n")
                continue
        else:
            # c_count >= 10 => proceed
            break

    # Ask threshold from 10.. c_count
    def get_threshold(low, high):
        while True:
            raw = input(f"Real threshold ({low}..{high}): ")
            try:
                val = int(raw)
                if val >= low and val <= high:
                    return val
            except:
                pass
            print(f"Must be {low}..{high}.\n")

    r_thr = get_threshold(10, c_count)
    print(f"[INFO] Must pick >= {r_thr} correct picks to reconstruct real secret.\n")

    # 4) Real secret
    real_secret = get_nonempty_secret("Enter REAL secret: ")
    real_b64 = base64.b64encode(real_secret.encode()).decode()

    # 5) Pad & Argon2
    print("Custom PAD size? Press ENTER to use default=128.")
    try_pad = input("PAD >= length of base64 secret? ").strip()
    if try_pad:
        try:
            user_pad = int(try_pad)
            if user_pad < len(real_b64):
                print("Too small, using 128.")
                user_pad = 128
        except:
            print("Invalid, using 128.")
            user_pad = 128
    else:
        user_pad = 128

    arg_time, arg_mem, arg_par = prompt_argon2_parameters()

    # 6) SSS split
    try:
        real_shares, dummy_shares = asyncio.run(
            split_secret_and_dummy(
                real_b64.encode(),
                c_count,
                i_count,
                r_thr,
                pad=user_pad
            )
        )
    except Exception as e:
        log_error("Error splitting secret", e)
        return

    # partial encryption approach
    def split_into_95_5(full_bytes: bytes):
        length = len(full_bytes)
        five_p = max(1, (length * 5) // 100)
        if five_p < 1:
            five_p = 1
        part5 = full_bytes[-five_p:]
        part95 = full_bytes[:-five_p]
        return (part95, part5)

    def ephemeral_encrypt(data: bytes) -> dict:
        ephemeral_pass = base64.b64encode(os.urandom(12)).decode()
        ephemeral_salt = os.urandom(16)
        ephemeral_key, ephemeral_salt_used = derive_or_recover_key(
            ephemeral_pass,
            ephemeral_salt,
            ephemeral=True,
            time_cost=arg_time,
            memory_cost=arg_mem,
            parallelism=arg_par
        )
        alg_options = ["chacha20poly1305", "aes256gcm"]
        chosen_alg = choice(alg_options)
        if chosen_alg == "chacha20poly1305":
            enc_obj = encrypt_chacha20poly1305(data, ephemeral_key,
                                               ephemeral_pass=ephemeral_pass,
                                               ephemeral_salt=ephemeral_salt_used)
        else:
            enc_obj = encrypt_aes256gcm(data, ephemeral_key,
                                        ephemeral_pass=ephemeral_pass,
                                        ephemeral_salt=ephemeral_salt_used)
        enc_obj["ephemeral_password"] = ephemeral_pass
        enc_obj["ephemeral_salt_b64"] = base64.b64encode(ephemeral_salt_used).decode()
        enc_obj["algorithm"] = chosen_alg
        return enc_obj

    # partition correct picks => standard or critical
    std_correct = []
    crit_correct = []
    for (q, alt) in correct_map:
        if q["is_critical"]:
            crit_correct.append((q, alt))
        else:
            std_correct.append((q, alt))

    # partition incorrect picks => standard or critical
    std_incorrect = []
    crit_incorrect = []
    for (q, alt) in incorrect_map:
        if q["is_critical"]:
            crit_incorrect.append((q, alt))
        else:
            std_incorrect.append((q, alt))

    used_pairs = min(len(std_correct), len(crit_correct), len(real_shares))
    used_pairs_dummy = min(len(std_incorrect), len(crit_incorrect), len(dummy_shares))

    # Real shares => ephemeral encrypt => attach to standard + critical picks
    for i in range(used_pairs):
        share = real_shares[i]
        (part95, part5) = split_into_95_5(share)
        (q_s, alt_s) = std_correct[i]
        enc_95 = ephemeral_encrypt(part95)
        q_s.setdefault("answer_shares", {})
        q_s["answer_shares"][alt_s] = {
            "is_real": True,
            "which_part": "95%",
            "enc_data": enc_95,
            "hash_": hash_share(share)
        }
        (q_c, alt_c) = crit_correct[i]
        enc_5 = ephemeral_encrypt(part5)
        q_c.setdefault("answer_shares", {})
        q_c["answer_shares"][alt_c] = {
            "is_real": True,
            "which_part": "5%",
            "enc_data": enc_5,
            "hash_": hash_share(share)
        }
        for j in range(len(share)):
            share[j] = 0

    # Dummy shares
    for i in range(used_pairs_dummy):
        share = dummy_shares[i]
        (part95, part5) = split_into_95_5(share)
        (q_s, alt_s) = std_incorrect[i]
        enc_95 = ephemeral_encrypt(part95)
        q_s.setdefault("answer_shares", {})
        q_s["answer_shares"][alt_s] = {
            "is_real": False,
            "which_part": "95%",
            "enc_data": enc_95,
            "hash_": hash_share(share)
        }
        (q_c, alt_c) = crit_incorrect[i]
        enc_5 = ephemeral_encrypt(part5)
        q_c.setdefault("answer_shares", {})
        q_c["answer_shares"][alt_c] = {
            "is_real": False,
            "which_part": "5%",
            "enc_data": enc_5,
            "hash_": hash_share(share)
        }
        for j in range(len(share)):
            share[j] = 0

    for i in range(used_pairs, len(real_shares)):
        for j in range(len(real_shares[i])):
            real_shares[i][j] = 0
    for i in range(used_pairs_dummy, len(dummy_shares)):
        for j in range(len(dummy_shares[i])):
            dummy_shares[i][j] = 0

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
            print("Aborted. Exiting.")
            return

    # Reconstruct partial data
    partials_map = {}
    for q in chosen:
        for alt in q["user_answers"]:
            info = q.get("answer_shares", {}).get(alt)
            if not info:
                continue
            enc_data = info["enc_data"]
            ephemeral_pass = enc_data["ephemeral_password"]
            ephemeral_salt_b64 = enc_data["ephemeral_salt_b64"]
            ephemeral_salt = base64.b64decode(ephemeral_salt_b64)
            ephemeral_key, _ = derive_or_recover_key(
                ephemeral_pass,
                ephemeral_salt,
                ephemeral=True,
                time_cost=arg_time,
                memory_cost=arg_mem,
                parallelism=arg_par
            )
            if enc_data["alg"] == "chacha20poly1305":
                dec_pt = decrypt_chacha20poly1305(enc_data, ephemeral_key)
            else:
                dec_pt = decrypt_aes256gcm(enc_data, ephemeral_key)

            h = info["hash_"]
            is_real = info["is_real"]
            wpart = info["which_part"]
            partials_map.setdefault(h, {"is_real": is_real, "95%": None, "5%": None})
            partials_map[h][wpart] = dec_pt

    recovered_shares = []
    for h, entry in partials_map.items():
        if not entry["is_real"]:
            continue
        if entry["95%"] is not None and entry["5%"] is not None:
            full_share = entry["95%"] + entry["5%"]
            if verify_share_hash(full_share, h):
                recovered_shares.append(full_share)

    if len(recovered_shares) < r_thr:
        print(f"Not enough real partial shares => reconstruct fail. Found={len(recovered_shares)}, threshold={r_thr}")
        return

    final_picks = recovered_shares[:r_thr]
    reconstructed_real = None
    try:
        combined = asyncio.run(sss_combine(final_picks))
        try:
            dec_real = base64.b64decode(combined).decode()
            reconstructed_real = dec_real
        except Exception as e:
            reconstructed_real = f"<Decode error: {e}>"
    except Exception as e:
        log_error("Combine fail", e)

    print("\n--- FINAL RECONSTRUCTION RESULTS ---\n")
    if reconstructed_real and not reconstructed_real.startswith("<"):
        print(f"REAL SECRET recovered: {reconstructed_real}\n")
    else:
        print("Secret not recoverable.\n")

    print("""
--- Steps to manually reconstruct (if not done above) ---
1. Identify correct standard & critical picks and ephemeral-encrypted partials.
2. Decrypt each 95% chunk + 5% chunk, combine => full share.
3. Combine enough real shares => sss_combine => base64-decode final secret.
""")

    append_recovery_guide()
    log_debug("Done with main program.", level="INFO")


if __name__ == "__main__":
    main()

################################################################################
# END OF FILE: "main.py"
################################################################################
