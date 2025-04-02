################################################################################
# START OF FILE: "input_utils.py"
################################################################################

"""
FILENAME:
"input_utils.py"

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
Handles user integer input & secret input with getpass.
Logs the integer input in plain to ensure everything needed is in logs.
"""

import getpass
from modules.debug_utils import log_debug
from modules.security_utils import sanitize_input, normalize_text


def get_valid_int(prompt, low, high):
    while True:
        print(prompt, end="", flush=True)
        val = input()
        try:
            num = int(val)
            if low <= num <= high:
                log_debug(f"User int input valid: {num}", level="INFO")
                return num
            else:
                print(f"Must be {low}..{high}")
        except:
            print("Invalid integer input.")


def get_nonempty_secret(prompt):
    while True:
        s = getpass.getpass(prompt)
        s = sanitize_input(normalize_text(s))
        if s.strip():
            if len(s) > 256:
                s = s[:256]
            return s
        print("Cannot be empty.")
        log_debug("Empty secret => re-prompt", level="WARNING")

################################################################################
# END OF FILE: "input_utils.py"
################################################################################
