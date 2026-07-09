// Shared vault-password policy — used by every place the user CHOOSES a
// vault password (create, restore, phrase-migration, change password) and
// mirrored in Rust (commands.rs `validate_vault_password`) for enforcement.
//
// Policy (best-practice, NIST-800-63B-friendly — length can stand in for
// composition, no rigid "must have all four classes" rule):
//   • at least 10 characters
//   • AND either 3+ of the 4 character classes (lower/upper/digit/symbol)
//     OR 16+ characters (a real passphrase doesn't need symbol soup)
//   • AND not an obviously weak/common password or trivial pattern
//
// The vault password protects data at rest behind Argon2id, so the real
// risk is a weak/guessable password, not a missing symbol.

const MIN_LENGTH = 10;
const PASSPHRASE_LENGTH = 16;

// A small block-list of the most common weak passwords + Flowsta-obvious
// ones. Compared case-insensitively against the whole password.
const COMMON = new Set([
  "password", "passw0rd", "password1", "password12", "password123",
  "1234567890", "12345678", "123456789", "qwertyuiop", "qwerty123",
  "letmein", "welcome", "welcome1", "iloveyou", "admin123", "administrator",
  "changeme", "trustno1", "monkey123", "dragon123", "flowsta", "flowstavault",
  "flowsta123", "recoveryphrase", "vaultpassword", "0000000000", "1111111111",
]);

function classCount(pw: string): number {
  let n = 0;
  if (/[a-z]/.test(pw)) n++;
  if (/[A-Z]/.test(pw)) n++;
  if (/[0-9]/.test(pw)) n++;
  if (/[^a-zA-Z0-9]/.test(pw)) n++;
  return n;
}

// All-one-character, or a straight ascending/descending run of digits or
// letters ("123456...", "abcdef...", "987654...").
function isTrivialPattern(pw: string): boolean {
  if (pw.length < 4) return true;
  if (/^(.)\1+$/.test(pw)) return true; // all same char
  const lower = pw.toLowerCase();
  let asc = true, desc = true;
  for (let i = 1; i < lower.length; i++) {
    const d = lower.charCodeAt(i) - lower.charCodeAt(i - 1);
    if (d !== 1) asc = false;
    if (d !== -1) desc = false;
  }
  return asc || desc;
}

export interface PasswordCheck {
  /** Meets the minimum policy — gate submission on this. */
  valid: boolean;
  /** 0 = unacceptable, 1 = fair, 2 = good, 3 = strong (for the meter). */
  strength: 0 | 1 | 2 | 3;
  label: string;
  /** What to fix (invalid) or what would make it stronger (valid). */
  hint: string;
}

export function checkVaultPassword(pw: string): PasswordCheck {
  const len = pw.length;
  const classes = classCount(pw);

  if (len === 0) {
    return { valid: false, strength: 0, label: "", hint: "" };
  }
  if (len < MIN_LENGTH) {
    return {
      valid: false, strength: 0, label: "Too short",
      hint: `Use at least ${MIN_LENGTH} characters.`,
    };
  }
  if (COMMON.has(pw.toLowerCase()) || isTrivialPattern(pw)) {
    return {
      valid: false, strength: 0, label: "Too easy to guess",
      hint: "That's a common or predictable password — choose something unique.",
    };
  }
  const varietyOk = classes >= 3 || len >= PASSPHRASE_LENGTH;
  if (!varietyOk) {
    return {
      valid: false, strength: 0, label: "Too weak",
      hint: "Mix in upper- and lower-case, numbers, or symbols — or make it 16+ characters.",
    };
  }

  // Valid — grade it for the meter.
  const strong = len >= PASSPHRASE_LENGTH && classes >= 3;
  const good = len >= 12 || classes >= 4;
  if (strong) {
    return { valid: true, strength: 3, label: "Strong", hint: "" };
  }
  if (good) {
    return {
      valid: true, strength: 2, label: "Good",
      hint: "Longer is stronger — 16+ characters is ideal.",
    };
  }
  return {
    valid: true, strength: 1, label: "Fair",
    hint: "Add length or more character variety to strengthen it.",
  };
}
