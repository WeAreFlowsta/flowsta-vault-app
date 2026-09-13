/**
 * The ONE email rule for every place a user types their address into the
 * Vault (setup wizard, post-restore resend, conflict repair, change-email).
 * Mirrors `normalize_email` in src-tauri/src/commands.rs, which enforces the
 * same rule at the Rust boundary. The server hashes the lowercased form, so
 * an address stored any other way silently stops matching the account.
 */
export function normalizeEmail(raw: string): string {
  return raw.trim().toLowerCase();
}

export function isValidEmail(raw: string): boolean {
  const email = normalizeEmail(raw);
  const at = email.indexOf("@");
  if (at <= 0 || at !== email.lastIndexOf("@")) return false;
  const domain = email.slice(at + 1);
  if (!domain.includes(".") || domain.startsWith(".") || domain.endsWith(".")) return false;
  return !/\s/.test(email);
}

/** Two typed copies of an address agree once both are normalized. */
export function emailsMatch(a: string, b: string): boolean {
  return normalizeEmail(a) === normalizeEmail(b);
}

export const EMAIL_INVALID = "Please enter a valid email address.";
export const EMAIL_MISMATCH = "Email addresses don't match.";
