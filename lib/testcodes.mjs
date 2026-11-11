// Test addresses for the mail check: a short code a human reads off a screen, types into
// another form, and sometimes spells out loud. So the alphabet is Crockford's Base32 —
// ten digits plus 22 letters with the confusable ones removed: I and L (they look like 1)
// and O (looks like 0). U is dropped too, because it trades places with V.
//
// Excluding the vowels has a side benefit worth knowing about: six symbols from this
// alphabet cannot spell most of the words you would rather not hand out as an address.
//
// Six characters is 32^6 = 1,073,741,824 combinations — about a billion. Random assignment
// still has to be claimed atomically (see mailcheck-probe/README.md), but at that size the
// birthday problem stops mattering: ~500 codes live at once is a 0.00002% chance that any
// two collide, where six digits gave roughly 1%.
//
// A code is an *address*, not a credential. Anyone who can guess it can send to it, and a
// billion combinations is only a billion reads. The record behind it still needs its own
// unguessable read token.

export const CODE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export const CODE_LENGTH = 6;

// 32 symbols = 5 bits each, so six characters are exactly 30 bits. Drawing a whole number
// of bits is what makes this unbiased — a plain `% 32**6` on a 32-bit integer would
// over-represent the low half of the space by ~23%.
const BITS_PER_CHAR = 5;

/**
 * Generate a code. `fill` exists so tests can supply their own randomness; production
 * always uses the CSPRNG.
 */
export function randomCode(fill) {
  const bytes = new Uint8Array(4);
  if (typeof fill === 'function') fill(bytes);
  else globalThis.crypto.getRandomValues(bytes);
  // Drop the 2 bits that do not fit in a 5-bit index, leaving 30 unbiased bits.
  const raw = ((((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0) >>> 2);
  let out = '';
  for (let i = CODE_LENGTH - 1; i >= 0; i--) out += CODE_ALPHABET[(raw >>> (i * BITS_PER_CHAR)) & 31];
  return out;
}

/**
 * Canonical form of a code a human typed. Email local parts are case-sensitive in theory
 * and case-insensitive in practice (Google, Microsoft and most filters fold them), so we
 * generate and compare folded: never let the address a user retyped decide the lookup.
 * Separators are stripped, and the three characters we deliberately excluded are mapped
 * back to what they were almost certainly meant to be.
 *
 * That last part has a consequence: the fold is lossy in one direction only, so an
 * unrelated word can normalize into a syntactically valid code (`office@` -> 0FFICE).
 * Nothing may be stored for a code that was never issued — check the registry before
 * writing, or stray mail to any word-address on the domain lands on a live test's record.
 */
export function normalizeCode(input) {
  return String(input == null ? '' : input)
    .trim().toUpperCase()
    .replace(/[-_\s.]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1')
    .replace(/U/g, 'V');
}

/** True when `input` names a code exactly as generated, after folding. */
export function isCode(input) {
  const n = normalizeCode(input);
  if (n.length !== CODE_LENGTH) return false;
  for (let i = 0; i < n.length; i++) if (CODE_ALPHABET.indexOf(n[i]) === -1) return false;
  return true;
}

/**
 * The code inside a recipient address. Works for both delivery schemes: a bare
 * `4K2M9X@domain` (catch-all on an apex) and `probe+4K2M9X@domain` (subaddressing on a
 * subdomain). Whichever side of the `+` it lands on, the part that reads as a code wins —
 * guessing "first segment" would hand back the literal word `probe`.
 */
export function codeFromAddress(address) {
  const parts = String(address || '').split('@')[0].split('+').map(normalizeCode);
  if (!parts.length) return '';
  return parts.find(isCode) || parts[0];
}
