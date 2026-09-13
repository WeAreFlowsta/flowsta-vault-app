/**
 * Only ever put an https URL (or a data:image/ URI) into an <img src> that
 * came from outside the app - developer-supplied app logos arrive through
 * the API. An <img> cannot run script, but a javascript:/file:/http: source
 * is still a leak or a mixed-content hole. Same rule as the Website's
 * sanitizeImageSrc.
 */
export function sanitizeImageUrl(value: unknown): string | null {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) return null;
  if (/^data:image\/(png|jpeg|jpg|gif|webp|svg\+xml);base64,/i.test(value)) return value;
  try {
    const u = new URL(value);
    return u.protocol === "https:" ? u.toString() : null;
  } catch {
    return null;
  }
}
