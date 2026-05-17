/**
 * Human-readable labels for signing DNA enum variants.
 *
 * DNA stores these in PascalCase ("AllRightsReserved", "Assisted",
 * "Generated"). The signing form / amend form dropdowns use kebab/
 * snake-case option values ("all-rights-reserved", "assisted") and
 * display labels ("Copyright protected", "Part AI Generated").
 *
 * Use these helpers when rendering badge pills on signature cards so
 * users see meaningful labels instead of raw enum names. Pass-through
 * for unknown values keeps things forward-compatible with future DNA
 * variants.
 */

export function formatLicense(value: string | null | undefined): string {
  if (!value) return "";
  switch (value) {
    case "AllRightsReserved":
    case "all-rights-reserved":
      return "All rights reserved";
    case "CC0":
    case "cc0":
      return "CC0";
    case "CCBY":
    case "cc-by":
      return "CC BY";
    case "CCBYSA":
    case "cc-by-sa":
      return "CC BY-SA";
    case "CCBYNC":
    case "cc-by-nc":
      return "CC BY-NC";
    case "CCBYNCSA":
    case "cc-by-nc-sa":
      return "CC BY-NC-SA";
    case "MIT":
    case "mit":
      return "MIT";
    case "Apache2":
    case "apache-2":
      return "Apache 2.0";
    case "GPL3":
    case "gpl-3":
      return "GPL 3.0";
    default:
      return value;
  }
}

export function formatAiGeneration(value: string | null | undefined): string {
  if (!value) return "";
  switch (value) {
    case "None":
    case "none":
      return "No AI";
    case "Assisted":
    case "assisted":
      return "AI assisted";
    case "Generated":
    case "generated":
      return "AI generated";
    default:
      return value;
  }
}
