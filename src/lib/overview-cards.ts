// The Backups card's number. (The rules for the device card and the email
// question moved to ./device-rules with the 1.8.0 device design.)

/** The Backups card's number: the backups made on this device plus the
 *  copies kept of the other devices', or null until BOTH are known. The two
 *  load separately, and a partial sum flashed the smaller number on every
 *  return to the Overview (10-29: 1,815 or 8 for a moment, then 1,823). */
export function backupsTotal(made: number | null, kept: number | null): number | null {
  return made === null || kept === null ? null : made + kept;
}
