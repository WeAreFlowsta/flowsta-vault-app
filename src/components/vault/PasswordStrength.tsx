import { component$ } from "@builder.io/qwik";
import { checkVaultPassword } from "~/lib/password-strength";

interface Props {
  password: string;
}

/** Live strength meter + hint under a vault-password field. Renders nothing
 *  for an empty field. Uses the shared `checkVaultPassword` policy. */
export const PasswordStrength = component$<Props>(({ password }) => {
  if (!password) return null;
  const check = checkVaultPassword(password);

  const barColor = !check.valid
    ? "bg-red-500"
    : check.strength >= 3
      ? "bg-green-500"
      : check.strength === 2
        ? "bg-amber-400"
        : "bg-yellow-500";
  const textColor = !check.valid
    ? "text-red-400"
    : check.strength >= 3
      ? "text-green-400"
      : "text-amber-300";
  // Filled segments: invalid = 1 (red), fair/good/strong = 1/2/3 of 3.
  const filled = check.valid ? check.strength : 1;

  return (
    <div class="mb-3">
      <div class="mb-1 flex gap-1">
        {[1, 2, 3].map((seg) => (
          <div
            key={seg}
            class={{
              "h-1 flex-1 rounded-full": true,
              [barColor]: seg <= filled,
              "bg-gray-700": seg > filled,
            }}
          />
        ))}
      </div>
      {check.label && (
        <p class={["text-xs", textColor]}>
          {check.label}
          {check.hint ? <span class="text-gray-500"> — {check.hint}</span> : null}
        </p>
      )}
    </div>
  );
});
