import type { WizardSelections } from "./types.js";

/*
  Constructs the shared @anephenix/auth Auth instance (and, if TOTP was
  selected, the TotpCrypto pair) that both the generated models and
  routes/auth.ts import - avoids each generated file constructing its own
  Auth instance, and avoids a circular import between models/User.ts and
  routes/auth.ts.
*/
export function authLibTemplate({ totp }: WizardSelections): string {
	const totpImport = totp
		? `import { buildTotpCrypto } from "@anephenix/fastify-auth/core";\n`
		: "";

	const totpExport = totp
		? `
// TOTP secrets are encrypted at rest - generate a key with:
//   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
// and set it as TOTP_SECRET_ENCRYPTION_KEY in your environment.
export const totpCrypto = buildTotpCrypto({
	serviceName: "My App",
	secretEncryptionKey: process.env.TOTP_SECRET_ENCRYPTION_KEY as string,
});
`
		: "";

	return `import { Auth } from "@anephenix/auth";
${totpImport}
// TODO: tune password validation rules, token expiry, etc. for your app -
// see https://github.com/anephenix/auth for all Auth options.
export const auth = new Auth({
	passwordValidationRules: { minLength: 8 },
});
${totpExport}`;
}
