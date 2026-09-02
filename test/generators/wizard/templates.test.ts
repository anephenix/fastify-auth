import { describe, expect, it } from "vitest";
import { authLibTemplate } from "../../../src/generators/wizard/authLibTemplate.js";
import { authRoutesTemplate } from "../../../src/generators/wizard/authRoutesTemplate.js";
import {
	indexTemplate,
	indexWiringInstructions,
} from "../../../src/generators/wizard/indexTemplate.js";
import {
	forgotPasswordModelTemplate,
	magicLinkModelTemplate,
	mfaTokenModelTemplate,
	recoveryCodeModelTemplate,
	sessionModelTemplate,
	smsCodeModelTemplate,
	userModelTemplate,
} from "../../../src/generators/wizard/modelTemplates.js";
import type { WizardSelections } from "../../../src/generators/wizard/types.js";

function selections(
	overrides: Partial<WizardSelections> = {},
): WizardSelections {
	return {
		password: false,
		magicLink: false,
		mfa: "none",
		forgotPassword: false,
		...overrides,
	};
}

describe("authLibTemplate", () => {
	it("only exports totpCrypto when mfa is totp", () => {
		expect(authLibTemplate(selections())).not.toContain("totpCrypto");
		expect(authLibTemplate(selections())).not.toContain("buildTotpCrypto");

		const withTotp = authLibTemplate(selections({ mfa: "totp" }));
		expect(withTotp).toContain("export const totpCrypto = buildTotpCrypto(");
		expect(withTotp).toContain(
			'import { buildTotpCrypto } from "@anephenix/fastify-auth/core";',
		);
	});

	it("does not export totpCrypto when mfa is sms", () => {
		const output = authLibTemplate(selections({ mfa: "sms" }));
		expect(output).not.toContain("totpCrypto");
		expect(output).not.toContain("buildTotpCrypto");
	});

	it("always exports the Auth instance", () => {
		expect(authLibTemplate(selections())).toContain(
			"export const auth = new Auth(",
		);
	});
});

describe("userModelTemplate", () => {
	it("omits MFA fields/relations and returns the plain user when mfa is none", () => {
		const output = userModelTemplate(selections());
		expect(output).not.toContain("mfa_totp_secret");
		expect(output).not.toContain("recoveryCodes");
		expect(output).not.toContain("sms_mfa_enabled");
		expect(output).toContain("return user;");
	});

	it("adds mfa_totp_secret, the recoveryCodes relation, and isUsingMFA when mfa is totp", () => {
		const output = userModelTemplate(selections({ mfa: "totp" }));
		expect(output).toContain("mfa_totp_secret!: string | null;");
		expect(output).toContain('import RecoveryCode from "./RecoveryCode.js";');
		expect(output).toContain("recoveryCodes:");
		expect(output).toContain("isUsingMFA: !!user.mfa_totp_secret");
	});

	it("adds sms_mfa_enabled and mobile_number, with no TOTP fields, when mfa is sms", () => {
		const output = userModelTemplate(selections({ mfa: "sms" }));
		expect(output).toContain("sms_mfa_enabled?: boolean;");
		expect(output).toContain("mobile_number?: string;");
		expect(output).not.toContain("mfa_totp_secret");
		expect(output).not.toContain("recoveryCodes");
		expect(output).toContain("return user;");
	});

	it("only adds updatePassword when forgotPassword is selected", () => {
		expect(userModelTemplate(selections())).not.toContain("updatePassword");
		expect(userModelTemplate(selections({ forgotPassword: true }))).toContain(
			"async updatePassword(password: string)",
		);
	});
});

describe("other model templates", () => {
	it("sessionModelTemplate defines tableName and token helpers", () => {
		const output = sessionModelTemplate();
		expect(output).toContain('return "sessions";');
		expect(output).toContain("static generateTokens()");
		expect(output).toContain("accessTokenHasExpired()");
	});

	it("magicLinkModelTemplate defines generateTokens and verifyTokenAndCode", () => {
		const output = magicLinkModelTemplate();
		expect(output).toContain("static async generateTokens()");
		expect(output).toContain("static async verifyTokenAndCode(");
	});

	it("mfaTokenModelTemplate defines the expected fields", () => {
		const output = mfaTokenModelTemplate();
		expect(output).toContain('return "mfa_tokens";');
		expect(output).toContain("number_of_attempts!: number;");
	});

	it("recoveryCodeModelTemplate hashes the code before insert", () => {
		const output = recoveryCodeModelTemplate();
		expect(output).toContain("async $beforeInsert()");
		expect(output).toContain("static generateCodes()");
		expect(output).toContain("static async checkForRecoveryCodeAndConsume(");
	});

	it("forgotPasswordModelTemplate defines markAsUsed", () => {
		const output = forgotPasswordModelTemplate();
		expect(output).toContain("async markAsUsed()");
	});

	it("smsCodeModelTemplate matches the ISmsCodeModel contract", () => {
		const output = smsCodeModelTemplate();
		expect(output).toContain('return "sms_codes";');
		expect(output).toContain("codeHasExpired(): boolean");
		expect(output).toContain(
			"async verifyCode(code: string): Promise<boolean>",
		);
	});
});

describe("authRoutesTemplate", () => {
	it("password-only: has signup/login with no MFA branch, no magic-links/totp/forgot-password routes", () => {
		const output = authRoutesTemplate(selections({ password: true }));
		expect(output).toContain('app.post("/signup"');
		expect(output).toContain('app.post("/login"');
		expect(output).not.toContain("issueMfaChallenge");
		expect(output).not.toContain('"/magic-links"');
		expect(output).not.toContain('"/login/mfa"');
		expect(output).not.toContain('"/forgot-password"');
		// session management is always present
		expect(output).toContain('"/profile"');
		expect(output).toContain('"/auth/refresh"');
	});

	it("password + totp: /login gets an MFA branch and /login/mfa + /auth/mfa/* are registered", () => {
		const output = authRoutesTemplate(
			selections({ password: true, mfa: "totp" }),
		);
		expect(output).toContain("if (user.isUsingMFA)");
		expect(output).toContain('"/login/mfa"');
		expect(output).toContain('"/auth/mfa/setup"');
		expect(output).toContain('"/auth/mfa/recovery-codes"');
		expect(output).toContain('"/auth/mfa/disable-with-recovery-code"');
		expect(output).not.toContain("/auth/mfa/sms/");
	});

	it("password + sms: /login gets an SMS MFA branch and /login/mfa + /auth/mfa/sms/* are registered", () => {
		const output = authRoutesTemplate(
			selections({ password: true, mfa: "sms" }),
		);
		expect(output).toContain("if (user.sms_mfa_enabled)");
		expect(output).toContain("auth.generateSmsCode()");
		expect(output).toContain('"/login/mfa"');
		expect(output).toContain('"/auth/mfa/sms/setup"');
		expect(output).toContain('"/auth/mfa/sms/disable"');
		// no TOTP-only imports/routes leak in
		expect(output).not.toContain("issueMfaChallenge");
		expect(output).not.toContain("otplib");
		expect(output).not.toContain('"/auth/mfa/setup"');
		expect(output).not.toContain('"/auth/mfa/recovery-codes"');
	});

	it("magicLink + totp: /magic-links/verify gets the MFA gate check", () => {
		const output = authRoutesTemplate(
			selections({ magicLink: true, mfa: "totp" }),
		);
		expect(output).toContain('"/magic-links/verify"');
		expect(output).toContain("if (user.mfa_totp_secret)");
		expect(output).toContain("issueMfaChallenge(MfaToken, auth, user.id)");
		// no password selected, so no signup/login
		expect(output).not.toContain('app.post("/signup"');
		expect(output).not.toContain('app.post("/login"');
	});

	it("magicLink + sms: /magic-links/verify gets the SMS MFA gate check", () => {
		const output = authRoutesTemplate(
			selections({ magicLink: true, mfa: "sms" }),
		);
		expect(output).toContain('"/magic-links/verify"');
		expect(output).toContain("if (user.sms_mfa_enabled)");
		expect(output).toContain("SmsCode.query().insert(");
		expect(output).not.toContain('app.post("/signup"');
		expect(output).not.toContain('app.post("/login"');
	});

	it("magicLink without any MFA: /magic-links/verify has no MFA gate", () => {
		const output = authRoutesTemplate(selections({ magicLink: true }));
		expect(output).toContain('"/magic-links/verify"');
		expect(output).not.toContain("mfa_totp_secret");
		expect(output).not.toContain("sms_mfa_enabled");
	});

	it("forgotPassword adds the reset-password routes and imports validateResetToken", () => {
		const output = authRoutesTemplate(
			selections({ password: true, forgotPassword: true }),
		);
		expect(output).toContain('"/forgot-password"');
		expect(output).toContain('"/reset-password/:selector"');
		expect(output).toContain("validateResetToken");
		expect(output).toContain("await user.updatePassword(password);");
	});

	it("the full combo registers every route (totp)", () => {
		const output = authRoutesTemplate(
			selections({
				password: true,
				magicLink: true,
				mfa: "totp",
				forgotPassword: true,
			}),
		);
		for (const route of [
			'"/signup"',
			'"/login"',
			'"/magic-links"',
			'"/magic-links/verify"',
			'"/login/mfa"',
			'"/auth/mfa/setup"',
			'"/forgot-password"',
			'"/reset-password"',
			'"/profile"',
			'"/logout"',
			'"/auth/refresh"',
			'"/sessions"',
			'"/sessions/:id"',
		]) {
			expect(output).toContain(route);
		}
	});

	it("the full combo registers every route (sms)", () => {
		const output = authRoutesTemplate(
			selections({
				password: true,
				magicLink: true,
				mfa: "sms",
				forgotPassword: true,
			}),
		);
		for (const route of [
			'"/signup"',
			'"/login"',
			'"/magic-links"',
			'"/magic-links/verify"',
			'"/login/mfa"',
			'"/auth/mfa/sms/setup"',
			'"/auth/mfa/sms/disable"',
			'"/forgot-password"',
			'"/reset-password"',
			'"/profile"',
			'"/logout"',
			'"/auth/refresh"',
			'"/sessions"',
			'"/sessions/:id"',
		]) {
			expect(output).toContain(route);
		}
		expect(output).not.toContain('"/auth/mfa/setup"');
		expect(output).not.toContain("issueMfaChallenge");
	});
});

describe("indexTemplate", () => {
	it("registers the generated auth routes and starts listening", () => {
		const output = indexTemplate();
		expect(output).toContain(
			'import { registerAuthRoutes } from "./routes/auth.js";',
		);
		expect(output).toContain("registerAuthRoutes(app);");
		expect(output).toContain("app.listen(");
	});
});

describe("indexWiringInstructions", () => {
	it("returns the two lines needed to wire up an existing index.ts", () => {
		const output = indexWiringInstructions();
		expect(output).toContain(
			'import { registerAuthRoutes } from "./routes/auth.js";',
		);
		expect(output).toContain("registerAuthRoutes(app);");
	});
});
