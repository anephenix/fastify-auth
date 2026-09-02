export type MfaMethod = "none" | "totp" | "sms";

export type WizardSelections = {
	password: boolean;
	magicLink: boolean;
	mfa: MfaMethod;
	forgotPassword: boolean;
};
