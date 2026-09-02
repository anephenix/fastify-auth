import { Auth } from "@anephenix/auth";
import { buildTotpCrypto } from "@anephenix/fastify-auth/core";

export const auth = new Auth({ passwordValidationRules: { minLength: 8 } });

export const totpCrypto = buildTotpCrypto({
	serviceName: "Test App",
	secretEncryptionKey:
		"a95aa3a63d690fa312dce593b889fe4bf20e55d53759f9ceefc1f7abb69a7150",
});
