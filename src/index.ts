import type { FastifyInstance, FastifyPluginAsync } from "fastify";
import fp from "fastify-plugin";
import { registerForgottenPasswordStrategy } from "./strategies/forgotten-password.js";
import { registerMagicLinksStrategy } from "./strategies/magic-links.js";
import { registerMfaSmsStrategy } from "./strategies/mfa-sms.js";
import { registerMfaTotpStrategy } from "./strategies/mfa-totp.js";
import { registerSessionsStrategy } from "./strategies/sessions.js";
import type { AuthFastifyPluginOptions } from "./types.js";

/**
 * @anephenix/auth-fastify
 *
 * A Fastify plugin that mounts authentication routes for a chosen strategy.
 *
 * Usage:
 *
 * ```ts
 * import authPlugin from '@anephenix/auth-fastify';
 *
 * app.register(authPlugin, {
 *   strategy: 'sessions',
 *   auth,              // Auth instance from @anephenix/auth
 *   models: { User, Session },
 * });
 * ```
 *
 * Strategies
 * ----------
 * 'sessions'           – signup / login / logout / refresh / session management
 * 'magic-links'        – passwordless email login
 * 'mfa-sms'            – password + SMS one-time code
 * 'mfa-totp'           – password + TOTP authenticator app
 * 'forgotten-password' – forgot-password / reset-password flow
 *
 * See each strategy file in src/strategies/ for the full route list and
 * required models / hooks.
 */
const authFastifyPlugin: FastifyPluginAsync<AuthFastifyPluginOptions> = async (
	app: FastifyInstance,
	opts: AuthFastifyPluginOptions,
) => {
	switch (opts.strategy) {
		case "sessions":
			registerSessionsStrategy(app, opts);
			break;
		case "magic-links":
			registerMagicLinksStrategy(app, opts);
			break;
		case "mfa-sms":
			registerMfaSmsStrategy(app, opts);
			break;
		case "mfa-totp":
			registerMfaTotpStrategy(app, opts);
			break;
		case "forgotten-password":
			registerForgottenPasswordStrategy(app, opts);
			break;
		default: {
			const _exhaustive: never = opts.strategy;
			throw new Error(`Unknown strategy: ${_exhaustive}`);
		}
	}
};

export default fp(authFastifyPlugin, {
	name: "@anephenix/auth-fastify",
	fastify: "5.x",
});

// Re-export types so consumers can import everything from one place
export type {
	AuthFastifyPluginOptions,
	AuthFastifyModels,
	AuthFastifyHooks,
	TotpOptions,
	Strategy,
	MagicLinkCreatedParams,
	SmsCodeCreatedParams,
	ForgotPasswordRequestedParams,
	IUserModel,
	IUserModelStatic,
	ISessionModel,
	ISessionModelStatic,
	IMagicLinkModel,
	IMagicLinkModelStatic,
	ISmsCodeModel,
	ISmsCodeModelStatic,
	IMfaTokenModel,
	IMfaTokenModelStatic,
	IRecoveryCodeModel,
	IRecoveryCodeModelStatic,
	IForgotPasswordModel,
	IForgotPasswordModelStatic,
} from "./types.js";
