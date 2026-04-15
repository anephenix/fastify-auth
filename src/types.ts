import type { Auth } from "@anephenix/auth";
// Import @fastify/cookie types so that request.cookies, reply.setCookie and
// reply.clearCookie are available throughout the plugin. The consuming app is
// responsible for registering @fastify/cookie before mounting this plugin.
import "@fastify/cookie";
import type { FastifyRequest } from "fastify";

// ─── Strategy names ───────────────────────────────────────────────────────────

export type Strategy =
	| "sessions"
	| "magic-links"
	| "mfa-sms"
	| "mfa-totp"
	| "forgotten-password";

// ─── Minimal model interfaces ─────────────────────────────────────────────────
//
// The plugin calls a fixed set of static and instance methods on each model.
// These interfaces describe exactly what the plugin needs – nothing more.
// Your models can have additional fields / methods; they just need to satisfy
// at least this contract.

/** A query-builder-like object returned by Model.query() / $query() / $relatedQuery(). */
// biome-ignore lint/suspicious/noExplicitAny: query builders vary by ORM
export type QueryBuilder = any;

export interface IUserModel {
	id: number | string;
	username?: string;
	email?: string;
	mobile_number?: string;
	mfa_totp_secret?: string | null;
	$query(): QueryBuilder;
	$relatedQuery(relation: string): QueryBuilder;
}

export interface IUserModelStatic {
	new (): IUserModel;
	query(): QueryBuilder;
	authenticate(params: {
		identifier: string;
		password: string;
	}): Promise<IUserModel & { isUsingMFA?: boolean }>;
}

export interface ISessionModel {
	id: number | string;
	user_id: number | string;
	access_token: string;
	refresh_token: string;
	access_token_expires_at: string;
	refresh_token_expires_at: string;
	user_agent?: string;
	ip_address?: string;
	accessTokenHasExpired(): boolean;
	refreshTokenHasExpired(): boolean;
	$query(): QueryBuilder;
	$relatedQuery(relation: string): QueryBuilder;
}

export interface ISessionModelStatic {
	new (): ISessionModel;
	query(): QueryBuilder;
	generateTokens(): {
		access_token: string;
		access_token_expires_at: string;
		refresh_token: string;
		refresh_token_expires_at: string;
	};
}

export interface IMagicLinkModel {
	id: number | string;
	user_id: number | string;
	token: string;
	hashed_code: string;
	expires_at: string;
	used_at?: string;
	$query(): QueryBuilder;
}

export interface IMagicLinkModelStatic {
	new (): IMagicLinkModel;
	query(): QueryBuilder;
	generateTokens(): Promise<{
		token: string;
		tokenExpiresAt: Date;
		code: string;
		hashedCode: string;
	}>;
	verifyTokenAndCode(
		token: string,
		code: string,
	): Promise<{ userId: number | string }>;
}

export interface ISmsCodeModel {
	id: number | string;
	user_id: number | string;
	token: string;
	hashed_code: string;
	expires_at: string;
	used_at?: string;
	codeHasExpired(): boolean;
	verifyCode(code: string): Promise<boolean>;
	$query(): QueryBuilder;
}

export interface ISmsCodeModelStatic {
	new (): ISmsCodeModel;
	query(): QueryBuilder;
}

export interface IMfaTokenModel {
	id: number | string;
	user_id: number | string;
	token: string;
	expires_at: string;
	used_at?: string;
	number_of_attempts: number;
	$query(): QueryBuilder;
}

export interface IMfaTokenModelStatic {
	new (): IMfaTokenModel;
	query(): QueryBuilder;
}

export interface IRecoveryCodeModel {
	id: number | string;
	user_id: number | string;
	code?: string;
	hashed_code: string;
	used_at?: string;
	verify(code: string): Promise<boolean>;
	markAsUsed(): Promise<void>;
	$query(): QueryBuilder;
}

export interface IRecoveryCodeModelStatic {
	new (): IRecoveryCodeModel;
	query(): QueryBuilder;
	generateCodes(): Promise<string[]>;
	checkForRecoveryCodeAndConsume(
		userId: number | string,
		code: string,
	): Promise<boolean>;
}

export interface IForgotPasswordModel {
	id: number | string;
	user_id: number | string;
	selector: string;
	token_hash: string;
	expires_at: Date;
	used_at?: Date | string | null;
	markAsUsed(): Promise<void>;
	$query(): QueryBuilder;
}

export interface IForgotPasswordModelStatic {
	new (): IForgotPasswordModel;
	query(): QueryBuilder;
}

// ─── Models bag ──────────────────────────────────────────────────────────────

export interface AuthFastifyModels {
	User: IUserModelStatic;
	Session?: ISessionModelStatic;
	MagicLink?: IMagicLinkModelStatic;
	SmsCode?: ISmsCodeModelStatic;
	MfaToken?: IMfaTokenModelStatic;
	RecoveryCode?: IRecoveryCodeModelStatic;
	ForgotPassword?: IForgotPasswordModelStatic;
}

// ─── Hooks (side-effects delegated to the consuming app) ─────────────────────

export interface MagicLinkCreatedParams {
	user: IUserModel;
	token: string;
	code: string;
	tokenExpiresAt: Date;
}

export interface SmsCodeCreatedParams {
	user: IUserModel;
	token: string;
	code: string;
}

export interface ForgotPasswordRequestedParams {
	identifier: string;
	isEmail: boolean;
}

export interface AuthFastifyHooks {
	/** Called after a magic link record is created. Use this to send the email. */
	onMagicLinkCreated?: (params: MagicLinkCreatedParams) => Promise<void>;
	/** Called after an SMS code record is created. Use this to send the SMS. */
	onSmsCodeCreated?: (params: SmsCodeCreatedParams) => Promise<void>;
	/**
	 * Called when a forgot-password request arrives (after basic validation).
	 * Use this to queue or send the password-reset email.
	 */
	onForgotPasswordRequested?: (
		params: ForgotPasswordRequestedParams,
	) => Promise<void>;
}

// ─── TOTP-specific options ────────────────────────────────────────────────────

export interface TotpOptions {
	/** Displayed in the authenticator app (e.g. "My App"). */
	serviceName: string;
	/**
	 * 64-character hex string (= 32 raw bytes) used to encrypt TOTP secrets
	 * before storing them in the database.
	 * Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
	 */
	secretEncryptionKey: string;
}

// ─── Top-level plugin options ─────────────────────────────────────────────────

export interface AuthFastifyPluginOptions {
	/** Which authentication strategy to mount. */
	strategy: Strategy;
	/** Your configured @anephenix/auth instance. */
	auth: Auth;
	/** The model classes the strategy needs. */
	models: AuthFastifyModels;
	/** Callbacks for side-effects (sending emails / SMS). */
	hooks?: AuthFastifyHooks;
	/** Required when strategy === 'mfa-totp'. */
	totp?: TotpOptions;
	/**
	 * Whether to set the `secure` flag on cookies.
	 * Defaults to `true` when NODE_ENV === 'production', `false` otherwise.
	 */
	secureCookie?: boolean;
}

// ─── Fastify request augmentation ────────────────────────────────────────────

declare module "fastify" {
	interface FastifyRequest {
		/** The authenticated user, set by the authenticateSession preHandler. */
		// biome-ignore lint/suspicious/noExplicitAny: user shape varies per app
		user?: any;
		/** The access token from the current session. */
		access_token?: string;
	}
}

export type { FastifyRequest };
