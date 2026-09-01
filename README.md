# @anephenix/fastify-auth

A Fastify 5 plugin that wires up authentication routes for your app using [@anephenix/auth](https://github.com/anephenix/auth) and your own ORM models (Objection.js or anything that satisfies the model interfaces).

Choose a strategy and the plugin registers the matching HTTP routes, handles token generation and verification, and delegates side-effects (sending emails, SMS) to hooks you provide.

## Contents

- [Install](#install)
- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Strategies](#strategies)
  - [sessions](#sessions)
  - [magic-links](#magic-links)
  - [mfa-sms](#mfa-sms)
  - [mfa-totp](#mfa-totp)
  - [forgotten-password](#forgotten-password)
- [Protecting routes](#protecting-routes)
- [Web vs API clients](#web-vs-api-clients)
- [Model interfaces](#model-interfaces)
- [TypeScript](#typescript)
- [FAQs](#faqs)

## Install

```shell
npm i @anephenix/fastify-auth
```

Peer dependencies (install separately if not already present):

```shell
npm i @anephenix/auth fastify
```

For cookie-based auth (web clients):

```shell
npm i @fastify/cookie
```

## Prerequisites

- Node.js >= 18
- Fastify >= 5.0.0
- An `Auth` instance from `@anephenix/auth`
- ORM models that satisfy the [model interfaces](#model-interfaces)

If you use web-client cookie support, register `@fastify/cookie` **before** registering this plugin:

```typescript
import fastifyCookie from '@fastify/cookie';
await app.register(fastifyCookie);
await app.register(authPlugin, { ... });
```

## Quick start

```typescript
import authPlugin from '@anephenix/fastify-auth';
import { Auth } from '@anephenix/auth';

const auth = new Auth({ /* your Auth config */ });

app.register(authPlugin, {
  strategy: 'sessions',
  auth,
  models: { User, Session },
});
```

## Strategies

### sessions

Password-based login with full session management. Tokens are returned in the response body for API clients, or set as HttpOnly cookies for web clients (see [Web vs API clients](#web-vs-api-clients)).

**Required models:** `User`, `Session`

```typescript
app.register(authPlugin, {
  strategy: 'sessions',
  auth,
  models: { User, Session },
  secureCookie: true, // optional; defaults to true when NODE_ENV=production
});
```

**Routes:**

| Method   | Path              | Auth required | Description                                      |
|----------|-------------------|:-------------:|--------------------------------------------------|
| `POST`   | `/signup`         |               | Create a user account                            |
| `POST`   | `/login`          |               | Authenticate; receive access + refresh tokens    |
| `GET`    | `/profile`        | ✓             | Return the current user                          |
| `POST`   | `/logout`         | ✓             | Delete the current session                       |
| `POST`   | `/auth/refresh`   |               | Exchange a refresh token for a new access token  |
| `GET`    | `/sessions`       | ✓             | List all sessions for the current user           |
| `DELETE` | `/sessions`       | ✓             | Delete all sessions except the active one        |
| `DELETE` | `/sessions/:id`   | ✓             | Delete a specific session                        |

**Example: signup, login (API client), call a protected route**

```bash
curl -X POST http://localhost:3000/signup \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "email": "alice@example.com", "password": "correct horse battery staple"}'
# 201
# { "id": 1, "username": "alice", "email": "alice@example.com" }

curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"identifier": "alice", "password": "correct horse battery staple"}'
# 201
# {
#   "access_token": "...",
#   "refresh_token": "...",
#   "access_token_expires_at": "2026-08-31T12:15:00.000Z",
#   "refresh_token_expires_at": "2026-09-07T12:00:00.000Z"
# }

curl http://localhost:3000/profile \
  -H "Authorization: Bearer <access_token>"
# 200
# { "id": 1, "username": "alice", "email": "alice@example.com" }
```

A **web client** (`x-client-type: web` header, or `Accept: text/html`) gets the
same tokens set as `HttpOnly` cookies instead of in the body - `/login` then
just returns the plain-text message `"Authenticated successfully"`.

`POST /auth/refresh` takes `{ "refresh_token": "..." }` for API clients (or
reads the `refresh_token` cookie for web clients) and returns a new
`access_token`/`refresh_token` pair in the same shape as `/login`.

`DELETE /sessions/:id` returns `409` with
`{ "error": "conflict", "message": "Cannot delete the active session. Use the /logout endpoint instead." }`
if you try to delete the session you're currently authenticated with - use
`/logout` for that instead.

---

### magic-links

Passwordless email login. The plugin creates a magic-link record and fires your hook — you are responsible for sending the email.

**Required models:** `User`, `Session`, `MagicLink`  
**Required hook:** `onMagicLinkCreated`

```typescript
app.register(authPlugin, {
  strategy: 'magic-links',
  auth,
  models: { User, Session, MagicLink },
  hooks: {
    onMagicLinkCreated: async ({ user, token, code, tokenExpiresAt }) => {
      // Send the magic-link email here, e.g. via a job queue
      await emailQueue.add({ to: user.email, token, code });
    },
  },
});
```

**Routes:**

| Method | Path                  | Description                                                                  |
|--------|-----------------------|------------------------------------------------------------------------------|
| `POST` | `/magic-links`        | Look up user by email, create magic-link record, call `onMagicLinkCreated`  |
| `POST` | `/magic-links/verify` | Verify token + code; return access + refresh tokens                          |

**Example**

```bash
curl -X POST http://localhost:3000/magic-links \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com"}'
# 201
# { "message": "Magic link created" }

curl -X POST http://localhost:3000/magic-links/verify \
  -H "Content-Type: application/json" \
  -d '{"token": "<token from onMagicLinkCreated>", "code": "<code from onMagicLinkCreated>"}'
# 201
# {
#   "access_token": "...",
#   "refresh_token": "...",
#   "access_token_expires_at": "2026-08-31T12:15:00.000Z",
#   "refresh_token_expires_at": "2026-09-07T12:00:00.000Z"
# }
```

The `token`/`code` pair only exists in your `onMagicLinkCreated` hook (e.g.
embedded in the email you send) - there's no endpoint to look them up.

---

### mfa-sms

Password login followed by an SMS one-time code. After the password check the plugin creates an SMS code record and fires your hook — you are responsible for sending the SMS.

**Required models:** `User`, `Session`, `SmsCode`  
**Required hook:** `onSmsCodeCreated`

```typescript
app.register(authPlugin, {
  strategy: 'mfa-sms',
  auth,
  models: { User, Session, SmsCode },
  hooks: {
    onSmsCodeCreated: async ({ user, token, code }) => {
      // Send the SMS here
      await smsQueue.add({ to: user.mobile_number, code });
    },
  },
});
```

**Routes:**

| Method | Path                     | Description                                                              |
|--------|--------------------------|--------------------------------------------------------------------------|
| `POST` | `/sessions`              | Authenticate with password; create SMS code, call `onSmsCodeCreated`   |
| `POST` | `/sessions/verify-code`  | Verify token + SMS code; return access + refresh tokens                 |

**Example**

```bash
curl -X POST http://localhost:3000/sessions \
  -H "Content-Type: application/json" \
  -d '{"identifier": "alice", "password": "correct horse battery staple"}'
# 201
# { "token": "...", "message": "Authentication successful. SMS code sent to verify authentication" }

curl -X POST http://localhost:3000/sessions/verify-code \
  -H "Content-Type: application/json" \
  -d '{"token": "<token from the previous step>", "code": "<code from onSmsCodeCreated>"}'
# 201
# {
#   "access_token": "...",
#   "refresh_token": "...",
#   "access_token_expires_at": "2026-08-31T12:15:00.000Z",
#   "refresh_token_expires_at": "2026-09-07T12:00:00.000Z"
# }
```

---

### mfa-totp

Password login followed by a TOTP code (authenticator app, e.g. Google Authenticator or Authy). TOTP secrets are encrypted at rest using AES-256-GCM.

**Required models:** `User`, `Session`, `MfaToken`, `RecoveryCode`  
**Required option:** `totp`

```typescript
app.register(authPlugin, {
  strategy: 'mfa-totp',
  auth,
  models: { User, Session, MfaToken, RecoveryCode },
  totp: {
    serviceName: 'My App',           // displayed in the authenticator app
    secretEncryptionKey: process.env.TOTP_SECRET_ENCRYPTION_KEY,
    // Generate a key with:
    // node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
  },
});
```

**Routes:**

| Method | Path                                    | Auth required | Description                                              |
|--------|-----------------------------------------|:-------------:|----------------------------------------------------------|
| `POST` | `/signup`                               |               | Create account; return session tokens immediately        |
| `POST` | `/login`                                |               | Authenticate with password; return MFA token if MFA is enabled |
| `POST` | `/login/mfa`                            |               | Verify TOTP code or recovery code; return session tokens |
| `POST` | `/auth/mfa/recovery-codes`              | ✓             | Generate 10 one-time recovery codes                      |
| `POST` | `/auth/mfa/setup`                       | ✓             | Generate TOTP secret + QR code image                     |
| `POST` | `/auth/mfa/verify`                      | ✓             | Verify a TOTP code (confirm setup)                       |
| `POST` | `/auth/mfa/disable`                     | ✓             | Disable MFA with password + TOTP code                    |
| `POST` | `/auth/mfa/disable-with-recovery-code`  | ✓             | Disable MFA with password + recovery code                |

**Example: enabling and using TOTP MFA**

```bash
# 1. Sign up - MFA isn't enabled yet, so you get a session back immediately
curl -X POST http://localhost:3000/signup \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "email": "alice@example.com", "password": "correct horse battery staple", "mobile_number": "+15551234567"}'
# 201 → { access_token, refresh_token, access_token_expires_at, refresh_token_expires_at }

# 2. Set up MFA (protected) - returns a QR code image for an authenticator app
curl -X POST http://localhost:3000/auth/mfa/setup \
  -H "Authorization: Bearer <access_token>"
# 200 → { "qrCodeImageData": "data:image/png;base64,..." }

# 3. Confirm setup with a code from the authenticator app
curl -X POST http://localhost:3000/auth/mfa/verify \
  -H "Authorization: Bearer <access_token>" -H "Content-Type: application/json" \
  -d '{"token": "123456"}'
# 200 → { "message": "TOTP token verified successfully" }

# 4. Generate recovery codes for account-recovery scenarios
curl -X POST http://localhost:3000/auth/mfa/recovery-codes \
  -H "Authorization: Bearer <access_token>"
# 201 → { "codes": ["ABCD-1234", "..."] }  (10 one-time codes)

# 5. On a later login, MFA is now required - you get an mfa token, not a session
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"identifier": "alice", "password": "correct horse battery staple"}'
# 201 → { "token": "<mfa_token>" }

# 6. Exchange the mfa token + a TOTP code (or a recovery code) for a session
curl -X POST http://localhost:3000/login/mfa \
  -H "Content-Type: application/json" \
  -d '{"token": "<mfa_token>", "code": "123456"}'
# 201 → { access_token, refresh_token, access_token_expires_at, refresh_token_expires_at }
```

To disable MFA, `POST /auth/mfa/disable` with
`{ "password": "...", "code": "<totp code>" }`, or
`POST /auth/mfa/disable-with-recovery-code` with
`{ "password": "...", "code": "<recovery code>" }` - both protected routes,
both return `{ "message": "MFA TOTP disabled successfully" }`.

---

### forgotten-password

Forgot-password and reset-password flow. The plugin fires your hook with the validated identifier — you are responsible for looking up the user, creating the reset record, and sending the email.

**Required models:** `User`, `ForgotPassword`  
**Required hook:** `onForgotPasswordRequested`

```typescript
app.register(authPlugin, {
  strategy: 'forgotten-password',
  auth,
  models: { User, ForgotPassword },
  hooks: {
    onForgotPasswordRequested: async ({ identifier, isEmail }) => {
      // Look up the user, create a ForgotPassword record, and send the email
      const user = isEmail
        ? await User.query().where({ email: identifier }).first()
        : await User.query().where({ username: identifier }).first();

      if (user) {
        const record = await createForgotPasswordRecord(user.id);
        await emailQueue.add({
          to: user.email,
          selector: record.selector,
          token: record.plainToken,
        });
      }
    },
  },
});
```

**Routes:**

| Method | Path                        | Description                                                            |
|--------|-----------------------------|------------------------------------------------------------------------|
| `POST` | `/forgot-password`          | Validate identifier; call `onForgotPasswordRequested`                  |
| `GET`  | `/reset-password/:selector` | Validate selector + token from query string                            |
| `POST` | `/reset-password`           | Validate selector + token; update user password                        |

The `POST /forgot-password` route always returns the same neutral message regardless of whether the account exists, to prevent user enumeration.

**Example**

```bash
curl -X POST http://localhost:3000/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"identifier": "alice@example.com"}'
# 200
# { "message": "If an account with that username/email exists, we've sent password reset instructions." }

# selector/token come from the reset link your onForgotPasswordRequested hook sent
curl "http://localhost:3000/reset-password/<selector>?token=<token>"
# 200
# { "message": "Password reset token is valid" }

curl -X POST http://localhost:3000/reset-password \
  -H "Content-Type: application/json" \
  -d '{"selector": "<selector>", "token": "<token>", "password": "new password", "password_confirmation": "new password"}'
# 200
# { "message": "Password reset successfully" }
```

## Protecting routes

The plugin exposes `createAuthenticateSession` — a factory for a Fastify `preHandler` that validates the session on protected routes in your own app.

```typescript
import { createAuthenticateSession } from '@anephenix/fastify-auth/middleware/authenticate';

const authenticateSession = createAuthenticateSession({ Session });

app.get('/dashboard', { preHandler: [authenticateSession] }, async (request, reply) => {
  // request.user and request.access_token are populated
  reply.send({ user: request.user });
});
```

The middleware:
1. Extracts the access token from `Authorization: Bearer <token>` or the `access_token` cookie.
2. Looks up the session and checks it has not expired.
3. Loads the related user via `session.$relatedQuery('user')`.
4. Attaches `request.user` and `request.access_token` for downstream handlers.
5. Returns `401` at the first failing step.

## Web vs API clients

The `sessions` strategy detects the client type from the incoming request:

- **Web clients** — requests with `x-client-type: web` header or `Accept: text/html` — receive tokens as `HttpOnly` cookies (`access_token` and `refresh_token`). This is the safest option for browser apps.
- **API clients** — all other requests — receive tokens in the JSON response body.

The `secureCookie` plugin option controls whether the `Secure` flag is set on cookies. It defaults to `true` when `NODE_ENV === 'production'` and `false` otherwise.

## Model interfaces

The plugin calls a fixed set of static and instance methods on each model. Your models can have additional fields; they just need to satisfy these contracts.

### User

```typescript
interface IUserModel {
  id: number | string;
  username?: string;
  email?: string;
  mobile_number?: string;     // required for mfa-sms
  mfa_totp_secret?: string | null;  // required for mfa-totp
  updatePassword?(password: string): Promise<void>; // required for forgotten-password
  $query(): QueryBuilder;
  $relatedQuery(relation: string): QueryBuilder;
}

interface IUserModelStatic {
  query(): QueryBuilder;
  authenticate(params: { identifier: string; password: string }): Promise<IUserModel & { isUsingMFA?: boolean }>;
}
```

### Session

```typescript
interface ISessionModel {
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
}

interface ISessionModelStatic {
  query(): QueryBuilder;
  generateTokens(): {
    access_token: string;
    access_token_expires_at: string;
    refresh_token: string;
    refresh_token_expires_at: string;
  };
}
```

### MagicLink

```typescript
interface IMagicLinkModelStatic {
  query(): QueryBuilder;
  generateTokens(): Promise<{ token: string; tokenExpiresAt: Date; code: string; hashedCode: string }>;
  verifyTokenAndCode(token: string, code: string): Promise<{ userId: number | string }>;
}
```

### SmsCode

```typescript
interface ISmsCodeModel {
  codeHasExpired(): boolean;
  verifyCode(code: string): Promise<boolean>;
  $query(): QueryBuilder;
}

interface ISmsCodeModelStatic {
  query(): QueryBuilder;
}
```

### MfaToken

```typescript
interface IMfaTokenModel {
  number_of_attempts: number;
  used_at?: string;
  $query(): QueryBuilder;
}

interface IMfaTokenModelStatic {
  query(): QueryBuilder;
}
```

### RecoveryCode

```typescript
interface IRecoveryCodeModelStatic {
  query(): QueryBuilder;
  generateCodes(): Promise<string[]>;
  checkForRecoveryCodeAndConsume(userId: number | string, code: string): Promise<boolean>;
}
```

### ForgotPassword

```typescript
interface IForgotPasswordModel {
  selector: string;
  token_hash: string;
  expires_at: Date;
  used_at?: Date | string | null;
  markAsUsed(): Promise<void>;
  $query(): QueryBuilder;
}

interface IForgotPasswordModelStatic {
  query(): QueryBuilder;
}
```

## TypeScript

All types are re-exported from the package root:

```typescript
import type {
  AuthFastifyPluginOptions,
  AuthFastifyModels,
  AuthFastifyHooks,
  TotpOptions,
  Strategy,
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
  MagicLinkCreatedParams,
  SmsCodeCreatedParams,
  ForgotPasswordRequestedParams,
} from '@anephenix/fastify-auth';
```

## FAQs

### Can I support both password login and magic-link sign-in in the same app?

Yes - register the plugin twice on the same Fastify instance, once per strategy:

```typescript
app.register(authPlugin, {
  strategy: 'sessions',
  auth,
  models: { User, Session },
});

app.register(authPlugin, {
  strategy: 'magic-links',
  auth,
  models: { User, Session, MagicLink },
  hooks: {
    onMagicLinkCreated: async ({ user, token, code }) => {
      await emailQueue.add({ to: user.email, token, code });
    },
  },
});
```

This works because the plugin is registered via `fastify-plugin`, so each
registration adds its routes straight onto your app instance rather than
into its own isolated context. The route sets don't collide - `sessions`
owns `/signup`, `/login`, `/profile`, `/logout`, `/auth/refresh` and
`/sessions*`; `magic-links` only adds `/magic-links` and
`/magic-links/verify`. Both strategies also create `Session` rows the same
way, so a session created via a magic link is indistinguishable from one
created via password - `/profile`, `/logout` and session
listing/revocation from the `sessions` strategy work for magic-link users
too, with no extra wiring.

The one gap to know about: **`magic-links` has no signup route of its
own.** `POST /magic-links` looks up the user by email and errors with
"User not found for email" if there's no match - it doesn't create
accounts. A brand-new user needs to go through the `sessions` strategy's
`POST /signup` first (which currently requires a `password`), and can then
log in either way afterwards. For a true "sign up via magic link, no
password ever set" flow, you'd need your own small custom signup route
rather than relying on the bundled one.

## License

MIT
