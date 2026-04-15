# Fastify-auth

A library for using @anephenix/auth in combination with Fastify.

## Dependencies

- Node.js (version 24+)

## Install

```shell
npm i @anephenix/fastify-auth
```

## Usage

```typescript
import authPlugin from '@anephenix/fastify-auth';

// Simplest — password-based auth with full session management
app.register(authPlugin, {
  strategy: 'sessions',
  auth,
  models: { User, Session },
});

// Magic links
app.register(authPlugin, {
  strategy: 'magic-links',
  auth,
  models: { User, Session, MagicLink },
  hooks: {
    onMagicLinkCreated: async ({ user, token, code, tokenExpiresAt }) => {
      await emailQueue.add({ to: user.email, token, code });
    },
  },
});

// TOTP MFA
app.register(authPlugin, {
  strategy: 'mfa-totp',
  auth,
  models: { User, Session, MfaToken, RecoveryCode },
  totp: {
    serviceName: 'My App',
    secretEncryptionKey: process.env.TOTP_SECRET_ENCRYPTION_KEY,
  },
});
```
