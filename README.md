# FluffyCloud IAM Platform

Hey! This is our Identity & Access Management platform. It's built with NestJS and handles all the auth stuff - users, roles, permissions, OAuth, SAML... basically everything you need to secure your apps.

## What's in here?

So we've got a bunch of features:

- Multi-tenant auth (each org gets their own isolated space)
- User registration/login (the basics, ya know)
- JWT tokens with RS256 (access + refresh, proper rotation and all that)
- RBAC with granular permissions (like `users:read:own` vs `users:read:all`)
- OAuth2 Provider with PKCE (for SPAs and mobile apps)
- SAML 2.0 SP for enterprise SSO (because enterprise clients always want SAML lol)
- Session management - tracks devices, lets users see where they're logged in
- Audit logs for compliance stuff
- Swagger docs at `/api-docs`
- Health check at `/health`

## Tech we're using

- NestJS + TypeScript (obviously)
- PostgreSQL with Prisma
- Redis for sessions and token blacklisting
- bcrypt for password hashing
- Helmet for security headers

## Getting Started

### You'll need

- Node.js 18+ 
- PostgreSQL running somewhere
- Redis running somewhere

### Setup

```bash
# install stuff
npm install

# copy the env file and fill in your db/redis details
cp .env.example .env

# generate the JWT signing keys (creates a keys/ folder)
npm run generate:keys

# setup the database
npm run prisma:generate
npm run prisma:migrate
npm run db:seed
```

### Run it

```bash
# dev mode (with hot reload)
npm run start:dev

# or for prod
npm run build
npm run start:prod
```

## API Overview

Check `/api-docs` for the full Swagger documentation, but here's the gist:

**The basics:**
- `GET /health` - is it alive?
- `POST /auth/register` - create account
- `POST /auth/login` - get your tokens
- `POST /auth/refresh` - refresh when access token expires
- `POST /auth/logout` - invalidate your refresh token

**OAuth2 stuff:**
- `GET /oauth/authorize` - start the OAuth dance
- `POST /oauth/token` - exchange codes for tokens
- `POST /oauth/revoke` - kill a token
- `POST /oauth/introspect` - check if a token is valid
- CRUD for `/oauth/clients` (creating apps that can use OAuth)

**SAML (for enterprise SSO):**
- `/saml/metadata/:tenantSlug` - your SP metadata XML
- `/saml/login/:tenantSlug` - kick off SAML flow
- `/saml/acs/:tenantSlug` - where the IdP posts back to
- CRUD for `/saml/idp` (managing IdP configs)

**RBAC:**
- CRUD for `/rbac/roles` 
- Assign/remove roles from users
- Check user permissions

**Admin stuff:**
- `/admin/dashboard/stats` - numbers for the dashboard
- `/admin/users` - manage users
- `/admin/security/*` - see active sessions, suspicious activity

**Demo app:**
- `/demo/tasks` - a simple task CRUD to show how permissions work

## How permissions work

We use `resource:action:scope` format. Some examples:

```
users:read        - can read any user
users:read:own    - can only read your own profile  
users:update:tenant - can update users in your tenant
roles:manage      - can do anything with roles
```

The scopes are: `own` (just your stuff), `tenant` (your org), `all` (everything).

## Default roles

- **super_admin** - god mode, can do everything
- **tenant_admin** - admin within a tenant
- **user_manager** - can manage users and assign roles
- **user** - basic user, can read/update their own profile

## TODOs and known limitations

Alright, being honest here - some stuff isn't done yet:

- [ ] Rate limiting - its mentioned in the code as TODOs but not implemented
- [ ] Email verification flow - schema has the field, logic isn't there
- [ ] Proper SAML signature verification (using passport-saml but needs more testing)
- [ ] Row-level security in Postgres (we rely on app-level filtering for now)

The integration tests exist but they're more like "smoke tests" - they test the happy paths, not every edge case. We'll add more as we find bugs lol.

## Project structure

```
src/
├── common/        # shared stuff (guards, decorators)
├── database/      # prisma service
└── modules/
    ├── admin/     # admin dashboard  
    ├── audit/     # audit logging
    ├── auth/      # login/register
    ├── demo/      # demo task app
    ├── oauth/     # oauth2 provider
    ├── rbac/      # roles & permissions
    ├── redis/     # redis wrapper
    ├── saml/      # saml SP
    ├── session/   # session tracking
    └── tenant/    # multi-tenancy
```

## Contributing

Just open a PR. We're not picky about commit message formats or anything, just make sure the tests pass (`npm test`) and the build works (`npm run build`).

## License

MIT - do whatever you want with it
