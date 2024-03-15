# Demo App

This is a simple task management app that shows how the IAM stuff works in practice. Its not meant to be a real app, just something to poke around with.

## Quick setup

Make sure you've got the main app set up first (postgres, redis, etc). Then:

```bash
npm install
npm run prisma:generate
npm run prisma:migrate
npm run db:seed
npm run generate:keys
npm run start:dev
```

Once its running, you can hit:

- http://localhost:3000/demo/public/index.html - the demo UI (its ugly but works)
- http://localhost:3000/api-docs - swagger docs
- http://localhost:3000/health - health check

## What's in the demo?

A basic task CRUD with permissions:

| Endpoint | Permission needed |
|----------|------------------|
| `GET /demo/tasks` | `tasks:list` |
| `GET /demo/tasks/:id` | `tasks:read` |
| `POST /demo/tasks` | `tasks:create` |
| `PATCH /demo/tasks/:id` | `tasks:update` or `tasks:update:own` |
| `DELETE /demo/tasks/:id` | `tasks:delete` |

### Demo roles

- **task_admin** - can do everything
- **team_member** - can create tasks, update their own, view all
- **viewer** - read only

## Playing with OAuth

If you want to test the OAuth2 flow:

### 1. Get an admin token first

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@system.local", "password": "AdminPass123!"}'
```

### 2. Create an OAuth client

```bash
curl -X POST http://localhost:3000/oauth/clients \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test App",
    "redirectUris": ["http://localhost:3000/demo/callback"],
    "allowedGrantTypes": ["authorization_code", "refresh_token"],
    "allowedScopes": ["openid", "profile", "email"],
    "isConfidential": false
  }'
```

Save the `clientId` and `clientSecret` - the secret is only shown this one time!

### 3. Start the auth flow

Open this URL in a browser (fill in your client_id):

```
http://localhost:3000/oauth/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost:3000/demo/callback&scope=openid%20profile%20email&state=random123&code_challenge=YOUR_CHALLENGE&code_challenge_method=S256
```

You'll see a consent screen. After approving, you'll get redirected with a code.

### 4. Exchange the code

```bash
curl -X POST http://localhost:3000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=THE_CODE&redirect_uri=http://localhost:3000/demo/callback&client_id=YOUR_CLIENT_ID&code_verifier=YOUR_VERIFIER"
```

## PKCE stuff

For public clients (SPAs, mobile), you should use PKCE. Here's how it works:

```javascript
// generate a random verifier
const verifier = crypto.randomBytes(32).toString('base64url');

// create the challenge (SHA256 of verifier, base64url encoded)
const challenge = crypto
  .createHash('sha256')
  .update(verifier)
  .digest('base64url');

// use challenge in authorize request, verifier in token request
```

The demo UI has this built in if you want to see it working.

## Multi-tenant demo

You can create multiple tenants to see the isolation:

```bash
# create tenant A
curl -X POST http://localhost:3000/tenants \
  -H "Authorization: Bearer SUPER_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Company A",
    "slug": "company-a", 
    "adminEmail": "admin@company-a.com",
    "adminPassword": "AdminPass123!"
  }'
```

Then login as the tenant admin and create some tasks. Login as a different tenant and verify you can't see them.

## Checking permissions

The cool part is the scoped permissions. If a user has `tasks:update:own`:

```bash
# this works (updating your own task)
curl -X PATCH http://localhost:3000/demo/tasks/MY_TASK_ID \
  -H "Authorization: Bearer TOKEN" \
  -d '{"title": "new title"}'

# this fails with 403 (someone else's task)
curl -X PATCH http://localhost:3000/demo/tasks/OTHER_TASK_ID \
  -H "Authorization: Bearer TOKEN" \
  -d '{"title": "nope"}'
```

## Decoding JWTs

Wanna see what's in your token?

```bash
# grab the middle part and decode it
echo "YOUR_TOKEN" | cut -d'.' -f2 | tr '_-' '/+' | base64 -d | jq .
```

Or just paste it into jwt.io (don't do this with prod tokens obviously lol).

## Troubleshooting

**"Tenant not found"** - Run `npm run db:seed` to create the default tenant

**"Invalid token"** - Did you run `npm run generate:keys`?

**Database errors** - Check your `DATABASE_URL` in .env

**Redis errors** - Make sure Redis is running on localhost:6379

For more verbose logs:
```bash
DEBUG=* npm run start:dev
```

## Security notes

Just a heads up - this is a demo. Some things that would be different in prod:

- Passwords are hashed with bcrypt (cost 12), that's real
- JWTs use RS256, that's real too
- But we don't have rate limiting yet (its in the TODOs)
- SAML signature validation needs more testing
- The consent page is ugly html, not a proper frontend lol

Feel free to poke around and break stuff, that's what its for!
