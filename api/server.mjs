import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import axios from 'axios';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import session from 'express-session';
import { createProxyMiddleware } from 'http-proxy-middleware';

// Construct __dirname equivalent in ES module scope
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const DOTENV_CONFIG_PATH = process.env.DOTENV_CONFIG_PATH;

if (DOTENV_CONFIG_PATH) {
  console.log("DOTENV_CONFIG_PATH is set to: ", DOTENV_CONFIG_PATH)
  dotenv.config({ path: DOTENV_CONFIG_PATH });
} else {
  dotenv.config({ path: path.join(__dirname, '.env') });
}

const app = express();

// The session holds a GitHub access token, so an unsigned or default-signed
// session is equivalent to handing out that token: refuse to start without a
// secret instead of silently using `undefined`.
if (!process.env.SESSION_SECRET) {
  console.error('SESSION_SECRET is not set. Refusing to start.');
  process.exit(1);
}

// `secure` cookies unless explicitly running plain HTTP for local development.
// Previously `secure: false` was hardcoded, so the session cookie carrying the
// GitHub token was transmitted over unencrypted HTTP in production too.
const isProduction = process.env.NODE_ENV === 'production';

app.use(session({
  name: 'copilot_metrics_session',
  secret: process.env.SESSION_SECRET,
  resave: false,
  // Do not persist sessions for visitors who never authenticated.
  saveUninitialized: false,
  cookie: {
    secure: isProduction,
    httpOnly: true,
    // OAuth returns to /callback via a top-level cross-site redirect, which
    // `strict` would strip the cookie from; `lax` keeps CSRF protection for
    // unsafe methods while allowing that navigation.
    sameSite: 'lax',
    maxAge: 8 * 60 * 60 * 1000,
  },
}));

if (isProduction) {
  // Required for `secure` cookies and for req.protocol to reflect the original
  // scheme when the app sits behind a TLS-terminating proxy.
  app.set('trust proxy', 1);
}

// Middleware to add Authorization header
const authMiddleware = (req, res, next) => {
  // not ideal but if someone wanted to use hardcoded token on the backend
  if (!req.session.token && !process.env.VUE_APP_GITHUB_TOKEN) {
    res.status(401).send('Unauthorized');
    return;
  }

  if (process.env.VUE_APP_GITHUB_TOKEN) {
    // Use the hardcoded token if it's available
    req.session.token = process.env.VUE_APP_GITHUB_TOKEN;
  }

  req.headers['Authorization'] = `Bearer ${req.session.token}`;
  console.log('Added Authorization to:', req.url);
  next();
};

const githubProxy = createProxyMiddleware({
  target: 'https://api.github.com',
  changeOrigin: true,
  pathRewrite: {
    '^/api/github': '', // Rewrite URL path (remove /api/github)
  },
  onProxyReq: (proxyReq, req) => {
    console.log('Proxying request to GitHub API:', req.url);
    // Optional: Modify the proxy request here (e.g., headers)
  },
});

// Apply middlewares to the app
app.use('/api/github', authMiddleware, githubProxy);

const exchangeCode = async (code) => {
  const params = new URLSearchParams({
    client_id: process.env.GITHUB_CLIENT_ID,
    client_secret: process.env.GITHUB_CLIENT_SECRET,
    code: code,
  });

  try {
    const response = await axios.post('https://github.com/login/oauth/access_token', params, {
      headers: { 'Accept': 'application/json' }
    });

    if (response.status === 200) {
      return response.data;
    } else {
      // Log the status only. Dumping the whole axios response prints its
      // `config`, and therefore the client secret that was posted.
      console.error('Unexpected status from GitHub token endpoint:', response.status);
      return {};
    }
  } catch (error) {
    // Never log the axios error object as-is: its `config.data` echoes the
    // request body, which contains GITHUB_CLIENT_SECRET and the OAuth code.
    // Log only the status and GitHub's error slug.
    console.error(
      'Error in exchangeCode:',
      error.response?.status ?? 'no response',
      error.response?.data?.error ?? error.code ?? 'unknown error',
    );
    return {};
  }
};

// Serve static files from the Vue app
app.use(express.static(path.join(__dirname, 'public')));

/**
 * Base URL used to build the OAuth redirect URI.
 *
 * Prefer an explicit APP_BASE_URL. Deriving it from the `Host` header lets a
 * caller with a spoofed Host influence the `redirect_uri` that GitHub echoes
 * back, and the host also ends up in a redirect the browser follows.
 */
const buildRedirectUri = (req) => {
  const base = process.env.APP_BASE_URL;
  if (base) return new URL('/callback', base).toString();
  return `${req.protocol}://${req.get('host')}/callback`;
};

app.get('/login', (req, res) => {
  if (!process.env.GITHUB_CLIENT_ID) {
    res.status(500).send('OAuth is not configured.');
    return;
  }

  // 128 bits from a CSPRNG. `Math.random()` is not cryptographically secure and
  // its output is predictable from previous values, which makes the CSRF `state`
  // parameter guessable and therefore useless.
  req.session.state = crypto.randomBytes(16).toString('hex');

  // Build the query with URLSearchParams so every value is percent-encoded.
  const params = new URLSearchParams({
    client_id: process.env.GITHUB_CLIENT_ID,
    redirect_uri: buildRedirectUri(req),
    state: req.session.state,
  });

  // Persist the state before redirecting, otherwise the callback can arrive
  // before the store has written it.
  req.session.save((error) => {
    if (error) {
      console.error('Failed to persist OAuth state:', error.message);
      res.status(500).send('Unable to start sign-in.');
      return;
    }
    res.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
  });
});

app.get('/callback', async (req, res) => {
  const code = req.query.code;
  const state = req.query.state;
  const expectedState = req.session.state;

  // Single-use state: clear it before doing anything else so a captured
  // callback URL cannot be replayed.
  delete req.session.state;

  // Require a state to have been issued. The previous check compared
  // `state !== req.session.state` only, so a request with no `state` query
  // parameter and no session state compared `undefined !== undefined` and
  // passed, defeating the CSRF protection entirely.
  if (
    typeof state !== 'string' ||
    typeof expectedState !== 'string' ||
    state.length !== expectedState.length ||
    !crypto.timingSafeEqual(Buffer.from(state), Buffer.from(expectedState))
  ) {
    res.status(400).send('Invalid state');
    return;
  }

  if (typeof code !== 'string' || !/^[A-Za-z0-9_-]{1,255}$/.test(code)) {
    res.status(400).send('Invalid code');
    return;
  }

  const tokenData = await exchangeCode(code);

  if (tokenData.access_token) {
    // Store the token in the session
    req.session.token = tokenData.access_token;

    // redirect to the Vue app with the user's information
    res.redirect(`/`);
  } else {
    // The `code` is deliberately not reflected here. Echoing a query parameter
    // into the HTML response was a reflected XSS sink, and the code itself is a
    // short-lived credential that should not be rendered.
    res.status(502).send('Authorized, but unable to exchange the code for a token.');
  }
});

// All other requests to serve the Vue app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

process.on('SIGINT', () => {
  console.log('Received SIGINT. Exiting...');
  // Clean up your application's resources here
  process.exit(0);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
