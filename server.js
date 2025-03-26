require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const path = require('path');

const app = express();
const PORT = 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'topsecret',
  resave: false,
  saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

// In-memory store for user sessions (use DB in production)
const users = {};

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
}, (accessToken, refreshToken, profile, done) => {
  if (!users[profile.id]) {
    users[profile.id] = {
      id: profile.id,
      name: profile.displayName,
      email: profile.emails?.[0]?.value,
      totpVerified: false,
    };
  }
  return done(null, users[profile.id]);
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => done(null, users[id]));

// Home route
app.get('/', (req, res) => {
  const user = req.user;
  if (!user) return res.render('index', { user: null });

  if (!user.totpVerified) return res.redirect('/2fa');

  res.render('index', { user });
});

// Google OAuth
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => res.redirect('/')
);

// 2FA Setup/Verify
app.get('/2fa', (req, res) => {
  const user = req.user;
  if (!user) return res.redirect('/');

  if (!user.totpSecret) {
    const secret = speakeasy.generateSecret({ name: `TopPoC (${user.email || user.name})` });
    user.totpSecret = secret.base32;
    qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
      return res.render('otp', { qr: data_url });
    });
  } else {
    return res.render('otp', { qr: null });
  }
});

app.post('/2fa', (req, res) => {
  const user = req.user;
  const isVerified = speakeasy.totp.verify({
    secret: user.totpSecret,
    encoding: 'base32',
    token: req.body.token,
    window: 1,
  });

  if (isVerified) {
    user.totpVerified = true;
    return res.redirect('/');
  } else {
    return res.send('Invalid OTP. <a href="/2fa">Try again</a>');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
