const session = require('express-session');
const cookieParser = require('cookie-parser');

// Secret sourced from the environment. Should NOT fire.
app.use(session({ secret: process.env.SESSION_SECRET, resave: false }));

// cookie-parser secret from env. Should NOT fire.
app.use(cookieParser(process.env.COOKIE_SECRET));
