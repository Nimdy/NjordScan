const session = require('express-session');
const cookieParser = require('cookie-parser');

// session.hardcoded-secret: literal string secret
app.use(session({ secret: 'super-secret-prod-key-123', resave: false }));

// session.hardcoded-secret: the famous 'keyboard cat' default
app.use(session({ secret: 'keyboard cat', resave: false }));

// session.hardcoded-secret: cookie-parser with a literal secret
app.use(cookieParser('my-signing-secret-value'));
