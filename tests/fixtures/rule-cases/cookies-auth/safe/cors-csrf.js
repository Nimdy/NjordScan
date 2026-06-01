const cors = require('cors');

// Allowlisted origins with credentials. Should NOT fire.
app.use(cors({ origin: ['https://app.example.com'], credentials: true }));

// Wildcard origin WITHOUT credentials is acceptable for public read APIs.
app.use(cors({ origin: '*' }));

// CSRF protection enabled. Should NOT fire.
const config = { csrf: true };
