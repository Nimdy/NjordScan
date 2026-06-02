const cors = require('cors');

// cors.wildcard-credentials: reflect any origin + credentials
app.use(cors({ origin: true, credentials: true }));

// cors.wildcard-credentials: literal wildcard + credentials
app.use(cors({ origin: '*', credentials: true }));

// csrf.disabled: protection turned off
const config = { csrf: false };

// csrf.disabled: skip flag
const opts = { skipCSRF: true };
