// SAFE: only known keys are picked from the request.
const defaults = { theme: 'light', locale: 'en' };

function buildConfig(req) {
  const { theme, locale } = req.body;
  return { ...defaults, theme, locale };
}

module.exports = { buildConfig };
