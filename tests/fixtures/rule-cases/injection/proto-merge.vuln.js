// VULNERABLE: request body merged into an object (prototype pollution).
const _ = require('lodash');

const defaults = { theme: 'light', locale: 'en' };

function buildConfig(req) {
  return _.merge({}, defaults, req.body);
}

function applySettings(req, target) {
  Object.assign(target, req.body);
  return target;
}

module.exports = { buildConfig, applySettings };
