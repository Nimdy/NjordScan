// VULNERABLE: user input compiled into the template SOURCE string.
const ejs = require('ejs');
const Handlebars = require('handlebars');

function greet(req) {
  return ejs.render('<h1>Hello ' + req.query.name + '</h1>');
}

function page(req) {
  const tpl = Handlebars.compile(`<title>${req.query.title}</title>`);
  return tpl({});
}

module.exports = { greet, page };
