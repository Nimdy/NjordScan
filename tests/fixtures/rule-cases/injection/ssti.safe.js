// SAFE: fixed template, user input passed as DATA in the context object.
const ejs = require('ejs');

function greet(req) {
  return ejs.render('<h1>Hello <%= name %></h1>', { name: req.query.name });
}

module.exports = { greet };
