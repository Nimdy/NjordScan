// SAFE: normal query operators, no $where, value coerced to a number.
async function findAdults(collection, age) {
  return collection.find({ age: { $gt: Number(age) } }).toArray();
}

module.exports = { findAdults };
