// VULNERABLE: MongoDB $where runs JavaScript in the database.
async function findAdults(collection, age) {
  return collection.find({ $where: `this.age > ${age}` }).toArray();
}

module.exports = { findAdults };
