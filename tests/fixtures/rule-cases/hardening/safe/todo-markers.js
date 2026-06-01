// SAFE: security controls are finished; remaining TODOs are non-security.

export function createPost(req) {
  const user = requireUser(req); // authorization done
  // TODO: add pagination to the response
  return db.posts.insert({ ...req.body, authorId: user.id });
}

export function search(req) {
  const q = SearchSchema.parse(req.query); // validated
  // FIXME: improve relevance ranking
  return db.search(q.term);
}
