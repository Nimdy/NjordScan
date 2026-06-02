// VULNERABLE: unfinished security controls left as TODO/FIXME markers.

export function createPost(req) {
  // TODO: add authorization check before allowing this
  return db.posts.insert(req.body);
}

export function search(req) {
  // FIXME: validate and sanitize this input to prevent injection
  return db.query(req.query.q);
}
