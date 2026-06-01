function safeHref(value) {
  try {
    const u = new URL(value, window.location.origin);
    return ['http:', 'https:'].includes(u.protocol) ? u.href : '#';
  } catch {
    return '#';
  }
}

export function Safe({ userUrl, slug }) {
  const href = safeHref(userUrl);
  return (
    <nav>
      <a href={href}>Profile link</a>
      <a href={`/posts/${slug}`}>Post</a>
      <a href="/about">About</a>
    </nav>
  );
}
