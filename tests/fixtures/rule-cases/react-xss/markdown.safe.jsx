import { marked } from 'marked';
import DOMPurify from 'isomorphic-dompurify';

export function Post({ userMarkdown }) {
  const html = DOMPurify.sanitize(marked.parse(userMarkdown));
  return <article dangerouslySetInnerHTML={{ __html: html }} />;
}
