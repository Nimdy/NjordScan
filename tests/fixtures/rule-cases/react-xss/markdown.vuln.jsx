import { marked } from 'marked';

export function Post({ userMarkdown }) {
  const rendered = marked.parse(userMarkdown);
  return (
    <div>
      <article dangerouslySetInnerHTML={{ __html: marked(userMarkdown) }} />
      <aside dangerouslySetInnerHTML={{ __html: rendered }} />
    </div>
  );
}
