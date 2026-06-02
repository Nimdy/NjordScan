export default function Widget({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;  // reachable from the page (client)
}
