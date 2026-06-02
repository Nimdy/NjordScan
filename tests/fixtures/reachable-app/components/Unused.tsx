export default function Unused({ data }: { data: any }) {
  return <div dangerouslySetInnerHTML={{ __html: data.raw }} />;  // unreachable
}
