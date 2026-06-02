export default function Home({ name }) {
  return <main><h1>Hello {name}</h1></main>;
}
export async function getServerSideProps() {
  const key = process.env.API_KEY;
  return { props: { name: 'world' } };
}
