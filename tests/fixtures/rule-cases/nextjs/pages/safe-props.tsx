export default function SafeProps({ count }: { count: number }) {
  return <div>{count}</div>;
}

// SAFE: the secret is USED on the server to fetch data, but only the result and
// a NEXT_PUBLIC_ value cross to the browser — never the secret itself.
export async function getServerSideProps() {
  const res = await fetch('https://api.example.com/x', {
    headers: { authorization: `Bearer ${process.env.STRIPE_SECRET_KEY}` },
  });
  const data = await res.json();
  return {
    props: {
      count: data.count,
      analyticsId: process.env.NEXT_PUBLIC_ANALYTICS_ID ?? '',
    },
  };
}
