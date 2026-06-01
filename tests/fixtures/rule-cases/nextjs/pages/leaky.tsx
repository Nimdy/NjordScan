export default function Leaky({ stripeKey }: { stripeKey: string }) {
  return <div data-k={stripeKey}>page</div>;
}

// VULNERABLE: a server-only secret is placed directly into props, which ship to
// the browser.
export async function getServerSideProps() {
  return {
    props: {
      stripeKey: process.env.STRIPE_SECRET_KEY,
    },
  };
}
