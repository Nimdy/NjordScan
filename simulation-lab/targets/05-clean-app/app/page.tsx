import Link from 'next/link';

/**
 * Public landing page. No data access, no user input — just a description and a
 * link into the protected area.
 */
export default function HomePage(): JSX.Element {
  const appName = process.env.NEXT_PUBLIC_APP_NAME ?? 'Secure Notes';
  return (
    <section>
      <h1>{appName}</h1>
      <p>
        A tiny demonstration app that stores private notes. Sessions are
        cookie-based and hardened, queries are parameterized, and a strict
        Content-Security-Policy is set for every route.
      </p>
      <p>
        <Link href="/login">Sign in to continue</Link>
      </p>
    </section>
  );
}
