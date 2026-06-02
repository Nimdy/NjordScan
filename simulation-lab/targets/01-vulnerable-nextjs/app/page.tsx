import Link from "next/link";

export default function HomePage() {
  return (
    <main style={{ maxWidth: 640, margin: "4rem auto" }}>
      <h1>ShopDash</h1>
      <p>Internal admin dashboard.</p>
      <ul>
        <li>
          <Link href="/login">Sign in</Link>
        </li>
        <li>
          <Link href="/profile">My profile</Link>
        </li>
      </ul>
    </main>
  );
}
