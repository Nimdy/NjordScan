import type { Metadata } from 'next';
import type { ReactNode } from 'react';

export const metadata: Metadata = {
  title: 'Secure Notes',
  description: 'A small notes app with security headers, hardened sessions, and parameterized queries.',
};

export default function RootLayout({ children }: { children: ReactNode }): JSX.Element {
  return (
    <html lang="en">
      <body>
        <header>
          <nav aria-label="Primary">
            <a href="/">Home</a>
            <a href="/notes">My notes</a>
          </nav>
        </header>
        <main>{children}</main>
        <footer>
          <p>
            Built with Next.js. See the{' '}
            <a
              href="https://nextjs.org/docs/app/building-your-application/configuring/content-security-policy"
              target="_blank"
              rel="noopener noreferrer"
            >
              security headers guide
            </a>
            .
          </p>
        </footer>
      </body>
    </html>
  );
}
