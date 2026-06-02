export const metadata = {
  title: 'Acme Dashboard',
  description: 'Internal analytics dashboard',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
