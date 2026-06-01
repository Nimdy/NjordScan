export function Vuln({ userUrl, redirectUrl }) {
  return (
    <nav>
      <a href={userUrl}>Profile link</a>
      <a href={redirectUrl}>Continue</a>
    </nav>
  );
}
