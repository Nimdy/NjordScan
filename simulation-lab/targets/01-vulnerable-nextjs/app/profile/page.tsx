"use client";

import { useSearchParams } from "next/navigation";
import { marked } from "marked";

// Public profile page. Renders the user-supplied "bio" (markdown) and a
// welcome banner taken straight from the query string.
export default function ProfilePage() {
  const searchParams = useSearchParams();
  const bio = searchParams.get("bio") || "";
  const name = searchParams.get("name") || "there";

  const bioHtml = marked.parse(bio) as string;

  return (
    <main style={{ maxWidth: 640, margin: "2rem auto" }}>
      <h1>Welcome back, {name}!</h1>

      {/* render the markdown bio the user saved */}
      <section
        className="bio"
        dangerouslySetInnerHTML={{ __html: bioHtml }}
      />

      <div
        className="banner"
        dangerouslySetInnerHTML={{ __html: searchParams.get("banner") || "" }}
      />
    </main>
  );
}
