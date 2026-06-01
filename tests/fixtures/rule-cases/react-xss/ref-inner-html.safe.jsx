import { useRef, useEffect } from 'react';

export function Safe({ userText }) {
  const boxRef = useRef(null);
  useEffect(() => {
    // Inserted as text, never parsed as HTML.
    boxRef.current.textContent = userText;
  }, [userText]);
  return <div ref={boxRef}>{userText}</div>;
}
