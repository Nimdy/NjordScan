import { useRef, useEffect } from 'react';

export function Vuln({ userHtml }) {
  const boxRef = useRef(null);
  useEffect(() => {
    boxRef.current.innerHTML = userHtml;
  }, [userHtml]);
  return <div ref={boxRef} />;
}
