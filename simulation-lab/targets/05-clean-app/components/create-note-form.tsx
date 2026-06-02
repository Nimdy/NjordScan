'use client';

import { useRef, useState, useTransition } from 'react';

import { createNoteAction } from '@/app/actions/notes';

/**
 * Client form for creating a note. Mutations go through the Server Action; the
 * component never touches the database directly and never stores anything
 * sensitive in the browser.
 */
export function CreateNoteForm(): JSX.Element {
  const formRef = useRef<HTMLFormElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  function onSubmit(formData: FormData): void {
    setError(null);
    startTransition(async () => {
      const result = await createNoteAction(formData);
      if (result.success) {
        formRef.current?.reset();
      } else {
        setError(result.error);
      }
    });
  }

  return (
    <form ref={formRef} action={onSubmit}>
      <label htmlFor="title">Title</label>
      <input id="title" name="title" type="text" maxLength={120} required />

      <label htmlFor="body">Body</label>
      <textarea id="body" name="body" maxLength={10000} required />

      {error ? <p role="alert">{error}</p> : null}

      <button type="submit" disabled={isPending}>
        {isPending ? 'Saving…' : 'Add note'}
      </button>
    </form>
  );
}
