import type { Note } from '@/lib/db';

import { deleteNoteAction } from '@/app/actions/notes';

/**
 * Renders a list of notes. Titles and bodies are interpolated as React children
 * ({note.title}), which React escapes automatically — there is no
 * dangerouslySetInnerHTML and therefore no XSS sink.
 */
export function NoteList({ notes }: { notes: ReadonlyArray<Note> }): JSX.Element {
  if (notes.length === 0) {
    return <p>You have no notes yet. Create your first one above.</p>;
  }

  return (
    <ul>
      {notes.map((note) => (
        <li key={note.id}>
          <article>
            <h2>{note.title}</h2>
            <p>{note.body}</p>
            <time dateTime={note.createdAt}>{note.createdAt}</time>
            <form action={deleteNoteAction}>
              <input type="hidden" name="id" value={note.id} />
              <button type="submit" aria-label={`Delete note ${note.title}`}>
                Delete
              </button>
            </form>
          </article>
        </li>
      ))}
    </ul>
  );
}
