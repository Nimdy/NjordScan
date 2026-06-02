import { requireUser } from '@/lib/auth';
import { listNotesForOwner } from '@/lib/db';
import { NoteList } from '@/components/note-list';
import { CreateNoteForm } from '@/components/create-note-form';
import { signOutAction } from '@/app/actions/auth';

/**
 * Protected notes page (Server Component). `requireUser` fails closed, and every
 * query is scoped to the authenticated owner, so users only ever see their own
 * notes.
 */
export default async function NotesPage(): Promise<JSX.Element> {
  const ownerId = requireUser();
  const notes = await listNotesForOwner(ownerId);

  return (
    <section>
      <div>
        <h1>Your notes</h1>
        <form action={signOutAction}>
          <button type="submit">Sign out</button>
        </form>
      </div>

      <CreateNoteForm />
      <NoteList notes={notes} />
    </section>
  );
}
