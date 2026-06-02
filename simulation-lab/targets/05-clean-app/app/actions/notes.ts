'use server';

/**
 * Server Actions for notes. Each action:
 *   1. authenticates (requireUser fails closed),
 *   2. validates input with zod,
 *   3. scopes every query to the caller's ownerId,
 *   4. returns a typed result with a generic error message (no stack traces).
 */

import { revalidatePath } from 'next/cache';

import { requireUser } from '@/lib/auth';
import { createNote, deleteNote, type Note } from '@/lib/db';
import { noteIdSchema, noteInputSchema } from '@/lib/validation';

export type ActionResult<T> =
  | { success: true; data: T }
  | { success: false; error: string };

export async function createNoteAction(formData: FormData): Promise<ActionResult<Note>> {
  const ownerId = requireUser();

  const parsed = noteInputSchema.safeParse({
    title: formData.get('title'),
    body: formData.get('body'),
  });
  if (!parsed.success) {
    return { success: false, error: 'Please provide a title and body.' };
  }

  try {
    const note = await createNote(ownerId, parsed.data.title, parsed.data.body);
    revalidatePath('/notes');
    return { success: true, data: note };
  } catch {
    // Log nothing sensitive; surface a generic message to the client.
    return { success: false, error: 'Could not save the note. Please try again.' };
  }
}

export async function deleteNoteAction(formData: FormData): Promise<ActionResult<{ id: string }>> {
  const ownerId = requireUser();

  const parsed = noteIdSchema.safeParse(formData.get('id'));
  if (!parsed.success) {
    return { success: false, error: 'Invalid note reference.' };
  }

  try {
    const removed = await deleteNote(parsed.data, ownerId);
    if (removed === 0) {
      return { success: false, error: 'Note not found.' };
    }
    revalidatePath('/notes');
    return { success: true, data: { id: parsed.data } };
  } catch {
    return { success: false, error: 'Could not delete the note. Please try again.' };
  }
}
