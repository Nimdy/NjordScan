import $ from 'jquery';
import DOMPurify from 'dompurify';

export function show(userInput, userHtml) {
  // .text() escapes everything — safe.
  $('#output').text(userInput);

  // Static literal markup is fine.
  $('.list').html('<li class="empty">No results</li>');

  // If raw HTML is unavoidable, sanitize first.
  $('#rich').html(DOMPurify.sanitize(userHtml));
}
