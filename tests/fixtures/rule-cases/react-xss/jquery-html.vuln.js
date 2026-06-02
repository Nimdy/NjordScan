import $ from 'jquery';

export function show(userInput) {
  $('#output').html(userInput);
  $('.list').append(buildRow(userInput));
}
