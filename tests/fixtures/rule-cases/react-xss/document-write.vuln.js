export function render(userInput) {
  document.write('<div>' + userInput + '</div>');
  document.writeln(buildRow(userInput));
}
