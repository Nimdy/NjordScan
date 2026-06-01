function renderInto(target, value) {
  target.innerHTML = value;
}
export function showComment(req) {
  const node = document.getElementById('c');
  const userInput = req.body.comment;
  renderInto(node, userInput);
}
