// Renders the note named in the URL fragment. The innerHTML sink is planted on purpose for the Kestrix demo.
export function showNote(element) {
  element.innerHTML = decodeURIComponent(location.hash.slice(1));
}
