// NEGATIVE: Safe output
function safeOutput(userInput) {
    // Safe: textContent
    document.getElementById('output').textContent = userInput;
    // Safe: DOMPurify
    element.innerHTML = DOMPurify.sanitize(userInput);
    // Safe: innerText
    div.innerText = userInput;
}
