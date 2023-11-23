function submitForm() {
    let form = document.getElementById("userForm");
    let formData = new FormData(form);

    fetch('/create_user', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(Object.fromEntries(formData)),
    })
    .then(response => response.json())
    .then(data => {
        console.log('Success:', data);
        // Optionally, redirect to a new page or update the UI
    })
    .catch((error) => {
        console.error('Error:', error);
        // Handle errors
    });
}