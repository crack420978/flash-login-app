
    const passwordInput = document.querySelector('input[name="password"]');
    const usernameInput = document.querySelector('input[name="username"]');     
    const vulResult = document.getElementById('vul-result');
    const strengthResult = document.getElementById('strength-result');
    const vulBar = document.getElementById('vul-bar');

    passwordInput.addEventListener('input', () => {
       fetch("/check_password", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                username: usernameInput.value,
                password: passwordInput.value   
            })
        })
        .then(response => response.json())
        .then(data => {
            vulResult.textContent = `vulnerability: ${data.vulnerability}%`;
            strengthResult.textContent = `strength: ${data.strength}%`;
            vulBar.style.width = `${data.vulnerability}%`;

            if (data.vulnerability < 30) {
                vulBar.style.backgroundColor = 'green';
            } else if (data.vulnerability < 70) {
                vulBar.style.backgroundColor = 'orange';
            } else {
                vulBar.style.backgroundColor = 'red';
            }
        });
    }); 