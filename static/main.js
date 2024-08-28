function showNotification(message) {
    const notification = document.querySelector('.notification');
    notification.textContent = message;
    notification.style.display = 'block';

    setTimeout(() => {
        notification.style.display = 'none';
    }, 3000); // Powiadomienie znika po 3 sekundach
}