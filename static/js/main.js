function showNotification(message) {
    const notification = document.querySelector('.notification');
    notification.textContent = message;
    notification.style.display = 'block';

    setTimeout(() => {
        notification.style.display = 'none';
    }, 3000); // Powiadomienie znika po 3 sekundach
}

document.addEventListener('DOMContentLoaded', function() {
    const advancedModeCheckbox = document.getElementById('advanced-mode');
    const advancedOptions = document.getElementById('advanced-options');
    const addActionButton = document.getElementById('add-action');
    const actionsContainer = document.getElementById('actions-container');
    const assistantForm = document.getElementById('assistant-form');

    if (advancedModeCheckbox) {
        advancedModeCheckbox.addEventListener('change', function() {
            advancedOptions.style.display = this.checked ? 'block' : 'none';
        });
    }

    if (addActionButton) {
        addActionButton.addEventListener('click', function() {
            const actionDiv = document.createElement('div');
            actionDiv.innerHTML = `
                <input type="text" placeholder="Trigger" name="action_trigger[]" required>
                <input type="text" placeholder="Response" name="action_response[]" required>
                <select name="action_ai_action[]">
                    <option value="">No Action</option>
                    <option value="hangup">Hang Up</option>
                    <option value="transfer">Transfer</option>
                </select>
                <button type="button" class="remove-action">Remove Action</button>
            `;
            actionsContainer.appendChild(actionDiv);
        });
    }

    if (actionsContainer) {
        actionsContainer.addEventListener('click', function(e) {
            if (e.target.classList.contains('remove-action')) {
                e.target.parentElement.remove();
            }
        });
    }

    if (assistantForm) {
        assistantForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            const assistant = Object.fromEntries(formData);
            
            // Handle actions
            assistant.actions = [];
            const triggers = formData.getAll('action_trigger[]');
            const responses = formData.getAll('action_response[]');
            const aiActions = formData.getAll('action_ai_action[]');
            for (let i = 0; i < triggers.length; i++) {
                assistant.actions.push({
                    trigger: triggers[i],
                    response: responses[i],
                    aiAction: aiActions[i] || null
                });
            }

            fetch('/create_assistant', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(assistant),
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Assistant created successfully!');
                    // Redirect to Your Assistants page or clear the form
                } else {
                    alert('Error creating assistant: ' + data.message);
                }
            })
            .catch((error) => {
                console.error('Error:', error);
                alert('An error occurred while creating the assistant.');
            });
        });
    }
});