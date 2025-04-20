function addField(containerId, fieldName) {
    const container = document.getElementById(containerId);
    const newField = document.createElement('div');
    newField.className = 'form-group';
    newField.innerHTML = `
        <input type="text" name="${fieldName}" placeholder="${getPlaceholder(fieldName)}" required>
        <button type="button" class="btn secondary" onclick="removeField(this)">Remove</button>
    `;
    container.appendChild(newField);
}

function removeField(button) {
    button.parentElement.remove();
}

function getPlaceholder(fieldName) {
    switch(fieldName) {
        case 'education':
            return 'Degree, Institution - Year';
        case 'experience':
            return 'Position - Company - Duration';
        case 'certifications':
            return 'Certification Name - Issuing Organization - Year';
        case 'projects':
            return 'Project Name - Description - Technologies Used';
        case 'skills':
            return 'Skill';
        default:
            return '';
    }
}