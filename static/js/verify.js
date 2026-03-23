// PaySecure - verify.js

document.addEventListener('DOMContentLoaded', () => {
    const checkboxes = document.querySelectorAll('.step-check');
    const submitBtn = document.getElementById('submitBtn');
    const textarea = document.getElementById('message_input');

    const toggleButton = () => {
        const allChecked = Array.from(checkboxes).every(c => c.checked);
        submitBtn.disabled = !allChecked;
        submitBtn.style.opacity = allChecked ? '1' : '0.5';
    };

    checkboxes.forEach(c => c.addEventListener('change', toggleButton));
    
    
    if (textarea) {
        textarea.addEventListener('input', () => {
            const resultBox = document.querySelector('.result-box');
            if (resultBox) {
                resultBox.style.opacity = '0.3';
            }
        });
    }
});


document.addEventListener('DOMContentLoaded', () => {
    const checkboxes = document.querySelectorAll('.step-check');
    const submitBtn = document.getElementById('submitBtn');

    // Function to enable button only if ALL checkboxes are ticked
    const checkChecklist = () => {
        const allChecked = Array.from(checkboxes).every(box => box.checked);
        submitBtn.disabled = !allChecked;
        
        // Visual feedback for the student
        if (allChecked) {
            submitBtn.style.background = 'var(--green)';
            submitBtn.style.cursor = 'pointer';
        } else {
            submitBtn.style.background = '#444';
            submitBtn.style.cursor = 'not-allowed';
        }
    };

    checkboxes.forEach(box => {
        box.addEventListener('change', checkChecklist);
    });
});