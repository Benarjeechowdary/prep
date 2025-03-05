// Get all OTP input fields
const otpInputs = document.querySelectorAll('.otp-input');

// Add event listeners to each input
otpInputs.forEach((input, index) => {
    // Handle input event for forward movement
    input.addEventListener('input', () => {
        if (input.value && index < otpInputs.length - 1) {
            otpInputs[index + 1].focus(); // Move to the next input
        }
    });

    // Handle backspace event for backward movement
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Backspace' && !input.value && index > 0) {
            otpInputs[index - 1].focus(); // Move to the previous input
        }
    });
});

// Submit OTP form by concatenating values and storing it in a hidden input
document.querySelector('.verify-btn').addEventListener('click', function(event) {
    event.preventDefault(); // Prevent default form submission

    let otp = '';
    otpInputs.forEach(input => {
        otp += input.value; // Concatenate the OTP values from all input fields
    });

    // Check if OTP is complete (optional)
    if (otp.length === otpInputs.length) {
        // Create a hidden input field to hold the OTP value
        const otpInputField = document.createElement('input');
        otpInputField.type = 'hidden';
        otpInputField.name = 'otp'; // Same name as in the backend
        otpInputField.value = otp;

        // Append the hidden input to the form
        document.querySelector('form').appendChild(otpInputField);

        // Submit the form
        document.querySelector('form').submit();
    } else {
        alert('Please enter a valid OTP.');
    }
});
