module.exports = {
    password: {
        minLength: 8,
        maxLength: 128,
        regex: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
        message: 'Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character.'
    },
    email: {
        regex: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        message: 'Invalid email format.'
    }
};

/*
Example Password Regex Patterns:

1. At least 8 characters, one uppercase, one lowercase, one number, and one special character:
   /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/
   - Explanation: 
     - (?=.*[a-z]): At least one lowercase letter
     - (?=.*[A-Z]): At least one uppercase letter
     - (?=.*\d): At least one digit
     - (?=.*[@$!%*?&]): At least one special character
     - [A-Za-z\d@$!%*?&]{8,}: Minimum length of 8 characters

2. At least 10 characters, one uppercase, one lowercase, and one number:
   /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{10,}$/
   - Explanation: 
     - (?=.*[a-z]): At least one lowercase letter
     - (?=.*[A-Z]): At least one uppercase letter
     - (?=.*\d): At least one digit
     - [A-Za-z\d]{10,}: Minimum length of 10 characters

3. At least 12 characters, one uppercase, one lowercase, one number, one special character, and no spaces:
   /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/
   - Explanation: 
     - (?=.*[a-z]): At least one lowercase letter
     - (?=.*[A-Z]): At least one uppercase letter
     - (?=.*\d): At least one digit
     - (?=.*[@$!%*?&]): At least one special character
     - [A-Za-z\d@$!%*?&]{12,}: Minimum length of 12 characters
     - No spaces allowed

4. At least 8 characters, one uppercase, one lowercase, one number, one special character, and no repeating characters:
   /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])(?!.*(.)\1)[A-Za-z\d@$!%*?&]{8,}$/
   - Explanation: 
     - (?=.*[a-z]): At least one lowercase letter
     - (?=.*[A-Z]): At least one uppercase letter
     - (?=.*\d): At least one digit
     - (?=.*[@$!%*?&]): At least one special character
     - (?!.*(.)\1): No repeating characters
     - [A-Za-z\d@$!%*?&]{8,}: Minimum length of 8 characters
*/