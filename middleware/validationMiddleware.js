const Joi = require('joi');
const validationConfig = require('../config/validationConfig');
const handleError = require('../utils/errorHandler');

const validate = (schema) => (req, res, next) => {
    const { error } = schema.validate(req.body, { abortEarly: false });
    if (error) {
        const errorMessage = error.details.map(detail => detail.message.replace(/\"/g, '')).join(', ');
        return handleError(res, 400, errorMessage);
    }
    next();
};

const schemas = {
    register: Joi.object({
        name: Joi.string().min(3).max(30).required(),
        email: Joi.string().pattern(validationConfig.email.regex).required().messages({
            'string.pattern.base': validationConfig.email.message
        }),
        password: Joi.string().min(validationConfig.password.minLength).max(validationConfig.password.maxLength).pattern(validationConfig.password.regex).required().messages({
            'string.pattern.base': validationConfig.password.message
        })
    }),
    login: Joi.object({
        email: Joi.string().pattern(validationConfig.email.regex).required().messages({
            'string.pattern.base': validationConfig.email.message
        }),
        password: Joi.string().required()
    }),
    updateUser: Joi.object({
        name: Joi.string().min(3).max(30),
        email: Joi.string().pattern(validationConfig.email.regex).messages({
            'string.pattern.base': validationConfig.email.message
        }),
        password: Joi.string().min(validationConfig.password.minLength).max(validationConfig.password.maxLength).pattern(validationConfig.password.regex).messages({
            'string.pattern.base': validationConfig.password.message
        }),
        confirmPassword: Joi.string().valid(Joi.ref('password')).messages({
            'any.only': 'Passwords do not match'
        })
    }),
    requestPasswordReset: Joi.object({
        email: Joi.string().pattern(validationConfig.email.regex).required().messages({
            'string.pattern.base': validationConfig.email.message
        })
    }),
    resetPassword: Joi.object({
        token: Joi.string().required(),
        newPassword: Joi.string().min(validationConfig.password.minLength).max(validationConfig.password.maxLength).pattern(validationConfig.password.regex).required().messages({
            'string.pattern.base': validationConfig.password.message
        })
    })
};

module.exports = {
    validate,
    schemas
};