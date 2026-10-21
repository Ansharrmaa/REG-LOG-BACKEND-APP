package com.auth.reglog.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

/**
 * Class-level annotation that validates that two password fields match.
 * Apply to the DTO class (not a field).
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = PasswordMatchValidator.class)
@Documented
public @interface PasswordMatch {

    String message() default "Passwords do not match";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    /** Field name containing the password. */
    String passwordField() default "password";

    /** Field name containing the confirmation password. */
    String confirmPasswordField() default "confirmPassword";
}
