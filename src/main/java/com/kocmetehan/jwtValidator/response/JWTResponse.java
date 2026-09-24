package com.kocmetehan.jwtValidator.response;

// This is the Response Class of the program, it returns a message if JWT is not valid
public class JWTResponse {
    private boolean valid;
    private String message;

    public JWTResponse(boolean valid, String message) {
        this.valid = valid;
        this.message = message;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
