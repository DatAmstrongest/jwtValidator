package com.kocmetehan.jwtValidator.response;

public class JWTResponse {
    private boolean valid;

    public JWTResponse(boolean valid) {
        this.valid = valid;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }
}
