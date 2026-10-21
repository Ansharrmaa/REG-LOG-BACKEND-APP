package com.auth.reglog.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Generic success/message response wrapper.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse {

    private String message;
    private Object data;

    public ApiResponse() {
    }

    public ApiResponse(String message, Object data) {
        this.message = message;
        this.data = data;
    }

    public static ApiResponse of(String message) {
        return new ApiResponse(message, null);
    }

    public static ApiResponse of(String message, Object data) {
        return new ApiResponse(message, data);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String message;
        private Object data;

        public Builder message(String message) {
            this.message = message;
            return this;
        }

        public Builder data(Object data) {
            this.data = data;
            return this;
        }

        public ApiResponse build() {
            return new ApiResponse(message, data);
        }
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Object getData() {
        return data;
    }

    public void setData(Object data) {
        this.data = data;
    }
}
