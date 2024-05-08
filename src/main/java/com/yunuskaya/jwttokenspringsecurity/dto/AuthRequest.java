package com.yunuskaya.jwttokenspringsecurity.dto;

public record AuthRequest (
        String username,
        String password
){
}
