package com.yunuskaya.jwttokenspringsecurity.dto;


import com.yunuskaya.jwttokenspringsecurity.model.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CreateUserRequest {

    private String name;
    private String username;
    private String password;
    Set<Role> authorities;
}
