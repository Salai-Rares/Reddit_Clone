package com.example.Reddit_clone.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
//Through this class we are transferring the user details like username, password and email as part of the RequestBody
public class RegisterRequest {
    private String username;
    private String email;
    private String password;
}