package com.secure.notesapp.dto;

public record ResetPasswordRequest(String token,String newPassword){
}
