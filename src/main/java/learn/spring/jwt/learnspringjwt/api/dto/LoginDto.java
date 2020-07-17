package learn.spring.jwt.learnspringjwt.api.dto;


import lombok.Data;

@Data
public class LoginDto {
    private String username;
    private String password;
}
