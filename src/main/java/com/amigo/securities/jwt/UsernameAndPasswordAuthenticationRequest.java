package com.amigo.securities.jwt;

import lombok.NoArgsConstructor;
import lombok.Getter;
import lombok.Setter;

// 表示客户端发送请求中携带的用户名和密码
@NoArgsConstructor
@Getter
@Setter
public class UsernameAndPasswordAuthenticationRequest {
    private String username;
    private String password;
}
