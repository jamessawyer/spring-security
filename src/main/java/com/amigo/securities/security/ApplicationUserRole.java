package com.amigo.securities.security;

import com.google.common.collect.Sets;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import static com.amigo.securities.security.ApplicationUserPermission.*;

@AllArgsConstructor
@Getter
public enum ApplicationUserRole {
    // 2个角色 STUDENT 和 ADMIN
    // STUDENT 没有权限
    // ADMIN 拥有COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE 权限
    // ADMINTRAINEE 只有读的权限
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)),
    ADMINTRAINEE(Sets.newHashSet(COURSE_READ, STUDENT_READ));

    private final Set<ApplicationUserPermission> permissions;


    // 自定义方法 获取不同Role 所有的 authorities
    public Set<SimpleGrantedAuthority> getGrantedAuthorities() {
        // 将Role拥有的permissions 存放到自定义的 Set<SimpleGrantedAuthority> 集合中
        Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
        // 将角色自身也添加到集合中
        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return permissions;
    }
}
