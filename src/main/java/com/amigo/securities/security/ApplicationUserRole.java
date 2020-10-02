package com.amigo.securities.security;

import com.google.common.collect.Sets;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Set;

import static com.amigo.securities.security.ApplicationUserPermission.*;

@AllArgsConstructor
@Getter
public enum ApplicationUserRole {
    // 2个角色 STUDENT 和 ADMIN
    // STUDENT 没有权限
    // ADMIN 拥有COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE 权限
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE));

    private final Set<ApplicationUserPermission> permissions;
}
