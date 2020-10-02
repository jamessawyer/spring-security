package com.amigo.securities.student;

import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {
    private final List<Student> students = Arrays.asList(
            new Student(1, "James Leborn"),
            new Student(2, "Kobe Bryant"),
            new Student(3, "Michael Jordan")
    );

    @GetMapping(path = "{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId) {
        return students.stream()
                .filter(student -> studentId.equals(student.getId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Student " + studentId + " does not exist"));
    }
}
