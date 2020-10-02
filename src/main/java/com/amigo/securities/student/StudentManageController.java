package com.amigo.securities.student;

import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManageController {
    private final List<Student> students = Arrays.asList(
            new Student(1, "James Leborn"),
            new Student(2, "Kobe Bryant"),
            new Student(3, "Michael Jordan")
    );

    @GetMapping
    public List<Student> getAllStudents() {
        System.out.println("Get All Students");
        return students;
    }

    @PostMapping
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println("registerNewStudent " + student);
    }

    @DeleteMapping(path = "{studentId}")
    public void deleteStudent(@PathVariable("studentId") Integer studentId) {
        System.out.println("deleteStudent id " + studentId);
    }

    @PutMapping(path = "{studentId}")
    public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student) {
        System.out.printf("%s %s%n", studentId, student);
    }
}
