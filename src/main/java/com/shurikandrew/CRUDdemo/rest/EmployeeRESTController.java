package com.shurikandrew.CRUDdemo.rest;

import com.shurikandrew.CRUDdemo.entity.Employee;
import com.shurikandrew.CRUDdemo.service.EmployeeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class EmployeeRESTController {
    private EmployeeService employeeService;

    @Autowired
    public EmployeeRESTController(EmployeeService employeeService) {
        this.employeeService = employeeService;
    }

    @GetMapping("/employees")
    public List<Employee> findAll(){
        return employeeService.findAll();
    }

    @GetMapping("/employees/{employeeId}")
    public Employee getEmployee(@PathVariable int employeeId){
        Employee emp = employeeService.findById(employeeId);

        if(emp == null){
            throw new RuntimeException("No Employee with given Id - " + employeeId);
        }

        return emp;
    }

    @DeleteMapping("/employees/{employeeId}")
    public String deleteEmployee(@PathVariable int employeeId){
        Employee emp = employeeService.findById(employeeId);

        if(emp == null){
            throw new RuntimeException("No Employee with given Id - " + employeeId);
        }
        employeeService.delete(employeeId);
        return "Deleted employee - " + emp;
    }

    @PostMapping("/employees")
    public Employee addEmployee(@RequestBody Employee employee ){
        employee.setId(0);

        Employee emp = employeeService.save(employee);

        return emp;
    }

    @PutMapping("/employees")
    public Employee updateEmployee(@RequestBody Employee employee){
        Employee emp = employeeService.save(employee);
        return emp;
    }
}
