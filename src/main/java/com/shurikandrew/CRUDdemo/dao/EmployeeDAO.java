package com.shurikandrew.CRUDdemo.dao;

import com.shurikandrew.CRUDdemo.entity.Employee;

import java.util.List;

public interface EmployeeDAO {
    List<Employee> findAll();

    Employee findById(int id);

    Employee update(Employee employee);

    void delete(int id);
}
