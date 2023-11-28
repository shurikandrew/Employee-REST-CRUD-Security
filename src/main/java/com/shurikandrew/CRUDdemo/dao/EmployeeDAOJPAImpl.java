package com.shurikandrew.CRUDdemo.dao;

import com.shurikandrew.CRUDdemo.entity.Employee;
import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class EmployeeDAOJPAImpl implements EmployeeDAO{

    private EntityManager manager;

    @Autowired
    public EmployeeDAOJPAImpl(EntityManager manager) {
        this.manager = manager;
    }

    @Override
    public List<Employee> findAll() {
        TypedQuery<Employee> query = manager.createQuery("from Employee", Employee.class);
        List<Employee> result = query.getResultList();
        return result;
    }

    @Override
    public Employee findById(int id) {
        Employee emp = manager.find(Employee.class, id);
        return emp;
    }

    @Override
    public Employee update(Employee employee) {
        Employee emp = manager.merge(employee);
        return emp;
    }

    @Override
    public void delete(int id) {
        Employee emp = manager.find(Employee.class, id);
        manager.remove(emp);
    }
}
