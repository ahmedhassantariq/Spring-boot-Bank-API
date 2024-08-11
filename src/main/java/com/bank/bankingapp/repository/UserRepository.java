package com.bank.bankingapp.repository;

import com.bank.bankingapp.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Transactional
public interface UserRepository extends JpaRepository<User, Long> {
    Boolean existsByEmail (String email);
    Boolean existsByAccountNumber (String accountNumber);
    User findByAccountNumber (String accountNumber);
    void deleteByAccountNumber (String accountNumber);
//    void updateByAccountNumber(String account, String firstName, String lastName, String email);
    List<User> findAll();
}
