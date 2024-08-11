package com.bank.bankingapp.service.impl;

import com.bank.bankingapp.dto.*;
import com.bank.bankingapp.entity.User;

import java.util.List;

public interface UserService {
    BankResponse createAccount(UserRequest userRequest);
    BankResponse balanceEnquiry(EnquiryRequest request);
    User nameEnquiry(EnquiryRequest request);
    BankResponse creditAccount(CreditDebitRequest request);
    BankResponse debitAccount (CreditDebitRequest request);
    BankResponse transfer(TransferRequest request);
    BankResponse deleteUser(DeleteRequest request);

    BankResponse updateUser(UpdateRequest request);

    List<User> getUsers();

    String getToken(EnquiryRequest findUser);
}
