package com.bank.bankingapp.service.impl;

import com.bank.bankingapp.dto.TransactionDto;
import com.bank.bankingapp.entity.Transaction;

public interface TransactionService {
    void saveTransaction(TransactionDto transactionDto);
}
