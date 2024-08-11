package com.bank.bankingapp.service.impl;

import com.bank.bankingapp.dto.EmailDetails;

public interface EmailService {
    void sendEmailAlert(EmailDetails emailDetails);
}
