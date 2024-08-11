package com.bank.bankingapp.controller;

import com.bank.bankingapp.dto.*;
import com.bank.bankingapp.entity.User;
import com.bank.bankingapp.service.impl.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
    @RequestMapping("/api/user")
@CrossOrigin
@Tag(name = "User Account Management APIs")
public class UserController {
        @Autowired
        UserService userService;
        @Operation(
                summary = "Create New User Account",
                description = "Creating a new user and assigning an account ID"
        )
        @ApiResponse(
                responseCode = "201",
                description = "Http Status 201 CREATED"
        )
        @PostMapping
        public BankResponse createAccount(@RequestBody UserRequest userRequest){
            return userService.createAccount(userRequest);
        }
    @Operation(
            summary = "Balance Enquiry",
            description = "Given an account number, check how much the user has"
    )
    @ApiResponse(
            responseCode = "200",
            description = "Http Status 200 SUCCESS"
    )
        @GetMapping("balanceEnquiry")
    public BankResponse balanceEnquiry(@RequestBody EnquiryRequest request){
            return userService.balanceEnquiry(request);
        }
        @GetMapping("nameEnquiry")
    public User nameEnquiry(@RequestBody EnquiryRequest request){
            return userService.nameEnquiry(request);
        }

        @PostMapping("credit")
    public BankResponse creditAccount(@RequestBody CreditDebitRequest request){
            return userService.creditAccount(request);
        }

    @PostMapping(value = "delete")
    public BankResponse deleteAccount(@RequestBody DeleteRequest request){
        return userService.deleteUser(request);
    }

    @PostMapping(value = "update")
    public BankResponse updateAccount(@RequestBody UpdateRequest request){
        return userService.updateUser(request);
    }

    @PostMapping("debit")
    public BankResponse debitAccount(@RequestBody CreditDebitRequest request){
            return userService.debitAccount(request);
    }

    @PostMapping("transfer")
    public BankResponse transfer(@RequestBody TransferRequest request){
            return userService.transfer(request);
        }

    @GetMapping("getUsers")
    public List<User> getUsers(){
        return userService.getUsers();
    }

    @GetMapping("getToken")
    public String getToken(@RequestBody EnquiryRequest request){return userService.getToken(request);}
}
