package com.example.oauth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
public class RegisteredClientController {

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @GetMapping("/registeredClients")
    public List<RegisteredClient> registeredClientList(){
        RegisteredClient registredClient1 = registeredClientRepository.findByClientId("oauth2-client-app1");
        RegisteredClient registredClient2 = registeredClientRepository.findByClientId("oauth2-client-app1");
        RegisteredClient registredClient3 = registeredClientRepository.findByClientId("oauth2-client-app1");

        return Arrays.asList(registredClient1,registredClient2,registredClient3);
    }
}
