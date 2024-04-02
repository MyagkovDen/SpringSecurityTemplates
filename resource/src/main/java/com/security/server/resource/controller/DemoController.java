package com.security.server.resource.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {
//    @GetMapping("/demo")
//    public String demo() {
//        return "Demo";
//    }

    @GetMapping("/demo")
    public Authentication demo(Authentication a) {
        return a;
    }
}