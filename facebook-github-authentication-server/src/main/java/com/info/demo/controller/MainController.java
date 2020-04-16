package com.info.demo.controller;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/main")
public class MainController {

    @Cacheable
    @RequestMapping("/test")
    public void test()  throws InterruptedException{
        Thread.sleep(100);
        System.out.println("test");
    }

}