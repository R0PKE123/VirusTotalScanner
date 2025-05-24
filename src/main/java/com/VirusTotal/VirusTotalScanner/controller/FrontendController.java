package com.VirusTotal.VirusTotalScanner.controller;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.IOException;

@Controller
public class FrontendController {
    @RequestMapping(value = {"/", "/{path:^(?!api$|settings$|dashboard$)[^\\.]*}", "/{path:^(?!api$|settings$|dashboard$)[^\\.]*}/**"})
    public void redirect(HttpServletResponse response) throws IOException {
        response.sendRedirect("/index.html");
    }
}