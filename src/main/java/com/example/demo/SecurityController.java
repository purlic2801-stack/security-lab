package com.example.demo;

import java.net.URI;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import jakarta.servlet.http.HttpSession;

@Controller
public class SecurityController {

    private final SecurityRepository products;
    private final VulnerabilityState state;

    public SecurityController(SecurityRepository products, VulnerabilityState state) {
        this.products = products;
        this.state = state;
    }

    @GetMapping("/")
    public String index(@RequestParam(name = "name", required = false) String name,
                        Model model, HttpSession session) {
        if (name != null) {
            model.addAttribute("name", name);
            if (state.isSqlVulnerable()) {
                model.addAttribute("results", products.findByNameVulnerable(name));
            } else {
                model.addAttribute("results", products.findByName(name));
            }
        }
        boolean enabled = !Boolean.FALSE.equals(session.getAttribute("notificationsEnabled"));
        model.addAttribute("notificationsEnabled", enabled);
        model.addAttribute("sqlEnabled", state.isSqlVulnerable());
        model.addAttribute("csrfEnabled", state.isCsrfVulnerable());
        return "index";
    }

    @PostMapping("/preferences/notifications")
    public ResponseEntity<Void> updateNotifications(
            @RequestParam("enabled") boolean enabled, HttpSession session) {
        session.setAttribute("notificationsEnabled", enabled);
        return ResponseEntity.status(HttpStatus.SEE_OTHER)
                .location(URI.create("/")).build();
    }

    @PostMapping("/api/ukljuci-Ranjivost-SQL")
    @ResponseBody
    public void ukljuciRanjivostSQL(@RequestBody Map<String, Boolean> podaci) {
        state.setSqlVulnerable(Boolean.TRUE.equals(podaci.get("ukljuceno")));
    }

    @PostMapping("/api/ukljuci-Ranjivost-CSRF")
    @ResponseBody
    public void ukljuciRanjivostCsrf(@RequestBody Map<String, Boolean> podaci) {
        state.setCsrfVulnerable(Boolean.TRUE.equals(podaci.get("ukljuceno")));
    }
}