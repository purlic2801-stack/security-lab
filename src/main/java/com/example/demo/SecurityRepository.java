package com.example.demo;

import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class SecurityRepository {
    private final JdbcTemplate jdbc;

    public SecurityRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<String> findByName(String name) {
        return jdbc.queryForList(
            "SELECT name FROM products WHERE LOWER(name) = LOWER(?) ORDER BY id",
            String.class,
            name
        );
    }

public List<String> findByNameVulnerable(String name) {
    String sql = "SELECT name FROM products WHERE name = '" + name + "' ORDER BY id";
    return jdbc.queryForList(sql, String.class);
}
}