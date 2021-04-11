package com.example.Reddit_clone.config;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
//enables the Web Security module in our Project
@EnableWebSecurity

//WebSecurityConfigurerAdapter it provides us the default security configurations, which we can override in our SecurityConfig and customize them
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    /*
    Here, we are configuring Spring to allow all the requests which match the endpoint “/api/auth/**”
     as these endpoints are used for authentication and registration
    we don’t expect the user to be authenticated at that point of time
     */
    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf().disable()
                .authorizeRequests()
                .antMatchers("/api/auth/**")
                .permitAll()
                .anyRequest()
                .authenticated();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}