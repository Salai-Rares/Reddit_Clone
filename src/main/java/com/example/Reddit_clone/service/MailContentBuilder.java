package com.example.Reddit_clone.service;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

@Service
@AllArgsConstructor
class MailContentBuilder {

    private final TemplateEngine templateEngine;
// takes our email message as input and it uses the Thymeleaf‘s TemplateEngine to generate the email message
    String build(String message) {
        Context context = new Context();
        context.setVariable("message", message);
        return templateEngine.process("mailTemplate", context);
    }
}