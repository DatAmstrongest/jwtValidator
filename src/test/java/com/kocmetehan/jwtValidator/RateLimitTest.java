package com.kocmetehan.jwtValidator;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "ratelimit.request.per.minute=1")
@AutoConfigureMockMvc
class RateLimitTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Should reject requests after the rate limit is consumed")
    void shouldRejectRequestsAfterRateLimitIsConsumed() throws Exception {
        mockMvc.perform(get("/auth"))
                .andExpect(status().isBadRequest());

        mockMvc.perform(get("/auth"))
                .andExpect(status().isTooManyRequests());
    }
}
