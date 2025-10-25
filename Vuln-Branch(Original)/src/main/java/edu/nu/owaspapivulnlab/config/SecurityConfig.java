package edu.nu.owaspapivulnlab.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.*;

import java.io.IOException;
import java.util.Collections;

@Configuration
public class SecurityConfig {

    @Value("${app.jwt.secret}")
    private String secret;

    // VULNERABILITY(API7 Security Misconfiguration): overly permissive CORS/CSRF and antMatchers order
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable()); // APIs typically stateless; but add CSRF for state-changing in real apps
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.authorizeHttpRequests(reg -> reg
                .requestMatchers("/api/auth/login", "/api/auth/register", "/h2-console/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/users").permitAll() // Allow user registration
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/**").authenticated()
                .anyRequest().authenticated()
        );

        // Configure authentication entry point to return 401 instead of 403
        http.exceptionHandling(ex -> ex
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Unauthorized\"}");
                })
        );

        http.headers(h -> h.frameOptions(f -> f.disable())); // allow H2 console

        http.addFilterBefore(new JwtFilter(secret), org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // Enhanced JWT filter with proper validation
    static class JwtFilter extends OncePerRequestFilter {
        private final String secret;
        private static final String EXPECTED_ISSUER = "owasp-api-vuln-lab";
        private static final String EXPECTED_AUDIENCE = "api-users";
        
        JwtFilter(String secret) { this.secret = secret; }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            String auth = request.getHeader("Authorization");
            if (auth != null && auth.startsWith("Bearer ")) {
                String token = auth.substring(7);
                try {
                    Claims c = Jwts.parserBuilder()
                            .setSigningKey(secret.getBytes())
                            .requireIssuer(EXPECTED_ISSUER)
                            .requireAudience(EXPECTED_AUDIENCE)
                            .build()
                            .parseClaimsJws(token).getBody();
                    
                    String user = c.getSubject();
                    String role = (String) c.get("role");
                    UsernamePasswordAuthenticationToken authn = new UsernamePasswordAuthenticationToken(user, null,
                            role != null ? Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role)) : Collections.emptyList());
                    SecurityContextHolder.getContext().setAuthentication(authn);
                } catch (JwtException e) {
                    // Enhanced security: reject invalid tokens instead of continuing as anonymous
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Invalid or expired token\"}");
                    return;
                }
            }
            chain.doFilter(request, response);
        }
    }
}
