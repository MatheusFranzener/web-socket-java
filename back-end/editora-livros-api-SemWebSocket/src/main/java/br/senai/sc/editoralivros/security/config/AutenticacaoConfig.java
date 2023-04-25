package br.senai.sc.editoralivros.security.config;

import br.senai.sc.editoralivros.security.filter.AutenticacaoFiltro;
import br.senai.sc.editoralivros.security.service.GoogleService;
import br.senai.sc.editoralivros.security.service.JpaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@Configuration
public class AutenticacaoConfig {

    @Autowired
    private JpaService jpaService;

    @Autowired
    private GoogleService googleService;

    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(jpaService).passwordEncoder(NoOpPasswordEncoder.getInstance());
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of(
                "http://localhost:3000",
                "https://localhost:3000",
                "http://editorasenaiweb:3000",
                "https://editorasenaiweb:3000",
                "http://nginx:80",
                "https://nginx:443"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        configuration.setAllowCredentials(true);
        configuration.setAllowedHeaders(List.of("*"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .antMatchers("/editora-livros-api/login/auth"
                        ,"/editora-livros-api/login"
                        ,"/api-docs/**"
                        ,"/swagger.html"
                        ,"/swagger-ui/**"
//                        ,"/editora-livros-api/**"
                ).permitAll()
//                .antMatchers("/login").permitAll()
//                .antMatchers(HttpMethod.POST,"/editora-livros-api/livro").hasAuthority("Autor")
                .anyRequest().authenticated();
//        http.exceptionHandling()
//                        .accessDeniedPage("/login");
        http.csrf().disable();
//        http.cors().disable();
//        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        http.cors().configurationSource(corsConfigurationSource());
//        http.cors().configurationSource(new CorsConfigurationSource() {
//            @Override
//            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
//                CorsConfiguration configuration = new CorsConfiguration();
//                configuration.setAllowedOrigins(List.of("https://localhost:3000"));
//                configuration.setAllowedMethods(Arrays.asList("HEAD", "GET", "POST", "PUT", "DELETE", "PATCH"));
//                configuration.setAllowCredentials(true);
//                configuration.setAllowedHeaders(Arrays.asList("*"));
//                configuration.addExposedHeader("Authorization");
//                configuration.addExposedHeader("Access-Control-Allow-Origin");
//                configuration.addExposedHeader("Access-Control-Allow-Credentials");
//                configuration.addExposedHeader("Access-Control-Allow-Methods");
//                configuration.addExposedHeader("Access-Control-Allow-Headers");
//                configuration.setMaxAge(3600L);
//                final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//                source.registerCorsConfiguration("/**", configuration);
//                return configuration;
//            }
//        });
//        http.headers()
//                .addHeaderWriter(new StaticHeadersWriter("Access-Control-Allow-Credentials", "true"))
//                .and()
//                .cors().disable()
                ;
//        http.formLogin()
//                .loginPage("/login")
//                .loginProcessingUrl("/login/auth")
//                .successForwardUrl("/home")
//                .failureForwardUrl("/login?error=true")
//                .passwordParameter("senha")
//                .usernameParameter("email")
//                .permitAll();
//        http.oauth2Login()
//                .loginPage("http://localhost:3000/login")
//                .userInfoEndpoint()
//                .userService(googleService)
//                .and()
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
//                        try {
//                            UserDetails userJpa = jpaService.loadUserByUsername(oAuth2User.getAttribute("email"));
//                            response.sendRedirect("http://localhost:3000/livros");
//                        } catch (UsernameNotFoundException e) {
//                            System.out.printf("Usuário não encontrado");
//                            response.sendRedirect("http://localhost:3000/login");
//                        }
//                    }
//                })
//                .permitAll();
//        http.apply(new AutenticacaoFiltro(jpaService);
        http.logout()
//                .logoutSuccessUrl("http://localhost:3000/home")
//                .invalidateHttpSession(true)
                .deleteCookies("jwt", "user")
                .permitAll();
        http.sessionManagement().sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS)
                .and().addFilterBefore(
                        new AutenticacaoFiltro(),
                        UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
//
//    @Bean
//    public AuthenticationManager authenticationManagerBean() throws Exception {
//        List<AuthenticationProvider> providers = new ArrayList<>();
//        providers.add(jpaAuthenticationProvider());
//        return new ProviderManager(providers);
//    }
//
//    @Bean
//    public AuthenticationProvider jpaAuthenticationProvider() {
//        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
//        provider.setUserDetailsService(jpaService);
//        provider.setPasswordEncoder(new BCryptPasswordEncoder());
//        return provider;
//    }

}
