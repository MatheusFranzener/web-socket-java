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

// Classe responsável
@Configuration
public class AutenticacaoConfig {

    // Criado para usar o nosso usuário e nossos dados ( caso contrário usaria o padrão ( userDetailsService))
    @Autowired
    private JpaService jpaService;

    @Autowired
    private GoogleService googleService;

    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(jpaService).passwordEncoder(NoOpPasswordEncoder.getInstance());
    }

    // Método para configuração do cors
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Permite o acesso das origens
        configuration.setAllowedOrigins(List.of(
                "http://localhost:3000",
                "https://localhost:3000",
                "http://editorasenaiweb:3000",
                "https://editorasenaiweb:3000",
                "http://nginx:80",
                "https://nginx:443"));

        // Permite os métodos
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));

        // Permite o acesso aos cookies
        configuration.setAllowCredentials(true);

        // Permite todos os tipos de headers
        configuration.setAllowedHeaders(List.of("*"));


        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        // Registra a configuração para todos os caminhos da nossa aplicação
        // Também posso permitir o acesso ao cors para apenas um caminho como por exemplo "/login"
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    // Método responsável por permitir as autorizações de acesso
    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                // Permitido mesmo sem autorização
                .antMatchers("/editora-livros-api/login/auth"
                        , "/editora-livros-api/login"
                        , "/api-docs/**"
                        , "/swagger.html"
                        , "/swagger-ui/**"
//                        ,"/editora-livros-api/**"
                ).permitAll()
//                .antMatchers("/login").permitAll()
                // Permitido requisições específicas
                .antMatchers(HttpMethod.POST, "/editora-livros-api/livro").hasAuthority("Autor")
                .anyRequest().authenticated();
//        http.exceptionHandling()
//                        .accessDeniedPage("/login");
        // Desabilitado por questões de segurança
        http.csrf().disable();

        //        http.cors().disable();
//        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());

        // Libera o acesso quando outra API está consumindo a nossa
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

        // Habilita o logout automatico do usuario com o "/logou" por exemplo
        http.logout()
//                .logoutSuccessUrl("http://localhost:3000/home")
//                .invalidateHttpSession(true)

                // quando realizado o logout também são deletados os cookies
                .deleteCookies("jwt", "user")
                .permitAll();

        // Se não colocar nada aqui a sessão vai ser mantida
        // Se colocar o STATELESS a sessão não vai ser mantida, cada vez que faço acesso tenho que validar o token ( usuário e senha )
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                // toda nova requisição irá passar pelo filtro
                .and().addFilterBefore(new AutenticacaoFiltro(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // Criado para poder realizar a autenticação passando o email e senha
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
