package br.senai.sc.editoralivros.security.filter;

import br.senai.sc.editoralivros.security.model.exceptions.ExCookieNaoEncontrado;
import br.senai.sc.editoralivros.security.model.exceptions.ExTokenInvalido;
import br.senai.sc.editoralivros.security.model.exceptions.ExUrlNaoPermitida;
import br.senai.sc.editoralivros.security.service.JpaService;
import br.senai.sc.editoralivros.security.model.entity.UserJpa;
import br.senai.sc.editoralivros.security.utils.CookieUtils;
import br.senai.sc.editoralivros.security.utils.JwtUtils;
import lombok.AllArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@AllArgsConstructor
public class AutenticacaoFiltro extends OncePerRequestFilter {



    private final CookieUtils cookieUtils = new CookieUtils();
    private final JwtUtils jwtUtils = new JwtUtils();

    @Override
    protected void doFilterInternal(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain) throws IOException, ServletException {
        try {
            String token = cookieUtils.getTokenCookie(request);
            System.out.println(token);
            jwtUtils.validarToken(token);

            System.out.println("valido");

            UserJpa user = cookieUtils.getUserCookie(request);
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(),
                            user.getPassword(), user.getAuthorities());
            System.out.println(usernamePasswordAuthenticationToken);
            SecurityContextHolder.getContext().setAuthentication(
                    usernamePasswordAuthenticationToken);
//            UserJpa user = cookieUtils.getUserCookie(request);
//            Cookie jwtCookie = cookieUtils.gerarTokenCookie(user);
//            response.addCookie(jwtCookie);
//            Cookie userCookie = cookieUtils.gerarUserCookie(user);
//            response.addCookie(userCookie);

//            Cookie jwtCookie = cookieUtils.renovarCookie(request, "jwt");
//            response.addCookie(jwtCookie);
//            Cookie userCookie = cookieUtils.renovarCookie(request, "user");
//            response.addCookie(userCookie);
        } catch (ExCookieNaoEncontrado | ExTokenInvalido e) {
            e.printStackTrace();
            try {
                validarUrl(request.getRequestURI());
            } catch (ExUrlNaoPermitida exUrlNaoPermitida) {
                exUrlNaoPermitida.printStackTrace();
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//                response.sendRedirect("http://localhost:3000/login");
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            System.out.println("Filtro finalizado");
            filterChain.doFilter(request, response);
        }
    }

    private void validarUrl(String url) throws ExUrlNaoPermitida {
        if (!(url.equals("/editora-livros-api/login/auth")
                || url.equals("/editora-livros-api/logout")
                || url.equals("http://localhost:3000/login")
                || url.equals("https://localhost:3000/login")
                || url.startsWith("/api-docs")
                || url.startsWith("/swagger")
//                || url.startsWith("/chat")
        )) {
            System.out.println("URL não permitida: " + url);
            throw new ExUrlNaoPermitida();
        }
        System.out.println("URL permitida: " + url);
    }
}
