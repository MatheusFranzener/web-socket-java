package br.senai.sc.editoralivros.security.controller;

import br.senai.sc.editoralivros.security.model.dto.UsuarioDTO;
import br.senai.sc.editoralivros.security.utils.CookieUtils;
import br.senai.sc.editoralivros.security.utils.JwtUtils;
import br.senai.sc.editoralivros.security.service.JpaService;
import br.senai.sc.editoralivros.security.model.entity.UserJpa;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/editora-livros-api/login")
@CrossOrigin
@AllArgsConstructor
public class AutenticacaoController {

    private AuthenticationManager authenticationManager;

    private final CookieUtils cookieUtils = new CookieUtils();

    @PostMapping("/auth")
    public ResponseEntity<Object> autenticacao(
            @RequestBody UsuarioDTO usuarioDTO
            , HttpServletResponse response) {
        try {
            System.out.println("Autenticando usuário" + usuarioDTO.getEmail() + "..." + usuarioDTO.getSenha());
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(
                            usuarioDTO.getEmail(), usuarioDTO.getSenha());
            System.out.println(authenticationToken);
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);

            System.out.println(authentication.isAuthenticated());
            if (authentication.isAuthenticated()) {
                UserJpa user = (UserJpa) authentication.getPrincipal();
                System.out.println(user);
                Cookie jwtCookie = cookieUtils.gerarTokenCookie(user);
                System.out.println(jwtCookie.getValue());
                response.addCookie(jwtCookie);
                System.out.println("Cookie do token adicionado");
                Cookie userCookie = cookieUtils.gerarUserCookie(user);
                System.out.println(userCookie.getValue());
                response.addCookie(userCookie);
                System.out.println("Cookie do usuário adicionado");
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                        new UsernamePasswordAuthenticationToken(user.getUsername(),
                                user.getPassword(), user.getAuthorities());
                System.out.println(usernamePasswordAuthenticationToken);
                SecurityContextHolder.getContext().setAuthentication(
                        usernamePasswordAuthenticationToken);
                System.out.println("Contexto de segurança atualizado");
                return ResponseEntity.ok().build();
            }
        } catch (Exception e) {
            System.out.println("Erro ao autenticar usuário");
            System.out.println(e);

        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

    }

}
