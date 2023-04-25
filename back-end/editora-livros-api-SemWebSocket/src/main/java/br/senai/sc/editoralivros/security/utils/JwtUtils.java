package br.senai.sc.editoralivros.security.utils;

import br.senai.sc.editoralivros.security.model.entity.UserJpa;
import br.senai.sc.editoralivros.security.model.exceptions.ExTokenInvalido;
import io.jsonwebtoken.*;

import java.util.Date;

public class JwtUtils {

    private final String senhaForte = "c127a7b6adb013a5ff879ae71afa62afa4b4ceb72afaa54711dbcde67b6dc325";

    public String gerarToken(UserJpa usuario) {
        return Jwts.builder()
                .setIssuer("Editora de Livros")
                .setSubject(usuario.getPessoa().getCpf().toString())
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + 1800000))
                .signWith(SignatureAlgorithm.HS256, senhaForte)
                .compact();
    }



    public void validarToken(String token) throws ExTokenInvalido {
        try {
            Jwts.parser().setSigningKey(senhaForte).parseClaimsJws(token);
        } catch (Exception e) {
            throw new ExTokenInvalido();
        }
    }

    public Long getCpf(String token) {
        return Long.parseLong(Jwts.parser().
                setSigningKey(senhaForte).
                parseClaimsJws(token).
                getBody().
                getSubject());
    }


}
