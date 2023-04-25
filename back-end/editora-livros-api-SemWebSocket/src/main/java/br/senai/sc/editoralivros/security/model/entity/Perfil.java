package br.senai.sc.editoralivros.security.model.entity;

import org.springframework.security.core.GrantedAuthority;


public enum Perfil implements GrantedAuthority {
    DIRETOR("Diretor"),
    REVISOR("Revisor"),
    AUTOR("Autor");

    private String descricao;

    Perfil(String descricao) {
        this.descricao = descricao;
    }

    public static Perfil perfilOf(String simpleName) {
        return switch (simpleName) {
            case "Autor" -> AUTOR;
            case "Revisor" -> REVISOR;
            case "Diretor" -> DIRETOR;
            default -> null;
        };
    }

    @Override
    public String getAuthority() {
        return this.name();
    }
}
