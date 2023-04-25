package br.senai.sc.editoralivros.model.enums;

public enum Status {
    AGUARDANDO_REVISAO("Aguardando Revisão"),
    AGUARDANDO_EDICAO("Aguardando Edição"),
    EM_REVISAO("Em Revisão"),
    APROVADO("Aprovado"),
    REPROVADO("Reprovado"),
    PUBLICADO("Publicado");
    String nome;
    Status(String nome) {
        this.nome = nome;
    }
}
