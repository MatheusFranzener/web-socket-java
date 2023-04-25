package br.senai.sc.editoralivros.model.dto;

import br.senai.sc.editoralivros.model.entity.Livro;
import br.senai.sc.editoralivros.model.entity.Pessoa;
import lombok.Data;
import lombok.Getter;

import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;

@Getter
public class MensagemChatDTO {
    private Livro livro;
    private Pessoa remetente;
    private String mensagem;
}
