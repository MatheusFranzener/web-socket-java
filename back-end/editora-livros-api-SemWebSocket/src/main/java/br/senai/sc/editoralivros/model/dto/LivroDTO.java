package br.senai.sc.editoralivros.model.dto;

import br.senai.sc.editoralivros.model.entity.*;
import br.senai.sc.editoralivros.model.enums.Status;
import lombok.Getter;

import java.util.List;

@Getter
public class LivroDTO {
    private Long isbn;
    private String titulo;
    private Autor autor;
    private Revisor revisor;
    private Integer qtdPag;
    private Integer pagRevisadas;
    private Status status;
    private Editora editora;
    private List<Arquivo> arquivos;
}
