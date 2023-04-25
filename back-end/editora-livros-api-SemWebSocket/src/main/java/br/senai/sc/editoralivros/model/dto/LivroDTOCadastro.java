package br.senai.sc.editoralivros.model.dto;

import br.senai.sc.editoralivros.model.entity.Arquivo;
import br.senai.sc.editoralivros.model.entity.Autor;
import br.senai.sc.editoralivros.model.entity.Revisor;
import lombok.Getter;

import java.util.List;

@Getter
public class LivroDTOCadastro {
    private Long isbn;
    private String titulo;
    private Autor autor;
    private Integer qtdPag;
}
