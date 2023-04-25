package br.senai.sc.editoralivros.model.dto;

import br.senai.sc.editoralivros.model.enums.Genero;
import lombok.Data;

@Data
public class PessoaDTO {
//    @NotBlank
    private Long cpf;
//    @NotBlank
    private String nome;
//    @NotBlank
    private String sobrenome;
//    @NotBlank
    private String email;
//    @NotBlank
    private String senha;
//    @NotBlank
    private Genero genero;
}
