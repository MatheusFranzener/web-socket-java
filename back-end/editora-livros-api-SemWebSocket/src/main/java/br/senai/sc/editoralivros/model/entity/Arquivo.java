package br.senai.sc.editoralivros.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;

import javax.persistence.*;

@Entity
@Table(name = "tb_arquivos")
@NoArgsConstructor(force = true)
@AllArgsConstructor
@RequiredArgsConstructor
@Getter @Setter
public class Arquivo {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @NonNull
    private String nome;
    @NonNull
    private String tipo;
    @NonNull
    @Lob
    private byte[] dados;
    @ManyToOne
    @JsonIgnore
    @JoinColumn(name = "livro_isbn")
    private Livro livro;

}
