package br.senai.sc.editoralivros.model.entity;

import br.senai.sc.editoralivros.model.enums.Status;
import lombok.*;
import org.springframework.web.multipart.MultipartFile;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "tb_livros")
@AllArgsConstructor
@NoArgsConstructor
@Data
public class Livro {

    @Id
//    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(length = 13, nullable = false, unique = true)
    private Long isbn;

    @Column(length = 50, nullable = false)
    private String titulo;

//    @ManyToMany
//    @JoinTable(name = "tb_livro_autor",
//        joinColumns =
//        @JoinColumn(name = "isbn_livro", nullable = false),
//        inverseJoinColumns =
//        @JoinColumn(name = "cpf_autor", nullable = false))
//    private List<Autor> autores;
    @ManyToOne
    @JoinColumn(name = "cpf_autor")
    private Autor autor;

    @Column(nullable = false)
    private Integer qtdPag;

    @ManyToOne
    @JoinColumn(name = "cpf_revisor")
    private Revisor revisor;

    @Column(length = 50, nullable = false)
    private Integer pagRevisadas = 0;

    @Column(nullable = false)
    private Status status;

    @ManyToOne
    private Editora editora;

    @OneToMany(mappedBy = "livro", cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    private List<Arquivo> arquivos;

    public void setArquivos(List<Arquivo> arquivos) {
        this.arquivos = (arquivos);
    }
}
