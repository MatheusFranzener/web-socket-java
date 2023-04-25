package br.senai.sc.editoralivros.repository;

import br.senai.sc.editoralivros.model.entity.Autor;
import br.senai.sc.editoralivros.model.entity.Livro;
import br.senai.sc.editoralivros.model.enums.Status;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface LivroRepository extends JpaRepository<Livro,Long> {
    List<Livro> findByStatus(Status status);
    List<Livro> findByAutor(Autor autor);
    List<Livro> findByIsbnAndStatus(Long isbn, Status status);
    @Query(value = "SELECT * FROM tb_pessoa u WHERE u.status = :pesquisa OR u.titulo = :pesquisa OR u.autor = :pesquisa OR u.qtdPag = :pesquisa OR u.revisor = :pesquisa OR u.pagRevisadas = :pesquisa OR u.editora = :pesquisa",
           nativeQuery = true)
    List<Livro> findByPesquisa(@Param("pesquisa") String pesquisa);
}
