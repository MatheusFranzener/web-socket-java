package br.senai.sc.editoralivros.service;

import br.senai.sc.editoralivros.model.entity.Autor;
import br.senai.sc.editoralivros.model.entity.Livro;
import br.senai.sc.editoralivros.model.enums.Status;
import br.senai.sc.editoralivros.repository.LivroRepository;
import lombok.AllArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@AllArgsConstructor
@Service
public class LivroService {

    private LivroRepository livroRepository;

    public Livro save(Livro livro){
        return livroRepository.save(livro);
    }

    @Transactional
    public Optional<Livro> findById(Long isbn){
        return livroRepository.findById(isbn);
    }

    public List<Livro> findByStatus(Status status){
        return livroRepository.findByStatus(status);
    }

    public List<Livro> findByAutor(Autor autor){
        return livroRepository.findByAutor(autor);
    }

    public List<Livro> findAll(){
        System.out.println("findAll Service");
        return livroRepository.findAll();
    }

    public Page<Livro> findAll(Pageable pageable){
        return livroRepository.findAll(pageable);
    }

    public void deleteById(Long isbn){
        livroRepository.deleteById(isbn);
    }

    public boolean existsById(Long isbn) {
        return livroRepository.existsById(isbn);
    }


    public List<Livro> findByIsbnAndStatus(Long isbn, Status status){
        return livroRepository.findByIsbnAndStatus(isbn, status);
    }
    public List<Livro> findByPesquisa(String pesquisa){
        return livroRepository.findByPesquisa(pesquisa);
    }

}
