package br.senai.sc.editoralivros.controller;


import br.senai.sc.editoralivros.model.entity.Autor;
import br.senai.sc.editoralivros.model.entity.Livro;
import br.senai.sc.editoralivros.model.enums.Status;
import br.senai.sc.editoralivros.service.LivroService;
import br.senai.sc.editoralivros.util.LivroUtil;
import lombok.AllArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@AllArgsConstructor
@RequestMapping("/editora-livros-api/livro")
@RestController
public class LivroController {

    private LivroService livroService;
    private final LivroUtil livroUtil= new LivroUtil();

    @GetMapping("/{pesquisa}")
    public ResponseEntity<List<Livro>> findByPesquisa(@PathVariable(value = "pesquisa") String pesquisa) {
        return ResponseEntity.status(HttpStatus.OK).body(
                livroService.findByPesquisa(pesquisa));
    }

    @GetMapping("/get/{isbn}")
    public ResponseEntity<List<Livro>> findByIdAndStatus(@PathVariable(value = "isbn") Long isbn) {
        return ResponseEntity.status(HttpStatus.OK).body(
                livroService.findByIsbnAndStatus(isbn, Status.APROVADO));
    }

    @GetMapping("/isbn/{isbn}")
    public ResponseEntity<Object> findById(
            @PathVariable(value = "isbn") Long isbn) {
        Optional<Livro> livroOptional =  livroService.findById(isbn);
        if (livroOptional.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                    "O livro de ISBN " + isbn + " não foi encontrado.");
        }
        System.out.println(livroOptional.get());
        return ResponseEntity.status(HttpStatus.OK).body(
                livroOptional.get());
    }

    @GetMapping("/status/{status}")
    public ResponseEntity<List<Livro>> findByStatus(
            @PathVariable(value = "status") Status status) {
        return ResponseEntity.status(HttpStatus.FOUND).body(
                livroService.findByStatus(status));
    }

    @GetMapping("/autor/{autor}")
    public ResponseEntity<List<Livro>> findByAutor(
            @PathVariable(value = "autor") Autor autor) {
        return ResponseEntity.status(HttpStatus.FOUND).body(
                livroService.findByAutor(autor));
    }

    @PreAuthorize("hasAnyAuthority('Autor', 'Revisor','Diretor')")
    @GetMapping
    public ResponseEntity<List<Livro>> findAll() {
        System.out.println("findAll Controller");
        return ResponseEntity.status(HttpStatus.OK).body(
                livroService.findAll());
    }
    @GetMapping("/page")
    public ResponseEntity<Page<Livro>> findAllPage(
            Pageable pageable
    ) {
        return ResponseEntity.status(HttpStatus.FOUND).body(
                livroService.findAll(pageable));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('Autor')")
    public ResponseEntity<Object> save(
            @RequestParam("livro") String livroJson,
            @RequestParam("arquivos") ArrayList<MultipartFile> files) {
        System.out.println(livroJson);
        System.out.println(files);
        Livro livro = livroUtil.convertJsonToModel(livroJson);
        if (livroService.existsById(livro.getIsbn())){
            return ResponseEntity.status(HttpStatus.CONFLICT).body(
                    "Há um livro com o ISBN " + livro.getIsbn() + " cadastrado.");
        }
        System.out.println(files);
        livro.setArquivos(livroUtil.convertMultiPartFilesToArquivos(files));
        livro.setStatus(Status.AGUARDANDO_REVISAO);
        return ResponseEntity.status(HttpStatus.OK).body(
                livroService.save(livro));
    }

    @GetMapping("/status")
    public ResponseEntity<List<Status>> getStatus(){
        List<Status> statusList = List.of(Status.values());
        System.out.println(statusList);
        return ResponseEntity.status(HttpStatus.OK).body(statusList);
    }

    @DeleteMapping("/{isbn}")
    public ResponseEntity<Object> deleteById(
            @PathVariable(value = "isbn") Long isbn) {
        if (livroService.existsById(isbn)) {
            livroService.deleteById(isbn);
            return ResponseEntity.status(HttpStatus.OK).body(
                    "Livro deletado!");
        }
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                "Livro não encontrado.");
    }
    @PutMapping("/{isbn}")
    public ResponseEntity<Object> update(
            @PathVariable(value = "isbn") Long isbn,
            @RequestParam("livro") String livroJson,
            @RequestParam("arquivos") ArrayList<MultipartFile> files) {
        LivroUtil util = new LivroUtil();
        Livro livro = util.convertJsonToModel(livroJson);
        if (livroService.existsById(isbn)){
            return ResponseEntity.status(HttpStatus.CONFLICT).body(
                    "Há um livro com o ISBN " + livro.getIsbn() + " cadastrado.");
        }

        livro.setArquivos(livroUtil.convertMultiPartFilesToArquivos(files));
        return ResponseEntity.status(HttpStatus.OK).body(
                livroService.save(livro));
    }
}
