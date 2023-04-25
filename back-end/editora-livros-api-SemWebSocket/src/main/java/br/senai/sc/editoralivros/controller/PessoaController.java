package br.senai.sc.editoralivros.controller;

import br.senai.sc.editoralivros.model.dto.PessoaDTO;
import br.senai.sc.editoralivros.model.enums.Genero;
import br.senai.sc.editoralivros.model.entity.Pessoa;
import br.senai.sc.editoralivros.service.PessoaService;
import lombok.AllArgsConstructor;
import org.springframework.beans.BeanUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import javax.validation.Valid;
import java.util.List;
import java.util.Optional;

@AllArgsConstructor
@RestController
@RequestMapping("/editora-livros-api/pessoa")
@CrossOrigin
public class PessoaController {
    private PessoaService pessoaService;

    @GetMapping("/email/{email}")
    public ResponseEntity<Object> findByEmail(
            @PathVariable(value = "email") String email) {
        Optional<Pessoa> pessoaOptional =
                pessoaService.findByEmail(email);
        if (pessoaOptional.isEmpty()){
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("Não foi encontrada nenhuma pessoa " +
                            "com este E-mail");
        }
        return ResponseEntity.status(HttpStatus.OK)
                .body(pessoaOptional.get());
    }
    @GetMapping("/{cpf}")
    public ResponseEntity<Object> findById(
            @PathVariable(value = "cpf") Long cpf) {
        Optional<Pessoa> pessoaOptional =
                pessoaService.findById(cpf);
        return pessoaOptional.<ResponseEntity<Object>>map(pessoa -> ResponseEntity.status(HttpStatus.OK)
                .body(pessoa)).orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body("Não foi encontrada nenhuma pessoa " +
                        "com este CPF"));
    }

    @GetMapping("/generos")
    public ResponseEntity<List<Genero>> getGeneros(){
        List<Genero> generoList = List.of(Genero.values());
        System.out.println(generoList);
        return ResponseEntity.status(HttpStatus.OK).body(generoList);
    }

    @GetMapping
    public ResponseEntity<List<Pessoa>> findAll() {
        return ResponseEntity.status(HttpStatus.OK)
            .body(pessoaService.findAll());
    }
    @PostMapping
    public ResponseEntity<Object> save(
            @RequestBody @Valid PessoaDTO pessoaDTO) {
        if(pessoaService.existsById(pessoaDTO.getCpf())) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("Este CPF já está cadastrado.");
        }
        if (pessoaService.existsByEmail(pessoaDTO.getEmail())){
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("Este E-mail já está cadastrado.");
        }
        Pessoa pessoa = new Pessoa();
        BeanUtils.copyProperties(pessoaDTO, pessoa);
//        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
//        pessoa.setSenha(encoder.encode(pessoa.getSenha()));
        return ResponseEntity.status(HttpStatus.OK)
                .body(pessoaService.save(pessoa));
    }
//    @PostMapping
//    public String save(PessoaDTO pessoaDTO) {
//        Pessoa pessoa = new Pessoa();
//        BeanUtils.copyProperties(pessoaDTO, pessoa);
//        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
//        pessoa.setSenha(encoder.encode(pessoa.getSenha()));
//        pessoaService.save(pessoa);
//        return "home";
//    }

    @DeleteMapping("/{cpf}")
    public ResponseEntity<Object> deleteById(@PathVariable(value = "cpf") Long cpf) {
        if (!pessoaService.existsById(cpf)){
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("Não foi encontrada nenhuma pessoa " +
                            "com este CPF");
        }
        pessoaService.deleteById(cpf);
        return ResponseEntity.status(HttpStatus.OK)
            .body("Pessoa deletada.");
    }
}
