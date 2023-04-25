package br.senai.sc.editoralivros.controller;

import br.senai.sc.editoralivros.model.dto.MensagemChatDTO;
import br.senai.sc.editoralivros.model.entity.Livro;
import br.senai.sc.editoralivros.model.entity.MensagemChat;
import br.senai.sc.editoralivros.model.entity.Pessoa;
import br.senai.sc.editoralivros.service.LivroService;
import br.senai.sc.editoralivros.service.MensagemChatService;
import br.senai.sc.editoralivros.service.PessoaService;
import lombok.AllArgsConstructor;
import org.springframework.beans.BeanUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("/editora-livros-api/mensagem")
public class MensagemChatController {
    private final MensagemChatService mensagemChatService;
    private final LivroService livroService;
    private final PessoaService pessoaService;

    @GetMapping("/{isbn}")
    public ResponseEntity<?> mensagensLivro(@PathVariable(value = "isbn") Long isbn) {
        return ResponseEntity.ok(mensagemChatService.findAllByLivro(livroService.findById(isbn).get()));
    }

    @PostMapping()
    public ResponseEntity<?> salvarMensagem(@RequestBody MensagemChatDTO mensagemChatDTO) {
        MensagemChat mensagemChat = new MensagemChat();
        mensagemChat.setLivro(livroService.findById(mensagemChatDTO.getLivro().getIsbn()).get());
        mensagemChat.setRemetente(pessoaService.findById(mensagemChatDTO.getRemetente().getCpf()).get());
        mensagemChat.setMensagem(mensagemChatDTO.getMensagem());
        return ResponseEntity.ok(mensagemChatService.save(mensagemChat));
    }
}
