package br.senai.sc.editoralivros.service;

import br.senai.sc.editoralivros.model.entity.Livro;
import br.senai.sc.editoralivros.model.entity.MensagemChat;
import br.senai.sc.editoralivros.repository.MensagemChatRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class MensagemChatService {
    private final MensagemChatRepository mensagemChatRepository;

    public MensagemChatService(MensagemChatRepository mensagemChatRepository) {
        this.mensagemChatRepository = mensagemChatRepository;
    }

    public MensagemChat save(MensagemChat mensagemChat) {
        return mensagemChatRepository.save(mensagemChat);
    }

    public List<MensagemChat> findAllByLivro(Livro livro) {
        return mensagemChatRepository.findAllByLivro(livro);
    }

}
