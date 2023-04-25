package br.senai.sc.editoralivros.model.factory;

import br.senai.sc.editoralivros.model.entity.Autor;
import br.senai.sc.editoralivros.model.entity.Diretor;
import br.senai.sc.editoralivros.model.entity.Pessoa;
import br.senai.sc.editoralivros.model.entity.Revisor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class PessoaFactory {
    public Pessoa getPessoa(SimpleGrantedAuthority authority, Pessoa pessoa) {
        switch (authority.getAuthority()) {
            case "Diretor" -> {
                Diretor diretor = new Diretor();
                diretor.setCpf(pessoa.getCpf());
                diretor.setNome(pessoa.getNome());
                diretor.setSobrenome(pessoa.getSobrenome());
                diretor.setEmail(pessoa.getEmail());
                diretor.setSenha(pessoa.getSenha());
                diretor.setGenero(pessoa.getGenero());
                return diretor;
            }
            case "Revisor" -> {
                Revisor revisor = new Revisor();
                revisor.setCpf(pessoa.getCpf());
                revisor.setNome(pessoa.getNome());
                revisor.setSobrenome(pessoa.getSobrenome());
                revisor.setEmail(pessoa.getEmail());
                revisor.setSenha(pessoa.getSenha());
                revisor.setGenero(pessoa.getGenero());
                return revisor;
            }
            case "Autor" -> {
                Autor autor = new Autor();
                autor.setCpf(pessoa.getCpf());
                autor.setNome(pessoa.getNome());
                autor.setSobrenome(pessoa.getSobrenome());
                autor.setEmail(pessoa.getEmail());
                autor.setSenha(pessoa.getSenha());
                autor.setGenero(pessoa.getGenero());
                return autor;
            }
        }
        throw new IllegalArgumentException("Pessoa não encontrada");
    }
}
