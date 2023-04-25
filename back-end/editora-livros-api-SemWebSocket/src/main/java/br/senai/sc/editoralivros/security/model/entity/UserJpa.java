package br.senai.sc.editoralivros.security.model.entity;

import br.senai.sc.editoralivros.model.entity.Pessoa;
//import br.senai.sc.editoralivros.security.utils.UserJpaDeserializer;
import br.senai.sc.editoralivros.security.utils.UserJpaDeserializer;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonTypeResolver;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Data
@NoArgsConstructor
@AllArgsConstructor
//@JsonDeserialize(using = UserJpaDeserializer.class)
public class UserJpa implements UserDetails {

    private Pessoa pessoa;

    private List<Perfil> authorities;

    private boolean accountNonExpired;

    private boolean accountNonLocked;

    private boolean credentialsNonExpired;

    private boolean enabled;

    private String password;

    private String username;
    public UserJpa(Pessoa pessoa){
        this.pessoa = pessoa;
        this.accountNonExpired = true;
        this.accountNonLocked = true;
        this.credentialsNonExpired = true;
        this.enabled = true;
        this.password = pessoa.getSenha();
        this.username = pessoa.getEmail();
        this.authorities = new ArrayList<>();
        this.authorities.add(Perfil.perfilOf(pessoa.getClass().getSimpleName()));
    }
}
