package br.senai.sc.editoralivros.security.utils;

import br.senai.sc.editoralivros.model.entity.*;
import br.senai.sc.editoralivros.model.factory.PessoaFactory;
import br.senai.sc.editoralivros.security.model.entity.UserJpa;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.util.BeanUtil;
import org.springframework.beans.BeanUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class UserJpaDeserializer extends JsonDeserializer<UserJpa> {
    @Override
    public UserJpa deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        ObjectMapper mapper = (ObjectMapper) p.getCodec();
        JsonNode node = mapper.readTree(p);

        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        ArrayNode authoritiesNode = (ArrayNode) node.get("authorities");
        for (JsonNode authorityNode : authoritiesNode) {
            String authority = authorityNode.get("authority").asText();
            SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(authority);
            authorities.add(simpleGrantedAuthority);
        }
        Pessoa pessoa = mapper.convertValue(node.get("pessoa"), Pessoa.class);
        System.out.println(pessoa);
        SimpleGrantedAuthority authority = authorities.get(0);
        pessoa = new PessoaFactory().getPessoa(authority, pessoa);
        System.out.println(pessoa);
        return new UserJpa(pessoa);
    }
}
