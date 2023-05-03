package br.senai.sc.editoralivros.security.service;

import br.senai.sc.editoralivros.security.model.entity.UserGoogle;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

// Classe responsável por carregar sozinho o usuário do google como oAuth2User
@Service
public class GoogleService extends DefaultOAuth2UserService {

    // Converter o usuário do tipo OAuth2User para a nossa classe de usuário
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest){
        OAuth2User oAuth2User = super.loadUser(userRequest);
        // Cria um objeto UserGoogle através do oAuth2User
        return new UserGoogle(oAuth2User);
    }
}
