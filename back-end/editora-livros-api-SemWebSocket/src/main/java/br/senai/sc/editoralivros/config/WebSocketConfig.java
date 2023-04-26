package br.senai.sc.editoralivros.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        // caminho padrão para poder enviar mensagens
        registry.setApplicationDestinationPrefixes("/editora-livros-api");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        // caminho para poder conectar com o webSocket
        registry.addEndpoint("/editora-livros-api/websocket")
                .setAllowedOrigins("http://localhost:3000") // quem pode se conectar
                .withSockJS()
                .setSessionCookieNeeded(true); // permite a leitura do cookie
    }

}
