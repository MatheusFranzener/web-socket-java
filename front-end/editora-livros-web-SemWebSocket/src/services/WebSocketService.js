import { useEffect, useState, createContext } from "react";
import SockJS from "sockjs-client";
import * as Stomp from "stompjs";

export const WebSocketContext = createContext(null);

export const WebSocketService = ({children}) => {
    const [stompClient, setStompClient] = useState(null);

    useEffect(() => {
        const conectar = () => {
            const socket = new SockJS("http://localhost:8085/editora-livros-api/websocket");
            const stomp = Stomp.over(socket);
            stomp.connect({}, () => {
                setStompClient(stomp);
            }, (erro) => {
                console.log("Erro ao conectar: ", erro)
                setTimeout(() => {
                    console.log("Tentando reconectar...")
                    conectar();
                }, 5000)
            })
        }

        conectar();
    }, [])

    const desconectar = () => {
        if (stompClient) {
            stompClient.disconnect();
        }
    }

    const enviar = (destino, mensagem) => {
        if (stompClient) {
            console.log("foi front ", destino)
            stompClient.send(destino, {}, JSON.stringify(mensagem))
        } else {
            console.log("Conexão não estabelecida!")
        }
    }

    return (
        <WebSocketContext.Provider value={{stompClient, desconectar, enviar}}> 
            {children}
        </WebSocketContext.Provider>
    )

}