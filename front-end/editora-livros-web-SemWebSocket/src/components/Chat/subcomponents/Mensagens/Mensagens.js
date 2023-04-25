import React from "react";

export const Mensagens = ({mensagens}) => {
    return (
        <div className="messages">
            {
                mensagens.map((mensagem) => {
                    <Mensagem mensagem={mensagem} key={mensagem.id} />
                })
            }
        </div>
    );
}


