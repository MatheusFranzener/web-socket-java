import React, { useEffect, useRef } from "react";

export const Mensagem = ({mensagem, usuario}) => {

    const ref = useRef();

    useEffect(() => {
        ref.current?.scrollIntoView({ behavior: "smooth" });
    }, [mensagem]);

    return (
        <div
            ref={ref}
            className={`message ${mensagem.remetente.cpf === usuario.cpf && "owner"}`}
        >
            <div className="messageInfo">
                {/*<img*/}
                {/*    src={*/}
                {/*        mensagem.remetente.cpf === usuario.cpf*/}
                {/*            ? usuario.foto*/}
                {/*            : mensagem.destinatario.foto*/}
                {/*    }*/}
                {/*    alt=""*/}
                {/*/>*/}
                {/*<span>just now</span>*/}
            </div>
            <div className="messageContent">
                <p>{mensagem.mensagem}</p>
                {/*{mensagem.img && <img src={mensagem.img} alt="" />}*/}
            </div>
        </div>
    );
};
