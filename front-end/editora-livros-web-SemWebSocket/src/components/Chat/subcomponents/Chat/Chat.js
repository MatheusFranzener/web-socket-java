import React, {useState} from "react";
import {Mensagens} from "../";
import {TextInput} from "flowbite-react";

export const Chat = ({mensagens}) => {

    const [mensagem, setMensagem] = useState()
    const atualizarMensagem = (event) => {
        setMensagem({...mensagem, [event.target.name]: event.target.value})
    }

    return (
        <div className="chat">
            <div className="chatInfo"/>
            <Mensagens mensagens={mensagens}/>
            <TextInput
                id="mensagem"
                type="text"
                placeholder="Harry Potter e a Pedra Filosofal"
                required={true}
                name='mensagem'
                value={mensagem.mensagem}
                onChange={atualizarMensagem}
            />
        </div>
    );
};
