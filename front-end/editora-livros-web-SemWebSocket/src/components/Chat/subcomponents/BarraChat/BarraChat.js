import React from 'react'
import {useNavigate} from "react-router-dom";

export const BarraChat = ({livro, usuario}) => {

    const voltar = () => {
        const navigate = useNavigate();
        navigate("/livro/" + livro.isbn)
    }

    return (
        <div className='navbar'>
            <span className="logo">{livro.titulo}</span>
            <div className="user">
                {/*<img src={currentUser.foto} alt="" />*/}
                <span>{usuario.nome + " " + usuario.sobrenome}</span>
                <button onClick={() => voltar()}>Voltar</button>
            </div>
        </div>
    )
}