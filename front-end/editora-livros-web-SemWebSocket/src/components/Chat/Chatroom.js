import React from 'react'
import {BarraLateralChat, Chat} from "./subcomponents";


export const Chatroom = ({livro, usuario}) => {
    return (
        <div className='home'>
            <div className="container">
                <BarraLateralChat livro={livro} usuario={usuario}/>
                <Chat mensagens={livro.mensagens}/>
            </div>
        </div>
    )
}