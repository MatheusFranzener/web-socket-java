import React from "react";
import {BarraChat, PessoasChat} from "../"

 export const BarraLateralChat = ({livro, usuario}) => {
    return (
        <div className="sidebar">
            <BarraChat livro={livro} usuario={usuario}/>
            <PessoasChat livro={livro} usuario={usuario}/>
        </div>
    );
};