import React from 'react';
import {Table} from 'flowbite-react';
import {TabelaCabecalho, TabelaCorpo} from "./subcomponents";

export const Tabela = ({cabecalho, corpo, acoes, editar, deletar}) => {
    return (<>
            <Table hoverable={true}>
                <TabelaCabecalho cabecalho={cabecalho} acoes={acoes}/>
                <TabelaCorpo corpo={corpo} acoes={acoes} editar={editar} deletar={deletar}/>
            </Table>
        </>);
}