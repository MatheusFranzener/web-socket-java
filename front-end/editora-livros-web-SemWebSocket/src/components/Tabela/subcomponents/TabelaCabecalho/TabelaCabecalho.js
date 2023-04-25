import React from 'react';
import {Table} from 'flowbite-react';
import {TabelaCabecalhoCelula} from "../";

export const TabelaCabecalho = ({cabecalho, acoes}) => {
    return (<>
        <Table.Head>
            {Object.values(cabecalho).map((celula, indice) => (!acoes && celula === "Ações" ? null :
                <TabelaCabecalhoCelula key={indice} celula={celula}/>))}
        </Table.Head>
    </>);
}