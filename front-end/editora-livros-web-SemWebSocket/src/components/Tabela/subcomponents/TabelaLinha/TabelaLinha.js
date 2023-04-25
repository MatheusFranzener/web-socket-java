import React from 'react';
import {Table} from 'flowbite-react';
import {TabelaLinhaCelula, TabelaLinhaCelulaAcoes} from "../";

export const TabelaLinha = ({linha, indice, acoes, deletar, editar}) => {
    return (<>
        <Table.Row key={indice} className="bg-white dark:border-gray-700 dark:bg-gray-800">
            {
                Object.values(linha).map((celula, indice) => (
                    <TabelaLinhaCelula key={indice} celula={celula}/>
                ))
            }
            {acoes && <TabelaLinhaCelulaAcoes objeto={linha} deletar={deletar} editar={editar}/>}
        </Table.Row>
    </>);
}