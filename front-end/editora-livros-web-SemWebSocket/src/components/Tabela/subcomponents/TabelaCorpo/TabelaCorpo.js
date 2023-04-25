import React from 'react';
import {Table} from 'flowbite-react';
import {TabelaLinha} from "../TabelaLinha";

export const TabelaCorpo = ({corpo, acoes, deletar, editar}) => {
    return (
        <>
            <Table.Body>
                {
                    Object.values(corpo).map((linha, indice) => (
                        <TabelaLinha
                            key={indice}
                            linha={linha}
                            indice={indice}
                            acoes={acoes}
                            deletar={deletar}
                            editar={editar}
                        />))
                }
            </Table.Body>
        </>
    );
}