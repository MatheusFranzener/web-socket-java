import React from 'react';
import {Table} from 'flowbite-react';
import {PencilSquareIcon, TrashIcon} from "@heroicons/react/24/outline";

export const TabelaLinhaCelulaAcoes = ({objeto, editar, deletar}) => {
    return (
        <>
            <Table.Cell className="flex py-4 justify-center">
                <a className="text-blue-600 hover:cursor-pointer" onClick={(e) => {
                    editar(e, objeto)
                }}>
                    <PencilSquareIcon className='px-2 h-4'/>
                </a>
                <a className="text-red-600 hover:cursor-pointer" onClick={(e) => {
                    deletar(e, objeto)
                }}>
                    <TrashIcon className='px-2 h-4'/>
                </a>
            </Table.Cell>
        </>
    );
}