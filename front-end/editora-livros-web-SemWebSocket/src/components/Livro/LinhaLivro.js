import { PencilSquareIcon, TrashIcon } from '@heroicons/react/24/outline'
import React from 'react'
import { Table } from 'flowbite-react'

const LinhaLivro = (props) => {
    const livro = props.livro
    return (
        <Table.Row key={livro.isbn} className="bg-white dark:border-gray-700 dark:bg-gray-800">
            <Table.Cell>
                {livro.isbn}
            </Table.Cell>
            <Table.Cell>
                {livro.titulo}
            </Table.Cell>
            <Table.Cell>
                {livro.autor.nome}
            </Table.Cell>
            <Table.Cell>
                {livro.revisor === null ? "" : livro.revisor.nome}
            </Table.Cell>
            <Table.Cell>
                {livro.status}
            </Table.Cell>
            <Table.Cell>
                {livro.qtdPag}
            </Table.Cell>
            <Table.Cell>
                {livro.pagRevisadas}
            </Table.Cell>
            <Table.Cell>
                {livro.editora === null ? "" : livro.editora.nome}
            </Table.Cell>
            <Table.Cell className="flex py-4 justify-center">
                <a className="text-blue-600 hover:cursor-pointer" onClick={(e)=>{props.editarLivro(e,livro.isbn)}}>
                    <PencilSquareIcon className='px-2 h-4' />
                </a>
                <a className="text-red-600 hover:cursor-pointer" onClick={(e)=>{props.deletarLivro(e,livro.isbn)}}>
                    <TrashIcon className='px-2 h-4' />
                </a>
            </Table.Cell>
        </Table.Row>
    )
}

export default LinhaLivro