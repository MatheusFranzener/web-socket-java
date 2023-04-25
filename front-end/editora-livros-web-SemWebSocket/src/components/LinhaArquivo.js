import React from 'react'
import { Table } from 'flowbite-react'

export const LinhaArquivo = (props) => {
    const arquivo = props.arquivo
    const posicao = props.posicao
    return (
        <Table.Row key={posicao} className="bg-white dark:border-gray-700 dark:bg-gray-800">
            <Table.Cell className="whitespace-nowrap font-medium text-gray-900 dark:text-white">
                {arquivo.name}
            </Table.Cell>
            <Table.Cell>
                <a
                    href="#"
                    className="font-medium text-blue-600 hover:underline dark:text-blue-500"
                >
                    Deletar
                </a>
            </Table.Cell>
        </Table.Row>
    )
}