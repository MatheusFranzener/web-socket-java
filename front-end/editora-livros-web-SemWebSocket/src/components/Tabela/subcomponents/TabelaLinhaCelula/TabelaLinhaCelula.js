import React from 'react';
import {Table} from 'flowbite-react';

export const TabelaLinhaCelula = ({celula}) => {
    return (
        <>
            <Table.Cell>
                {celula === null?"":celula}
            </Table.Cell>
        </>
    );
}