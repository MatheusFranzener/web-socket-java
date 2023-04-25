import React from 'react';
import {Table} from 'flowbite-react';

export const TabelaCabecalhoCelula = ({celula}) => {
    return (
        <>
            <Table.HeadCell>
                {celula === null?"":celula}
            </Table.HeadCell>
        </>
    );
}