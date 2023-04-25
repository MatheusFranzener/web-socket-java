import React from 'react'

export const Paragrafo = ({texto}) => {
    return (
        <p className="font-normal text-gray-700 dark:text-gray-400">
            {texto}
        </p>
    )
}