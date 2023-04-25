import React from 'react'
import {Card} from 'flowbite-react'
import {Paragrafo, Titulo} from "../../components";
import locale from "./locale.json";

export const Home = () => {
    return (
        <>
            <Card>
                <Titulo texto={locale.titulo}/>
                {Object.values(locale.paragrafos).map((frase) => <Paragrafo texto={frase}/>)}
            </Card>
        </>
    )
}