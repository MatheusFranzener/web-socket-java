import React, {useEffect, useState} from 'react'
import {Button, Card, TextInput} from "flowbite-react";
import {Paragrafo, Titulo} from "../../components";
import ForwardToInboxIcon from "@mui/icons-material/ForwardToInbox";
import {apiMensagens} from '../../services';
import {useParams} from "react-router-dom";
import Cookies from 'js-cookie';

export const ChatRoom = () => {

    const isbn = useParams().isbn
    const [mensagens, setMensagens] = useState([]);
    const [mensagem, setMensagem] = useState({});

    useEffect(() => {
        async function carregar() {
            await apiMensagens.getMensagensLivro(isbn)
                .then((response) => {
                    console.log(response);
                    setMensagens(response);
                }).catch((error) => {
                    console.log(error);
                })
            setDefaultMensagem();
        }
        carregar();
    }, []);

    const setDefaultMensagem = () => {
        const userCookie = Cookies.get('user');
        const userDecode = decodeURIComponent(userCookie);
        const user = JSON.parse(userDecode);
        const {pessoa} = user;
        const {cpf} = pessoa;
        setMensagem({
            livro: {isbn: isbn},
            remetente: {cpf: cpf},
            mensagem: null
        })
        console.log(mensagem)
    }

    const atualizaMensagem = (event) => {
        event.preventDefault();
        const {value} = event.target;
        setMensagem({...mensagem, "mensagem": value});
    }

    const submit = async (event) => {
        event.preventDefault();
        const response = await apiMensagens.postMensagem(mensagem)
            .then((response) => {
                return response;
            }).catch((error) => {
                console.log(error);
            })
        setMensagens([...mensagens, response]);
    }

    return (
        <>
            <Card>
                {
                    Object.values(mensagens).map((mensagem) => (
                        console.log(mensagem),
                        <Card key={mensagem.id}>
                            <Titulo texto={mensagem.remetente.nome}/>
                            <Paragrafo texto={mensagem.mensagem}/>
                        </Card>
                    ))
                }
                <form onSubmit={submit}>
                    <TextInput
                        id="mensagem"
                        type="text"
                        placeholder="Digite a sua mensagem aqui..."
                        required={true}
                        onChange={atualizaMensagem}
                    />
                    <Button type="submit">
                        <ForwardToInboxIcon className='h-4 w-auto pr-2'/>
                        Enviar mensagem
                    </Button>
                </form>
            </Card>
        </>
    )
}