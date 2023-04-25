import React, {useEffect, useState} from 'react';
import {Tabela} from '../../components';
import locale from "./locale.json";
import {apiLivros} from "../../services";
import {useNavigate} from 'react-router-dom';

export const Livros = () => {

    const [livros, setLivros] = useState([]);
    const navigate = useNavigate()


    useEffect(() => {
        async function carregar() {
            await apiLivros.getLivros().then(response => {
                console.log(response);
                const linhas = converter(response)
                console.log(linhas);
                setLivros(linhas);
            });
        }
        carregar().then(r => console.log(r));
    }, []);

    const converter = (livros) => {
        return livros.map(livro => {
            return ({
                isbn: livro.isbn,
                titulo: livro.titulo,
                autor: livro.autor.nome + " " + livro.autor.sobrenome,
                revisor: (livro.revisor === null ? "" : livro.revisor.nome + " " + livro.revisor.sobrenome),
                status: livro.status,
                qtdPag: livro.qtdPag,
                pagRevisadas: livro.pagRevisadas,
                editora: (livro.editora === null ? "" : livro.editora.nome)
            })
        })
    }

    const deletarLivro = (livro) => {
        apiLivros.deleteLivro(livro.isbn).then(response => {
            console.log(response.data);
        }).catch(error => {
            console.log(error);
        })
    };

    const editarLivro = (event, livro) => {
        event.preventDefault()
        navigate(`/livro/editar/${livro.isbn}`)
    }

    const acoes = true

    return (<>
            <Tabela cabecalho={locale.heads} corpo={livros} acoes={acoes} deletar={deletarLivro} editar={editarLivro}/>
        </>);
}