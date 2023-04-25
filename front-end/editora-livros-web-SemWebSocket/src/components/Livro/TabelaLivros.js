import React, {useState, useEffect} from 'react'
import LinhaLivro from './LinhaLivro';
import {Button, Table, Spinner} from 'flowbite-react'
import { LivrosService } from '../../services/LivrosService';
import MeuToast from '../MeuToast';
import {Navigate, useNavigate} from 'react-router-dom';


const TabelaLivros = () => {

    const service = new LivrosService();
    const [livros, setlivros] = useState(null)
    const [carregando, setcarregando] = useState(true)
    const [show, setshow] = useState(false)
    const navigate = useNavigate()

    useEffect(() => {
        async function buscarLivros() {
            try {
                setcarregando(true)
                const response = await service.getLivros()
                setlivros(response.data);
            } catch (error) {
                console.log('Erro ao buscar livros', error)
                if(error?.response?.status === 401) {

                }
            } finally {
                setcarregando(false)
            }
        }
        buscarLivros().then(r => r)
    }, [])


    const deletarLivro = async (e, isbn) => {
        e.preventDefault()
        try {
            const response = await LivrosService.deleteLivro(isbn)
            if (response?.data?.status === 200) {
                setshow(true)
                setTimeout(() => setshow(false), 3000)
                setlivros((livros) => livros.filter((livro) => livro.isbn !== isbn))
            }
        } catch (error) {
            console.log("Erro ao deletar o livro",error)
        }
    }

    const editarLivro = async (e, isbn) => {
        e.preventDefault()
        navigate(`/livro/editar/${isbn}`)
    }

    if (carregando) {
        return (
            <div className="flex justify-center items-center h-80">
                <Spinner/>
            </div>
        )
    }

    const dados = {show: show, mensagem: `O livro foi deletado com sucesso!`}

    return (
        <>
            <div>
                <MeuToast toastDados={dados}/>
            </div>
            <Button
                className='w-40 mb-4'
                href='livro/cadastro'>
                Cadastrar Livro
            </Button>
            <Table hoverable={true}>
                <Table.Head>
                    <Table.HeadCell>
                        ISBN
                    </Table.HeadCell>
                    <Table.HeadCell>
                        Título
                    </Table.HeadCell>
                    <Table.HeadCell>
                        Autor
                    </Table.HeadCell>
                    <Table.HeadCell>
                        Revisor
                    </Table.HeadCell>
                    <Table.HeadCell>
                        Status
                    </Table.HeadCell>
                    <Table.HeadCell>
                        Qtd. Pág.
                    </Table.HeadCell>
                    <Table.HeadCell>
                        Pág. Rev.
                    </Table.HeadCell>
                    <Table.HeadCell>
                        Editora
                    </Table.HeadCell>
                    <Table.HeadCell>
                        Ações
                    </Table.HeadCell>
                </Table.Head>
                <Table.Body className="divide-y">
                    {console.log(livros.length)}
                    {Array.of(livros).length === 0 ?
                        <Table.Cell colSpan={9}>
                            'Nenhum livro cadastrado'
                        </Table.Cell> :
                        livros.map((livro) => (
                            <LinhaLivro key={livro.isbn} livro={livro} deletarLivro={deletarLivro}
                                        editarLivro={editarLivro}/>
                        ))}
                </Table.Body>
            </Table>
        </>
    )
}
export default TabelaLivros