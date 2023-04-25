import { Label, TextInput, FileInput, Button, Card, Table, Spinner, Select } from 'flowbite-react'
import React, { useState, useEffect } from 'react'
import {apiLivros} from '../../services'
import MeuToast from '../MeuToast'
import { useNavigate, useParams } from 'react-router-dom'
import {LinhaArquivo} from '../LinhaArquivo'


export const Livro = () => {

    const livroDetalhes = {
        isbn: "",
        titulo: "",
        autor: { cpf: 123 },
        qtdPag: "",
        //arquivos: [],
        revisor: "",
        status: "",
        pagRevisadas: '',
        editora: "",
    }

    const livroCadastro = {
        isbn: "",
        titulo: "",
        autor: { cpf: 123 },
        qtdPag: ""
    }

    const navigate = useNavigate()
    const [editando, seteditando] = useState(false)
    const [show, setshow] = useState(false)
    const [carregando, setcarregando] = useState(false)
    const [arquivos, setarquivos] = useState([])
    const [isbn] = useState(useParams().isbn)
    const [livro, setlivro] = useState(editando ? livroDetalhes : livroCadastro)
    const [listaStatus,setListaStatus] = useState([])

    useEffect(() => {
        async function start() {
            setcarregando(true)
            if (isbn) {
                seteditando(true)
                try {
                    const response = apiLivros.getLivro(isbn)
                    setlivro(response.data);
                    try {
                        const responseStatus = apiLivros.getStatus()
                        const dataStatus = responseStatus.data
                        setListaStatus(dataStatus)
                    } catch (error) {
                        console.log(error)
                    }
                } catch (error) {
                    console.log(error);
                }
                setcarregando(false)
            } else {
                setlivro(livroCadastro)
                setcarregando(false)
            }
        }
        start()
    }, [isbn, setcarregando, seteditando, setlivro])

    const dados = { show: show, mensagem: `O livro "${livro.titulo}" foi cadastrado com sucesso!` }

    const atualizarLivro = (event) => {
        setlivro({ ...livro, [event.target.name]: event.target.value })
    }

    const atualizarArquivos = (event) => {
        const copia = [...arquivos]
        copia.push(...event.target.files)
        setarquivos(copia)
        // Array.from(event.target.files).forEach((arquivo) => {
        //     arquivos.push(arquivo);
        // });
        // setarquivos(event.target.files)
    }

    const submit = event => {
        event.preventDefault()
        salvarLivro(livro);
    };

    // Ação executada ao enviar o formulário
    const salvarLivro = async () => {
        //    const salvarLivro = async (livro, arquivos) => {
        console.log(livro)
        console.log(listaStatus)
        try {
            const data = new FormData();
            data.append('livro', JSON.stringify(livro));
            Array.from(arquivos).forEach((arquivo) => {
                data.append("arquivos", arquivo);
            });
            let response
            if (editando) {
                response = apiLivros.putLivro(livro.isbn, data)
                //    response = await LivrosService.putLivro(livro.isbn, livro)
            } else {
                response = apiLivros.postLivro(data)
                //    response = await LivrosService.postLivro(livro)
            }
            if (response.data != null) {
                setshow(true)
                setTimeout(() => setshow(false), 3000)
                navigate('/livros')
            }
            return (response.data)
        } catch (error) {
            console.log(error)
        }
    }

    const mostrar = { display: editando ? "block" : "none" }
    const temArquivos = { display: arquivos.length > 0 ? "block" : "none" }
    function retornar() {
        navigate('/livros')
    }

    if (carregando) {
        return (
            <div className="flex justify-center items-center h-80">
                <Spinner />
            </div>
        )
    }
    return (
        <>
            <div>
                <MeuToast toastDados={dados} />
            </div>
            <Card>
                <form id='formLivro' onSubmit={submit}>
                    <div className='my-2'>
                        <Label
                            htmlFor="titulo"
                            value="Título"
                        />
                        <TextInput
                            id="titulo"
                            type="text"
                            placeholder="Harry Potter e a Pedra Filosofal"
                            required={true}
                            name='titulo'
                            value={livro.titulo}
                            onChange={atualizarLivro}
                        />
                    </div>
                    <div className="my-2 grid gap-2 grid-cols-2">
                        <div>
                            <Label
                                htmlFor="isbn"
                                value="ISBN"
                            />
                            <TextInput
                                id="isbn"
                                type="number"
                                placeholder="1234"
                                required={true}
                                name='isbn'
                                value={livro.isbn}
                                onChange={atualizarLivro}
                            />
                        </div>
                        <div style={mostrar}>
                            <Label
                                htmlFor="autor_nome"
                                value="Autor"
                            />
                            <TextInput
                                id="autor_nome"
                                type="text"
                                placeholder="J. K. Rowling"
                                required={true}
                                name='autor'
                                value={livro.autor.nome}
                                onChange={atualizarLivro}
                            />
                        </div>
                        <div>
                            <Label
                                htmlFor="qtdPag"
                                value="Quantidade de Páginas"
                            />
                            <TextInput
                                id="qtdPag"
                                type="number"
                                placeholder="1234"
                                required={true}
                                name='qtdPag'
                                value={livro.qtdPag}
                                onChange={atualizarLivro}
                            />
                        </div>
                        <div style={mostrar}>
                            <Label
                                htmlFor="revisor_nome"
                                value="Revisor"
                            />
                            <TextInput
                                id="revisor_nome"
                                type="text"
                                placeholder="C. S. Lewis"
                                name='revisor'
                                value={editando ? (livro.revisor !== null) ? livro.revisor.nome : "" : ""}
                                onChange={atualizarLivro}
                            />
                        </div>
                        <div style={mostrar}>
                            <Label
                                htmlFor="pag_rev"
                                value="Páginas Revisadas"
                            />
                            <TextInput
                                id="pag_rev"
                                type="number"
                                placeholder="1234"
                                required={true}
                                name='pagRevisadas'
                                value={livro.pagRevisadas}
                                onChange={atualizarLivro}
                            />
                        </div>
                        <div style={mostrar}>
                            <Label
                                htmlFor="status"
                                value="Selecione o status"
                            />
                            <Select
                                id="status"
                                required={true}
                                name = "status"
                                value={editando ? livro.status : ""}
                                onChange = {atualizarLivro}
                            >
                                {listaStatus.map((status, index) => (
                                <option key={index}>
                                    {status}
                                </option>
                                ))}
                            </Select>
                        </div>
                    </div>
                    <div className="my-2">
                        <div style={temArquivos}>
                            <Label
                                htmlFor="tb_arquivos"
                                value="Arquivos"
                            />
                            <Table id='tb_arquivos'>
                                <Table.Head>
                                    <Table.HeadCell>
                                        Nome do arquivo
                                    </Table.HeadCell>
                                    <Table.HeadCell>
                                    </Table.HeadCell>
                                </Table.Head>
                                <Table.Body className="divide-y">
                                    {!(Array.of(arquivos).length === 0) ? (
                                        Object.values(arquivos).map((arquivo, i) => (
                                            <LinhaArquivo key={i} arquivo={arquivo} posicao={i} />
                                        ))
                                    ) : (
                                        <Table.Cell colSpan={9}>
                                            'Nenhum arquivo cadastrado'
                                        </Table.Cell>
                                    )}
                                </Table.Body>
                            </Table>
                        </div>
                        <div className="my-2">
                            <Label
                                htmlFor="arquivos"
                                value="Upload de Arquivo"
                            />
                            <FileInput
                                id="arquivos"
                                accept='application/pdf'
                                name='arquivos'
                                onChange={atualizarArquivos}
                                multiple={true}
                            />
                        </div>
                    </div>
                    <div className="mt-8 grid gap-10 grid-cols-2">
                        <Button onClick={submit}>
                            {editando ? "Salvar" : "Cadastrar"}
                        </Button>
                        <Button color="light" onClick={retornar}>
                            Voltar
                        </Button>
                    </div>
                </form>
            </Card>
        </>
    )
}