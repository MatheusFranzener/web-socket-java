import {Label, TextInput, FileInput, Button, Card, Table, Spinner, Select} from 'flowbite-react'
import React, {useState, useEffect} from 'react'
import {apiLivros} from '../../services'
import {useNavigate, useParams} from 'react-router-dom'
import {LinhaArquivo} from '../../components/LinhaArquivo'
import livroCadastroJson from './livroCadastro.json'
import livroDetalhesJson from './livroDetalhes.json'
import Cookies from 'js-cookie';

export const CadastroLivro = () => {

    const navigate = useNavigate()
    const [isbn] = useState(useParams().isbn)
    const [editando, setEditando] = useState(false)
    const [carregando, setCarregando] = useState(false)
    const [arquivosFile, setArquivosFile] = useState([])
    const [livro, setLivro] = useState(livroDetalhesJson)
    const [listaStatus, setListaStatus] = useState([])

    useEffect(() => {
        if (isbn) {
            async function carregarLivro() {
                setEditando(true)
                await apiLivros.getLivro(isbn).then(async (response) => {
                    setLivro(response);
                    convertFiles(response)
                    await apiLivros.getStatus().then((responseStatus) => {
                        setListaStatus(responseStatus)
                    }).catch(errorStatus => {
                        console.log(errorStatus)
                    })
                }).catch(error => {
                    console.log(error);
                })
            }

            setCarregando(true);
            carregarLivro().finally(() =>
                setCarregando(false)
            );
        } else {
            setLivro(livroCadastroJson)
            const user = JSON.parse(Cookies.get('user'));
            setLivro({...livro, "autor": user})
        }
    }, [isbn])


    const convertFiles = (livro) => {
        const arquivos = livro.arquivos
        console.log(arquivos)
        arquivos.forEach((arquivo) => {
            const blob = new Blob([arquivo.dados], {type: arquivo.tipo}); // dados é o conteúdo do seu objeto arquivo
            const file = new File([blob], arquivo.nome, {type: arquivo.tipo});
            setArquivosFile([...arquivos, file])
        })
    }

    const atualizarLivro = (event) => {
        setLivro({...livro, [event.target.name]: event.target.value})
    }

    const atualizarArquivos = (event) => {
        const copia = [...arquivosFile]
        copia.push(...event.target.files)
        setArquivosFile(copia)
        // Array.from(event.target.files).forEach((arquivo) => {
        //     arquivosFile.push(arquivo);
        // });
        // setArquivos(event.target.files)
    }

    const submit = event => {
        event.preventDefault()
        salvarLivro(livro);
    };

// Ação executada ao enviar o formulário
    const salvarLivro = async () => {
        //    const salvarLivro = async (livro, arquivosFile) => {
        console.log(livro)
        console.log(listaStatus)
        try {
            const formData = new FormData();
            formData.append('livro', JSON.stringify(livro));
            Array.from(arquivosFile).forEach((arquivo) => {
                formData.append("arquivosFile", arquivo);
            });
            let resposta
            if (editando) {
                resposta = apiLivros.putLivro(livro.isbn, formData).then(response => {
                    console.log("Livro editado com sucesso! >>> " + response.data)
                }).catch(error => {
                    console.log(error)
                })
            } else {
                resposta = apiLivros.postLivro(formData).then(response => {
                    console.log("Livro cadastrado com sucesso! >>> " + response)
                    return response
                }).catch(error => {
                    console.log(error)
                })
            }
            if (resposta != null) {
                navigate('/livros')
            }
        } catch (error) {
            console.log(error)
        }
    }

    const mostrar = {display: editando ? "block" : "none"}
    const temArquivos = {display: arquivosFile.length > 0 ? "block" : "none"}

    function retornar() {
        navigate('/livros')
    }

    if (carregando) {
        return (
            <div className="flex justify-center items-center h-80">
                <Spinner/>
            </div>
        )
    } else {
        return (
            <>
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
                                    name="status"
                                    value={editando ? livro.status : ""}
                                    onChange={atualizarLivro}
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
                                        {!(Array.of(arquivosFile).length === 0) ? (
                                            Object.values(arquivosFile).map((arquivo, i) => (
                                                <LinhaArquivo key={i} arquivo={arquivo} posicao={i}/>
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
}